package secsuite

import (
	"fmt"
	"os"
	"strings"
)

// PipelineResult is the outcome of a full static scan.
type PipelineResult struct {
	Findings []Finding
	AnyRan   bool
	Skipped  []ToolName
}

// adapters maps each static scanner to the function that turns its SARIF into
// findings. All three share one signature, so they can live in a map - a
// function type is an ordinary value in Go.
var adapters = map[ToolName]func(sarifPath, targetDir string) ([]Finding, error){
	ToolSemgrep:  AdaptSemgrep,
	ToolTrivy:    AdaptTrivy,
	ToolGitleaks: AdaptGitleaks,
}

// RunStaticPipeline is the full static lane:
// detect -> resolve -> run -> adapt -> ignore-filter -> dedupe.
// Shared by `scan` and `baseline` so the two can never drift apart.
func RunStaticPipeline(targetDir string, config Config) (PipelineResult, error) {
	stack := DetectStack(targetDir)
	if len(stack.Languages) == 0 {
		fmt.Fprintln(os.Stderr, "[secsuite] no known language manifests found; running stack-agnostic scanners only.")
	} else {
		// stderr, not stdout: stdout is reserved for the report (or `--json -`).
		fmt.Fprintf(os.Stderr, "[secsuite] detected: %s\n", strings.Join(stack.Languages, ", "))
	}

	tmpDir, err := os.MkdirTemp("", "secsuite-")
	if err != nil {
		return PipelineResult{}, fmt.Errorf("creating temp dir: %w", err)
	}
	// defer runs when this function returns, however it returns. The adapters
	// below read the SARIF files out of tmpDir first, so the cleanup lands
	// after the last read rather than before it.
	defer os.RemoveAll(tmpDir)

	scanners := ResolveScanners(stack)
	runResults := RunScanners(scanners, targetDir, tmpDir, stack)

	anyRan := false
	var skipped []ToolName
	for _, r := range runResults {
		if r.Ran {
			anyRan = true
		} else {
			skipped = append(skipped, r.Tool)
		}
	}
	if !anyRan {
		return PipelineResult{AnyRan: false, Skipped: skipped}, nil
	}

	var findings []Finding
	for _, result := range runResults {
		if !result.Ran || result.SarifPath == "" {
			continue
		}
		adapt, ok := adapters[result.Tool]
		if !ok {
			continue
		}
		adapted, err := adapt(result.SarifPath, targetDir)
		if err != nil {
			return PipelineResult{}, fmt.Errorf("reading %s results: %w", result.Tool, err)
		}
		findings = append(findings, adapted...)
	}

	kept := findings[:0] // reuse the backing array; nothing else refers to it
	for _, f := range findings {
		if !IsIgnored(f.Location.File, config.IgnorePaths) {
			kept = append(kept, f)
		}
	}

	return PipelineResult{
		Findings: DedupeFindings(kept),
		AnyRan:   true,
		Skipped:  skipped,
	}, nil
}
