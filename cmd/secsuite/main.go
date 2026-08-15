// Command secsuite is a stack-aware security scanning CLI: it detects a
// repository's tech stack, runs the appropriate open-source scanners, and
// merges their results into a single report.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kousthubha-sky/secsuite-cli/internal/secsuite"
)

// version is overwritten at release time with -ldflags="-X main.version=...".
var version = "dev"

// Exit codes are part of the CLI contract: 0 clean, 1 findings, 2 error.
// An agent reading "unknown flag" as "findings found" would be a real bug.
const (
	exitClean    = 0
	exitFindings = 1
	exitError    = 2
)

func main() {
	// os.Exit skips deferred functions, so all the real work happens in run()
	// and only its return value reaches here.
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		// AXI content-first: bare `secsuite` shows live state, not help text.
		secsuite.RunStatus(version)
		return exitClean
	}

	switch args[0] {
	case "scan":
		return runScan(args[1:])
	case "baseline":
		return runBaseline(args[1:])
	case "dast":
		return runDast(args[1:])
	case "doctor":
		secsuite.RunDoctor()
		return exitClean
	case "help", "-h", "--help":
		usage(os.Stdout)
		return exitClean
	case "version", "-v", "--version":
		fmt.Println(version)
		return exitClean
	default:
		fmt.Fprintf(os.Stderr, "[secsuite] unknown command %q\n\n", args[0])
		usage(os.Stderr)
		return exitError
	}
}

func usage(w *os.File) {
	fmt.Fprintf(w, `secsuite %s - detect your stack, run the right security scanners, get one clean report.

Usage:
  secsuite                 show detected stack and scanner availability
  secsuite scan [path]     scan a directory and report findings
  secsuite baseline [path] accept all current findings; gate only on new ones
  secsuite dast <url>      dynamic scan of a running app with OWASP ZAP
  secsuite doctor          check that the scanners and Docker are installed

Run a command with --help for its flags.
`, version)
}

// newFlagSet builds a subcommand's flag set. ContinueOnError makes Parse return
// an error instead of calling os.Exit, so a bad flag can exit 2 like every
// other usage error rather than flag's default 2-with-no-context.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: secsuite %s [flags]\n\nFlags:\n", name)
		fs.PrintDefaults()
	}
	return fs
}

// parsePositional pulls the optional leading path/URL argument out before
// parsing flags.
//
// Go's flag package stops at the first non-flag argument, so `scan . --json
// out.json` would parse zero flags and silently ignore --json. Commander did
// not care about order, and the README documents that form, so the positional
// is lifted off the front first.
func parsePositional(fs *flag.FlagSet, args []string, fallback string) (string, error) {
	positional := fallback
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		positional, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if fs.NArg() > 0 {
		positional = fs.Arg(0)
	}
	return positional, nil
}

// resolveThreshold picks the severity gate: the flag when given, else the
// config's.
func resolveThreshold(flagValue string, configThreshold secsuite.Severity) (secsuite.Severity, error) {
	if flagValue == "" {
		return configThreshold, nil
	}
	return secsuite.ParseSeverity(flagValue)
}

func requireDir(kind, target string) error {
	info, err := os.Stat(target)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("%s target is not a directory: %s", kind, target)
	}
	return nil
}

// writeSARIF renders findings as SARIF 2.1.0 for GitHub Code Scanning.
func writeSARIF(path string, findings []secsuite.Finding) error {
	payload, err := json.MarshalIndent(secsuite.FindingsToSARIF(findings, version), "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		return err
	}
	fmt.Printf("SARIF written to %s\n", path)
	return nil
}

func runScan(args []string) int {
	fs := newFlagSet("scan")
	severity := fs.String("severity", "", "minimum severity to report (default: medium, or config's severity_threshold)")
	jsonPath := fs.String("json", "", "write full findings JSON to <file> (use - for stdout)")
	sarifPath := fs.String("sarif", "", "write merged findings as SARIF 2.1.0 to <file> (for GitHub Code Scanning)")
	configPath := fs.String("config", "", "path to secsuite.yaml")
	baselinePath := fs.String("baseline", "", "baseline file (default: <path>/"+secsuite.BaselineFilename+" when present)")
	noBaseline := fs.Bool("no-baseline", false, "ignore any baseline file")
	raw := fs.Bool("raw", false, "include each finding's raw scanner payload in --json output")
	fs.Bool("static-only", false, "static analysis only (this is the only mode in v0)")

	targetArg, err := parsePositional(fs, args, ".")
	if err != nil {
		return exitError
	}

	targetDir, err := filepath.Abs(targetArg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[secsuite] %v\n", err)
		return exitError
	}
	if err := requireDir("scan", targetDir); err != nil {
		fmt.Fprintf(os.Stderr, "[secsuite] %v\n", err)
		return exitError
	}

	config, err := secsuite.LoadConfig(*configPath, targetDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[secsuite] %v\n", err)
		return exitError
	}

	threshold, err := resolveThreshold(*severity, config.SeverityThreshold)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[secsuite] %v\n", err)
		return exitError
	}

	result, err := secsuite.RunStaticPipeline(targetDir, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[secsuite] %v\n", err)
		return exitError
	}
	if !result.AnyRan {
		fmt.Fprintln(os.Stderr, "[secsuite] every scanner failed to run - nothing was actually scanned.")
		return exitError
	}

	// A nil map means "no baseline in play", which is different from an empty
	// one and drives the hint printed further down.
	var baselineIDs map[string]bool
	if !*noBaseline {
		path := filepath.Join(targetDir, secsuite.BaselineFilename)
		if *baselinePath != "" {
			if path, err = filepath.Abs(*baselinePath); err != nil {
				fmt.Fprintf(os.Stderr, "[secsuite] %v\n", err)
				return exitError
			}
		}
		baselineIDs = secsuite.LoadBaselineIDs(path)
	}
	fresh, baselined := secsuite.SplitByBaseline(result.Findings, baselineIDs)

	// JSON and SARIF always carry everything; only the gate and the console
	// report are filtered to fresh findings.
	all := make([]secsuite.ReportFinding, 0, len(fresh)+len(baselined))
	for _, f := range fresh {
		all = append(all, secsuite.ReportFinding{Finding: f})
	}
	for _, f := range baselined {
		all = append(all, secsuite.ReportFinding{Finding: f, Baselined: true})
	}

	jsonFindings := all
	if !*raw {
		jsonFindings = secsuite.StripRaw(all)
	}

	shown, err := secsuite.PrintReport(fresh, threshold, *jsonPath, jsonFindings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[secsuite] %v\n", err)
		return exitError
	}

	// Human-mode extras; `--json -` keeps stdout machine-clean.
	if *jsonPath != "-" {
		if len(baselined) > 0 {
			fmt.Printf("%d baselined finding(s) suppressed (accepted in %s).\n", len(baselined), secsuite.BaselineFilename)
		}
		if len(shown) > 0 && baselineIDs == nil && !*noBaseline {
			fmt.Printf("help: secsuite baseline %s  # accept these once, gate only on new findings\n", targetArg)
		}
		if len(result.Skipped) > 0 {
			names := make([]string, len(result.Skipped))
			for i, t := range result.Skipped {
				names[i] = string(t)
			}
			fmt.Printf("help: secsuite doctor  # skipped: %s\n", strings.Join(names, ", "))
		}
	}

	if *sarifPath != "" {
		sarifInput := make([]secsuite.Finding, 0, len(all))
		for _, f := range all {
			sarifInput = append(sarifInput, f.Finding)
		}
		if err := writeSARIF(*sarifPath, sarifInput); err != nil {
			fmt.Fprintf(os.Stderr, "[secsuite] failed to write SARIF: %v\n", err)
			return exitError
		}
	}

	if len(shown) > 0 {
		return exitFindings
	}
	return exitClean
}

func runBaseline(args []string) int {
	fs := newFlagSet("baseline")
	configPath := fs.String("config", "", "path to secsuite.yaml")

	targetArg, err := parsePositional(fs, args, ".")
	if err != nil {
		return exitError
	}

	targetDir, err := filepath.Abs(targetArg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[secsuite] %v\n", err)
		return exitError
	}
	if err := requireDir("baseline", targetDir); err != nil {
		fmt.Fprintf(os.Stderr, "[secsuite] %v\n", err)
		return exitError
	}

	config, err := secsuite.LoadConfig(*configPath, targetDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[secsuite] %v\n", err)
		return exitError
	}

	result, err := secsuite.RunStaticPipeline(targetDir, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[secsuite] %v\n", err)
		return exitError
	}
	if !result.AnyRan {
		fmt.Fprintln(os.Stderr, "[secsuite] every scanner failed to run - refusing to write an empty baseline.")
		return exitError
	}

	baselinePath := filepath.Join(targetDir, secsuite.BaselineFilename)
	if err := secsuite.WriteBaseline(baselinePath, result.Findings); err != nil {
		fmt.Fprintf(os.Stderr, "[secsuite] %v\n", err)
		return exitError
	}

	fmt.Printf("[secsuite] baseline written: %d finding(s) accepted in %s.\n", len(result.Findings), baselinePath)
	fmt.Println("Commit this file; `secsuite scan` now reports only new findings. Line shifts re-surface a finding as new.")
	return exitClean
}

func runDast(args []string) int {
	fs := newFlagSet("dast")
	full := fs.Bool("full", false, "active scan (sends attack payloads - authorized targets only)")
	severity := fs.String("severity", "", "minimum severity to report (default: medium)")
	jsonPath := fs.String("json", "", "write full findings JSON to <file> (use - for stdout)")
	sarifPath := fs.String("sarif", "", "write merged findings as SARIF 2.1.0 to <file> (for GitHub Code Scanning)")
	raw := fs.Bool("raw", false, "include each finding's raw scanner payload in --json output")

	target, err := parsePositional(fs, args, "")
	if err != nil {
		return exitError
	}
	if !secsuite.IsHTTPURL(target) {
		fmt.Fprintf(os.Stderr, "[secsuite] dast target must be an http(s) URL, got: %s\n", target)
		return exitError
	}

	threshold, err := resolveThreshold(*severity, secsuite.SeverityMedium)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[secsuite] %v\n", err)
		return exitError
	}

	outDir, err := os.MkdirTemp("", "secsuite-dast-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[secsuite] creating temp dir: %v\n", err)
		return exitError
	}
	defer os.RemoveAll(outDir)

	result := secsuite.RunZapScan(target, outDir, *full)
	if !result.Ran || result.ReportPath == "" {
		fmt.Fprintln(os.Stderr, "[secsuite] DAST scan did not run - nothing was scanned.")
		return exitError
	}

	adapted, err := secsuite.AdaptZap(result.ReportPath, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[secsuite] %v\n", err)
		return exitError
	}
	findings := secsuite.DedupeFindings(adapted)

	jsonFindings := secsuite.ToReportFindings(findings)
	if !*raw {
		jsonFindings = secsuite.StripRaw(jsonFindings)
	}

	shown, err := secsuite.PrintReport(findings, threshold, *jsonPath, jsonFindings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[secsuite] %v\n", err)
		return exitError
	}

	if *sarifPath != "" {
		if err := writeSARIF(*sarifPath, findings); err != nil {
			fmt.Fprintf(os.Stderr, "[secsuite] failed to write SARIF: %v\n", err)
			return exitError
		}
	}

	if len(shown) > 0 {
		return exitFindings
	}
	return exitClean
}
