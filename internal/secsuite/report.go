package secsuite

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ReportFinding is a Finding as it appears in --json and --sarif output.
//
// The embedded Finding is not a field named "Finding": Go promotes an embedded
// struct's fields, and encoding/json flattens them into the same JSON object.
// So this marshals as a normal finding, plus one extra key - which is exactly
// what the TypeScript `{ ...f, baselined: true }` spread produced.
type ReportFinding struct {
	Finding
	Baselined bool `json:"baselined,omitempty"`
}

// ToReportFindings wraps plain findings for output, marking none as baselined.
func ToReportFindings(findings []Finding) []ReportFinding {
	// make(...) not var: a nil slice marshals to JSON `null`, but an empty
	// allocated slice marshals to `[]`. Any consumer piping `--json -` into jq
	// would break on null.
	out := make([]ReportFinding, 0, len(findings))
	for _, f := range findings {
		out = append(out, ReportFinding{Finding: f})
	}
	return out
}

// StripRaw drops each finding's raw scanner payload. It is by far the largest
// field and rarely needed; agents opt back in with --raw.
func StripRaw(findings []ReportFinding) []ReportFinding {
	out := make([]ReportFinding, 0, len(findings))
	for _, f := range findings {
		// f is a per-iteration copy, so clearing it cannot touch the caller's
		// slice - no object spread needed to avoid mutating the original.
		f.Raw = nil
		out = append(out, f)
	}
	return out
}

// FilterByThreshold keeps only findings at or above threshold.
func FilterByThreshold(findings []Finding, threshold Severity) []Finding {
	minRank := threshold.Rank()
	shown := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if f.Severity.Rank() <= minRank {
			shown = append(shown, f)
		}
	}
	return shown
}

// PrintReport writes the human report to stdout and returns the findings that
// passed the threshold - the set the exit code gates on.
//
// jsonPath is "" for no JSON output, "-" for machine mode, or a file path.
func PrintReport(findings []Finding, threshold Severity, jsonPath string, jsonFindings []ReportFinding) ([]Finding, error) {
	shown := FilterByThreshold(findings, threshold)

	// Machine mode: `--json -` streams one compact JSON payload to stdout and
	// suppresses the human report - nothing else may touch stdout.
	if jsonPath == "-" {
		payload, err := json.Marshal(jsonFindings)
		if err != nil {
			return shown, fmt.Errorf("encoding findings: %w", err)
		}
		fmt.Println(string(payload))
		return shown, nil
	}

	if len(shown) == 0 {
		fmt.Printf("No findings at or above severity %q.\n", threshold)
	} else {
		for _, severity := range allSeverities {
			atSeverity := findingsWithSeverity(shown, severity)
			if len(atSeverity) == 0 {
				continue
			}

			fmt.Printf("\n%s (%d)\n", strings.ToUpper(string(severity)), len(atSeverity))
			categories, byCategory := groupByCategory(atSeverity)
			for _, category := range categories {
				fmt.Printf("  %s:\n", category)
				for _, f := range byCategory[category] {
					loc := f.Location.File
					if f.Location.StartLine != 0 {
						loc += ":" + strconv.Itoa(f.Location.StartLine)
					}
					sources := ""
					if len(f.Sources) > 1 {
						sources = " [" + strings.Join(f.Sources, ", ") + "]"
					}
					fmt.Printf("    - %s (%s)%s\n", f.Title, loc, sources)
				}
			}
		}
	}

	counts := make([]string, len(allSeverities))
	for i, severity := range allSeverities {
		counts[i] = fmt.Sprintf("%s: %d", severity, len(findingsWithSeverity(shown, severity)))
	}
	fmt.Printf("\nTotal: %d finding(s) at or above %q (%s)\n", len(shown), threshold, strings.Join(counts, ", "))

	if jsonPath != "" {
		payload, err := json.MarshalIndent(jsonFindings, "", "  ")
		if err != nil {
			return shown, fmt.Errorf("encoding findings: %w", err)
		}
		if err := os.WriteFile(jsonPath, payload, 0o644); err != nil {
			return shown, fmt.Errorf("writing %s: %w", jsonPath, err)
		}
		fmt.Printf("Full findings (all severities) written to %s\n", jsonPath)
	}

	return shown, nil
}

func findingsWithSeverity(findings []Finding, severity Severity) []Finding {
	var matched []Finding
	for _, f := range findings {
		if f.Severity == severity {
			matched = append(matched, f)
		}
	}
	return matched
}

// groupByCategory returns the categories in first-seen order plus the findings
// under each. The order slice exists for the same reason it does in dedupe: a
// Go map alone would shuffle the report's sections between runs.
func groupByCategory(findings []Finding) ([]Category, map[Category][]Finding) {
	var order []Category
	groups := make(map[Category][]Finding)
	for _, f := range findings {
		if _, seen := groups[f.Category]; !seen {
			order = append(order, f.Category)
		}
		groups[f.Category] = append(groups[f.Category], f)
	}
	return order, groups
}
