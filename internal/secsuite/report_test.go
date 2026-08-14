package secsuite

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStdout swaps os.Stdout for a pipe while fn runs and returns whatever
// was written. The report prints with fmt.Println rather than taking a writer,
// so this is how its stdout discipline gets tested at all.
//
// Only safe for small outputs: an OS pipe buffer is finite, and filling it
// would block fn forever with nothing draining the other end.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating pipe: %v", err)
	}
	original := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = original }()

	fn()
	w.Close()

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading captured stdout: %v", err)
	}
	return string(out)
}

func mkRawFinding(tool ToolName, ruleID, file string, category Category, severity Severity, startLine int) Finding {
	f := mkFinding(tool, ruleID, file, category, severity, startLine)
	f.Raw = json.RawMessage(`{"huge":"scanner payload"}`)
	return f
}

func TestStripRaw(t *testing.T) {
	input := ToReportFindings([]Finding{
		mkRawFinding(ToolTrivy, "CVE-1", "a.txt", CategorySCA, SeverityCritical, 3),
	})
	lean := StripRaw(input)

	if lean[0].Raw != nil {
		t.Errorf("raw = %s, want nil", lean[0].Raw)
	}
	if lean[0].RuleID != "CVE-1" || lean[0].Severity != SeverityCritical {
		t.Errorf("stripping dropped other fields: %+v", lean[0])
	}
	if lean[0].Location.StartLine != 3 {
		t.Errorf("startLine = %d, want 3", lean[0].Location.StartLine)
	}
	if len(lean[0].Sources) != 1 || lean[0].Sources[0] != "trivy" {
		t.Errorf("sources = %v, want [trivy]", lean[0].Sources)
	}
	// The caller's copy must be untouched - --json strips, --sarif does not.
	if input[0].Raw == nil {
		t.Error("StripRaw mutated its input")
	}
}

func TestPrintReportMachineMode(t *testing.T) {
	findings := []Finding{mkRawFinding(ToolTrivy, "CVE-1", "a.txt", CategorySCA, SeverityHigh, 1)}

	var shown []Finding
	out := captureStdout(t, func() {
		var err error
		shown, err = PrintReport(findings, SeverityMedium, "-", ToReportFindings(findings))
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	if len(shown) != 1 {
		t.Errorf("gate saw %d findings, want 1", len(shown))
	}
	// `--json -` must emit exactly one compact line and nothing else.
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d lines on stdout, want exactly 1:\n%s", len(lines), out)
	}

	var parsed []ReportFinding
	if err := json.Unmarshal([]byte(lines[0]), &parsed); err != nil {
		t.Fatalf("stdout was not valid JSON: %v", err)
	}
	if len(parsed) != 1 || parsed[0].RuleID != "CVE-1" {
		t.Errorf("payload = %+v, want one CVE-1 finding", parsed)
	}
}

// A nil slice marshals to `null` and an allocated empty one to `[]`. Anything
// piping --json - into jq breaks on null, so this is worth pinning down.
func TestPrintReportMachineModeEmpty(t *testing.T) {
	out := captureStdout(t, func() {
		if _, err := PrintReport(nil, SeverityMedium, "-", ToReportFindings(nil)); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
	if strings.TrimSpace(out) != "[]" {
		t.Errorf("stdout = %q, want []", strings.TrimSpace(out))
	}
}

func TestPrintReportHumanMode(t *testing.T) {
	findings := []Finding{
		mkFinding(ToolTrivy, "CVE-1", "a.txt", CategorySCA, SeverityCritical, 3),
		mkFinding(ToolSemgrep, "rule-x", "b.js", CategorySAST, SeverityLow, 9),
	}

	out := captureStdout(t, func() {
		shown, err := PrintReport(findings, SeverityHigh, "", ToReportFindings(findings))
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		// low is below the high threshold, so only the critical one is gated on.
		if len(shown) != 1 {
			t.Errorf("gate saw %d findings, want 1", len(shown))
		}
	})

	if !strings.Contains(out, "CRITICAL (1)") {
		t.Errorf("missing the CRITICAL section:\n%s", out)
	}
	if !strings.Contains(out, "a.txt:3") {
		t.Errorf("missing the file:line location:\n%s", out)
	}
	if strings.Contains(out, "rule-x") {
		t.Errorf("a below-threshold finding was printed:\n%s", out)
	}
	if !strings.Contains(out, `Total: 1 finding(s) at or above "high"`) {
		t.Errorf("missing the totals line:\n%s", out)
	}
}

func TestPrintReportWritesJSONFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.json")
	findings := []Finding{mkFinding(ToolTrivy, "CVE-1", "a.txt", CategorySCA, SeverityInfo, 1)}

	captureStdout(t, func() {
		// The gate is empty at this threshold, but the JSON file still carries
		// every severity - that split is the whole point of --json.
		shown, err := PrintReport(findings, SeverityHigh, path, ToReportFindings(findings))
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(shown) != 0 {
			t.Errorf("gate saw %d findings, want 0", len(shown))
		}
	})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var parsed []ReportFinding
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("output was not valid JSON: %v", err)
	}
	if len(parsed) != 1 || parsed[0].Severity != SeverityInfo {
		t.Errorf("file = %+v, want the info finding", parsed)
	}
}

func TestFilterByThreshold(t *testing.T) {
	findings := []Finding{
		mkFinding(ToolTrivy, "a", "f", CategorySCA, SeverityCritical, 1),
		mkFinding(ToolTrivy, "b", "f", CategorySCA, SeverityMedium, 2),
		mkFinding(ToolTrivy, "c", "f", CategorySCA, SeverityInfo, 3),
	}

	tests := []struct {
		threshold Severity
		want      int
	}{
		{SeverityCritical, 1},
		{SeverityMedium, 2},
		{SeverityInfo, 3},
	}
	for _, tt := range tests {
		t.Run(string(tt.threshold), func(t *testing.T) {
			if got := len(FilterByThreshold(findings, tt.threshold)); got != tt.want {
				t.Errorf("got %d findings, want %d", got, tt.want)
			}
		})
	}
}

// The baselined marker is an extra key on an otherwise normal finding, which is
// what embedding a struct buys.
func TestReportFindingFlattensIntoJSON(t *testing.T) {
	payload, err := json.Marshal(ReportFinding{
		Finding:   mkFinding(ToolTrivy, "CVE-1", "a.txt", CategorySCA, SeverityHigh, 1),
		Baselined: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var flat map[string]any
	if err := json.Unmarshal(payload, &flat); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, nested := flat["Finding"]; nested {
		t.Errorf("embedded struct was nested rather than flattened: %s", payload)
	}
	if flat["ruleId"] != "CVE-1" || flat["baselined"] != true {
		t.Errorf("payload = %s, want a flat finding plus baselined", payload)
	}
}
