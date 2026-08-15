package secsuite

import (
	"encoding/json"
	"testing"
)

func mkRefFinding(tool ToolName, ruleID, file string, category Category, severity Severity, startLine int) Finding {
	f := mkFinding(tool, ruleID, file, category, severity, startLine)
	f.Title = "title for " + ruleID
	f.References = []string{"https://example.com/rule"}
	return f
}

func TestFindingsToSARIFShell(t *testing.T) {
	doc := FindingsToSARIF([]Finding{
		mkRefFinding(ToolTrivy, "CVE-1", "requirements.txt", CategorySCA, SeverityCritical, 2),
	}, "0.2.0")

	if doc.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("got %d runs, want 1", len(doc.Runs))
	}
	if doc.Runs[0].Tool.Driver.Name != "secsuite" {
		t.Errorf("driver = %q, want secsuite", doc.Runs[0].Tool.Driver.Name)
	}
	if doc.Runs[0].Tool.Driver.Version != "0.2.0" {
		t.Errorf("driver version = %q, want 0.2.0", doc.Runs[0].Tool.Driver.Version)
	}
	if len(doc.Runs[0].Results) != 1 {
		t.Errorf("got %d results, want 1", len(doc.Runs[0].Results))
	}
}

func TestFindingsToSARIFLevels(t *testing.T) {
	findings := []Finding{
		mkRefFinding(ToolTrivy, "a", "f1", CategorySCA, SeverityCritical, 1),
		mkRefFinding(ToolTrivy, "b", "f2", CategorySCA, SeverityHigh, 1),
		mkRefFinding(ToolTrivy, "c", "f3", CategorySCA, SeverityMedium, 1),
		mkRefFinding(ToolTrivy, "d", "f4", CategorySCA, SeverityLow, 1),
		mkRefFinding(ToolTrivy, "e", "f5", CategorySCA, SeverityInfo, 1),
	}
	want := []string{"error", "error", "warning", "note", "note"}

	for i, result := range FindingsToSARIF(findings, "0.2.0").Runs[0].Results {
		if result.Level != want[i] {
			t.Errorf("result %d level = %q, want %q", i, result.Level, want[i])
		}
	}
}

func TestFindingsToSARIFLocations(t *testing.T) {
	doc := FindingsToSARIF([]Finding{
		mkRefFinding(ToolSemgrep, "r1", `src\app\main.py`, CategorySAST, SeverityHigh, 10),
		mkRefFinding(ToolZAP, "40018", "https://staging.example.com/search", CategoryDAST, SeverityHigh, 0),
	}, "0.2.0")

	code, dast := doc.Runs[0].Results[0], doc.Runs[0].Results[1]

	if got := code.Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "src/app/main.py" {
		t.Errorf("uri = %q, want forward slashes", got)
	}
	if code.Locations[0].PhysicalLocation.Region == nil {
		t.Fatal("a code finding with a line lost its region")
	}
	if got := code.Locations[0].PhysicalLocation.Region.StartLine; got != 10 {
		t.Errorf("startLine = %d, want 10", got)
	}

	if got := dast.Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "https://staging.example.com/search" {
		t.Errorf("uri = %q, want the URL untouched", got)
	}
	// The pointer is what makes this possible: a struct value with omitempty
	// would still have emitted "region": {"startLine": 0}.
	if dast.Locations[0].PhysicalLocation.Region != nil {
		t.Error("a DAST finding with no line still emitted a region")
	}

	payload, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := raw["$schema"]; !ok {
		t.Errorf("$schema missing from the encoded document: %s", payload)
	}
}

func TestFindingsToSARIFRulesAreUnique(t *testing.T) {
	findings := []Finding{
		mkRefFinding(ToolTrivy, "CVE-1", "a.txt", CategorySCA, SeverityHigh, 1),
		mkRefFinding(ToolTrivy, "CVE-1", "b.txt", CategorySCA, SeverityHigh, 2),
	}
	run := FindingsToSARIF(findings, "0.2.0").Runs[0]

	if len(run.Tool.Driver.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(run.Tool.Driver.Rules))
	}
	if run.Tool.Driver.Rules[0].ID != "CVE-1" {
		t.Errorf("rule id = %q, want CVE-1", run.Tool.Driver.Rules[0].ID)
	}
	if run.Results[0].RuleIndex != 0 || run.Results[1].RuleIndex != 0 {
		t.Errorf("rule indexes = %d/%d, want both 0", run.Results[0].RuleIndex, run.Results[1].RuleIndex)
	}
	// Stable across re-runs so GitHub alert tracking survives new scans.
	if run.Results[0].PartialFingerprints["secsuiteId"] != findings[0].ID {
		t.Errorf("fingerprint = %q, want the finding id", run.Results[0].PartialFingerprints["secsuiteId"])
	}
	if run.Results[0].Properties.Category != CategorySCA {
		t.Errorf("category property = %q, want sca", run.Results[0].Properties.Category)
	}
}
