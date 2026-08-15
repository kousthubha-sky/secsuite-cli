package secsuite

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestBaselineRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), BaselineFilename)
	findings := []Finding{
		mkFinding(ToolTrivy, "CVE-1", "requirements.txt", CategorySCA, SeverityCritical, 1),
		mkFinding(ToolGitleaks, "aws-key", "config.py", CategorySecret, SeverityHigh, 4),
	}

	if err := WriteBaseline(path, findings); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ids := LoadBaselineIDs(path)
	if len(ids) != 2 {
		t.Fatalf("loaded %d ids, want 2", len(ids))
	}
	for _, f := range findings {
		if !ids[f.ID] {
			t.Errorf("id %q did not round-trip", f.ID)
		}
	}
}

func TestLoadBaselineIDsMissingFile(t *testing.T) {
	// nil, not an empty map: the caller uses the difference to decide whether
	// to suggest creating a baseline.
	if ids := LoadBaselineIDs(filepath.Join(t.TempDir(), "does-not-exist.json")); ids != nil {
		t.Errorf("got %v, want nil", ids)
	}
}

func TestLoadBaselineIDsCorruptFile(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name    string
		content string
	}{
		{"not json at all", "{ not json !!"},
		{"wrong version", `{"version":99,"findings":[]}`},
		{"findings is not an array", `{"version":1,"findings":"nope"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.name+".json")
			mustWrite(t, path, tt.content)
			// A broken baseline must read as absent, so it can only ever
			// surface MORE findings, never hide them.
			if ids := LoadBaselineIDs(path); ids != nil {
				t.Errorf("got %v, want nil", ids)
			}
		})
	}
}

// An empty-but-valid baseline is not the same as a missing one.
func TestLoadBaselineIDsEmptyIsNotNil(t *testing.T) {
	path := filepath.Join(t.TempDir(), BaselineFilename)
	if err := WriteBaseline(path, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ids := LoadBaselineIDs(path)
	if ids == nil {
		t.Fatal("an empty baseline read as absent")
	}
	if len(ids) != 0 {
		t.Errorf("got %d ids, want 0", len(ids))
	}
}

func TestSplitByBaseline(t *testing.T) {
	known := mkFinding(ToolTrivy, "CVE-1", "a.txt", CategorySCA, SeverityHigh, 1)
	novel := mkFinding(ToolTrivy, "CVE-2", "a.txt", CategorySCA, SeverityCritical, 1)

	fresh, baselined := SplitByBaseline([]Finding{known, novel}, map[string]bool{known.ID: true})
	if len(fresh) != 1 || fresh[0].ID != novel.ID {
		t.Errorf("fresh = %v, want just the new finding", fresh)
	}
	if len(baselined) != 1 || baselined[0].ID != known.ID {
		t.Errorf("baselined = %v, want just the known finding", baselined)
	}

	fresh, baselined = SplitByBaseline([]Finding{known, novel}, nil)
	if len(fresh) != 2 || len(baselined) != 0 {
		t.Errorf("no baseline should leave everything fresh, got %d/%d", len(fresh), len(baselined))
	}
}

// startLine is omitempty, so a DAST finding with no line must not write
// "startLine": 0 into a file humans review and commit.
func TestWriteBaselineOmitsAbsentLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), BaselineFilename)
	findings := []Finding{mkFinding(ToolZAP, "40018", "https://app/", CategoryDAST, SeverityHigh, 0)}
	if err := WriteBaseline(path, findings); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var doc struct {
		Findings []map[string]any `json:"findings"`
	}
	data := mustRead(t, path)
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, present := doc.Findings[0]["startLine"]; present {
		t.Errorf("startLine was written for a finding that has none: %s", data)
	}
}
