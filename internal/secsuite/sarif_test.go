package secsuite

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The dedupe key is a string built from a file path. filepath.Join produces
// backslashes on Windows while SARIF emits forward slashes, so if this stopped
// normalizing, cross-tool duplicates would silently stop merging - the failure
// would look like "more findings than expected", not like a bug.
func TestNormalizeRelPath(t *testing.T) {
	repo := filepath.Join(string(filepath.Separator), "repo")

	tests := []struct {
		name string
		uri  string
		want string
	}{
		{"already relative", "app.js", "app.js"},
		{"nested relative", "src/app/main.py", "src/app/main.py"},
		{"percent-encoded space", "src/my%20file.js", "src/my file.js"},
		{"dot prefix", "./app.js", "app.js"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeRelPath(tt.uri, repo); got != tt.want {
				t.Errorf("normalizeRelPath(%q) = %q, want %q", tt.uri, got, tt.want)
			}
		})
	}

	t.Run("output never contains a backslash", func(t *testing.T) {
		got := normalizeRelPath("src/app/main.py", repo)
		if strings.Contains(got, `\`) {
			t.Errorf("got %q, want forward slashes only", got)
		}
	})
}

// Node treated "/C:/repo/app.js" as an absolute path on Windows; Go does not,
// because an absolute Windows path needs its volume first.
func TestNormalizeRelPathWindowsFileURI(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows drive-letter URIs only arise on windows")
	}
	if got := normalizeRelPath(`file:///C:/repo/src/app.js`, `C:\repo`); got != "src/app.js" {
		t.Errorf("got %q, want src/app.js", got)
	}
}

// Baselines match on this id, so the inputs and their order are a compatibility
// contract - a baseline committed by the TypeScript release has to keep working
// after the binary is swapped underneath it.
func TestMakeFindingIDIsStable(t *testing.T) {
	const want = "6af6b5ad48aeb22c"
	got := MakeFindingID("semgrep",
		"generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value",
		"config.py", 1)
	if got != want {
		t.Errorf("id = %q, want %q - this breaks every committed baseline", got, want)
	}
}

func TestMakeFindingIDDistinguishesInputs(t *testing.T) {
	base := MakeFindingID("trivy", "CVE-1", "a.txt", 1)

	tests := []struct {
		name string
		id   string
	}{
		{"different tool", MakeFindingID("gitleaks", "CVE-1", "a.txt", 1)},
		{"different rule", MakeFindingID("trivy", "CVE-2", "a.txt", 1)},
		{"different file", MakeFindingID("trivy", "CVE-1", "b.txt", 1)},
		{"different line", MakeFindingID("trivy", "CVE-1", "a.txt", 2)},
		// A missing line hashes as "", not as "0" - that is what the TypeScript
		// `startLine ?? ""` produced, and baselines depend on it.
		{"absent line", MakeFindingID("trivy", "CVE-1", "a.txt", 0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.id == base {
				t.Errorf("id collided with the base finding: %q", tt.id)
			}
			if len(tt.id) != 16 {
				t.Errorf("id = %q, want 16 characters", tt.id)
			}
		})
	}
}

// SARIF nests results[].locations[].physicalLocation.region.startLine. Every
// link is optional, and an unchecked index on a missing one panics in Go where
// TypeScript just returned undefined.
func TestParseSarifResultsSkipsIncompleteResults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "partial.sarif")
	mustWrite(t, path, `{
	  "runs": [{
	    "tool": {"driver": {"rules": []}},
	    "results": [
	      {"ruleId": "no-locations", "message": {"text": "x"}},
	      {"ruleId": "empty-locations", "locations": []},
	      {"ruleId": "no-uri", "locations": [{"physicalLocation": {"region": {"startLine": 3}}}]},
	      {"ruleId": "usable", "locations": [{"physicalLocation": {
	        "artifactLocation": {"uri": "app.js"}, "region": {"startLine": 7}}}]}
	    ]
	  }]
	}`)

	entries, err := ParseSarifResults(path, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want only the usable one", len(entries))
	}
	if entries[0].RuleID != "usable" || entries[0].StartLine != 7 {
		t.Errorf("entry = %+v, want the usable result at line 7", entries[0])
	}
}

// Per the SARIF spec a result with no level inherits the rule's
// defaultConfiguration.level, which is how semgrep avoids repeating itself.
func TestParseSarifResultsInheritsRuleLevel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inherit.sarif")
	mustWrite(t, path, `{
	  "runs": [{
	    "tool": {"driver": {"rules": [
	      {"id": "r1", "defaultConfiguration": {"level": "error"},
	       "shortDescription": {"text": "short"}, "properties": {"tags": ["HIGH"]}}
	    ]}},
	    "results": [
	      {"ruleId": "r1", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.js"}}}]},
	      {"ruleId": "r1", "level": "note", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "b.js"}}}]}
	    ]
	  }]
	}`)

	entries, err := ParseSarifResults(path, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Level != "error" {
		t.Errorf("level = %q, want the rule's default", entries[0].Level)
	}
	if entries[1].Level != "note" {
		t.Errorf("level = %q, want the result's own level to win", entries[1].Level)
	}
	if entries[0].Rule.ShortDescription != "short" || len(entries[0].Rule.Tags) != 1 {
		t.Errorf("rule metadata did not attach: %+v", entries[0].Rule)
	}
}

// An unknown ruleId yields the zero SarifRule rather than a nil pointer, which
// is what lets the adapters fall through to their defaults without nil checks.
func TestParseSarifResultsUnknownRuleIsZeroValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "orphan.sarif")
	mustWrite(t, path, `{
	  "runs": [{
	    "tool": {"driver": {"rules": []}},
	    "results": [{"ruleId": "missing-rule",
	      "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.js"}}}]}]
	  }]
	}`)

	entries, err := ParseSarifResults(path, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entries[0].Rule.ShortDescription != "" || entries[0].Rule.HelpURI != "" {
		t.Errorf("rule = %+v, want the zero value", entries[0].Rule)
	}
}
