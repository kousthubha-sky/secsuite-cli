package secsuite

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// targetDir is arbitrary - the fixture SARIF uris are relative paths. It is
// built with filepath.Join so the relative-path math runs on the host's
// separator rather than assuming posix.
var targetDir = filepath.Join(string(filepath.Separator), "repo")

func fixture(name string) string {
	return filepath.Join("testdata", name)
}

// mkFinding is a minimal Finding builder for the dedupe unit tests.
func mkFinding(tool ToolName, ruleID, file string, category Category, severity Severity, startLine int) Finding {
	return Finding{
		ID:       string(tool) + "-" + ruleID + "-" + file,
		Tool:     tool,
		Category: category,
		RuleID:   ruleID,
		Severity: severity,
		Title:    ruleID,
		Location: Location{File: file, StartLine: startLine},
		Sources:  []string{string(tool)},
	}
}

func TestAdaptSemgrep(t *testing.T) {
	findings, err := AdaptSemgrep(fixture("semgrep.sarif"), targetDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.Tool != ToolSemgrep {
		t.Errorf("tool = %q, want semgrep", f.Tool)
	}
	if f.Category != CategorySAST {
		t.Errorf("category = %q, want sast", f.Category)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("severity = %q, want high (SARIF level error)", f.Severity)
	}
	if f.Location.File != "app.js" {
		t.Errorf("file = %q, want app.js", f.Location.File)
	}
	if f.Location.StartLine != 5 {
		t.Errorf("startLine = %d, want 5", f.Location.StartLine)
	}
}

func TestAdaptTrivy(t *testing.T) {
	findings, err := AdaptTrivy(fixture("trivy.sarif"), targetDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}

	vuln := findByRule(t, findings, "CVE-2020-8203")
	if vuln.Category != CategorySCA {
		t.Errorf("category = %q, want sca", vuln.Category)
	}
	if vuln.Severity != SeverityHigh {
		t.Errorf("severity = %q, want high (from the HIGH tag)", vuln.Severity)
	}

	secret := findByRule(t, findings, "aws-access-key-id")
	if secret.Category != CategorySecret {
		t.Errorf("category = %q, want secret", secret.Category)
	}
	if secret.Location.File != "config.py" {
		t.Errorf("file = %q, want config.py", secret.Location.File)
	}
}

func TestAdaptGitleaks(t *testing.T) {
	findings, err := AdaptGitleaks(fixture("gitleaks.sarif"), targetDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	// Gitleaks findings are always high/secret, whatever the SARIF says.
	if findings[0].Severity != SeverityHigh {
		t.Errorf("severity = %q, want high", findings[0].Severity)
	}
	if findings[0].Category != CategorySecret {
		t.Errorf("category = %q, want secret", findings[0].Category)
	}
	if findings[0].Location.File != "config.py" {
		t.Errorf("file = %q, want config.py", findings[0].Location.File)
	}
}

func TestAdaptZap(t *testing.T) {
	findings, err := AdaptZap(fixture("zap.json"), "https://staging.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3", len(findings))
	}

	sqli := findByRule(t, findings, "40018")
	if sqli.Tool != ToolZAP || sqli.Category != CategoryDAST {
		t.Errorf("tool/category = %q/%q, want zap/dast", sqli.Tool, sqli.Category)
	}
	if sqli.Severity != SeverityHigh {
		t.Errorf("severity = %q, want high (riskcode 3)", sqli.Severity)
	}
	if sqli.Location.File != "https://staging.example.com/search?q=1" {
		t.Errorf("location = %q, want the instance URI", sqli.Location.File)
	}
	// DAST findings have no line: 0 is how this port spells "absent".
	if sqli.Location.StartLine != 0 {
		t.Errorf("startLine = %d, want 0", sqli.Location.StartLine)
	}
	if len(sqli.References) == 0 || !strings.Contains(sqli.References[0], "cwe.mitre.org") ||
		!strings.Contains(sqli.References[0], "89") {
		t.Errorf("references = %v, want a CWE-89 link", sqli.References)
	}

	if got := findByRule(t, findings, "10038").Severity; got != SeverityMedium {
		t.Errorf("riskcode 2 mapped to %q, want medium", got)
	}
	if got := findByRule(t, findings, "10096").Severity; got != SeverityInfo {
		t.Errorf("riskcode 0 mapped to %q, want info", got)
	}
}

// The raw payload has to survive the adapter untouched, or --raw returns
// nothing useful.
func TestAdaptersCarryRawPayload(t *testing.T) {
	findings, err := AdaptGitleaks(fixture("gitleaks.sarif"), targetDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(findings[0].Raw), "aws-access-token") {
		t.Errorf("raw payload = %q, want the original SARIF result", findings[0].Raw)
	}
}

func TestDedupe(t *testing.T) {
	t.Run("merges cross-tool findings on the same file+line+category", func(t *testing.T) {
		trivy, err := AdaptTrivy(fixture("trivy.sarif"), targetDir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		gitleaks, err := AdaptGitleaks(fixture("gitleaks.sarif"), targetDir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// trivy has 2 findings (1 sca + 1 secret); gitleaks has 1 secret finding
		// on the same file+line as trivy's secret finding, so those two merge.
		merged := DedupeFindings(append(trivy, gitleaks...))
		if len(merged) != 2 {
			t.Fatalf("got %d findings, want 2", len(merged))
		}

		secret := findByCategory(t, merged, CategorySecret)
		if !hasSources(secret, "trivy", "gitleaks") {
			t.Errorf("sources = %v, want both trivy and gitleaks", secret.Sources)
		}
	})

	t.Run("keeps distinct findings separate", func(t *testing.T) {
		semgrep, _ := AdaptSemgrep(fixture("semgrep.sarif"), targetDir)
		trivy, _ := AdaptTrivy(fixture("trivy.sarif"), targetDir)
		if got := len(DedupeFindings(append(semgrep, trivy...))); got != 3 {
			t.Errorf("got %d findings, want 3", got)
		}
	})

	t.Run("does NOT merge two findings from the same tool at one location", func(t *testing.T) {
		// Two CVEs on the same dependency line (trivy emits one per CVE) must
		// both survive - collapsing them under-counts real vulnerabilities.
		findings := []Finding{
			mkFinding(ToolTrivy, "CVE-1111", "requirements.txt", CategorySCA, SeverityHigh, 1),
			mkFinding(ToolTrivy, "CVE-2222", "requirements.txt", CategorySCA, SeverityCritical, 1),
		}
		if got := len(DedupeFindings(findings)); got != 2 {
			t.Errorf("got %d findings, want 2", got)
		}
	})

	t.Run("does NOT merge distinct ZAP alerts on the same URL", func(t *testing.T) {
		// DAST findings have no line number, so several alerts on one URL share
		// file+category; they must not collapse into one.
		findings := []Finding{
			mkFinding(ToolZAP, "40018", "https://app/", CategoryDAST, SeverityHigh, 0),
			mkFinding(ToolZAP, "10038", "https://app/", CategoryDAST, SeverityMedium, 0),
		}
		if got := len(DedupeFindings(findings)); got != 2 {
			t.Errorf("got %d findings, want 2", got)
		}
	})

	t.Run("merges across DIFFERENT tools and keeps the most severe", func(t *testing.T) {
		findings := []Finding{
			mkFinding(ToolTrivy, "aws-key", "config.py", CategorySecret, SeverityCritical, 4),
			mkFinding(ToolGitleaks, "aws-access-token", "config.py", CategorySecret, SeverityHigh, 4),
		}
		merged := DedupeFindings(findings)
		if len(merged) != 1 {
			t.Fatalf("got %d findings, want 1", len(merged))
		}
		if !hasSources(merged[0], "trivy", "gitleaks") {
			t.Errorf("sources = %v, want both tools", merged[0].Sources)
		}
		if merged[0].Severity != SeverityCritical {
			t.Errorf("severity = %q, want critical", merged[0].Severity)
		}
	})

	// The Go rewrite is where this can regress: a JS Map iterates in insertion
	// order for free, a Go map does not.
	t.Run("preserves input order", func(t *testing.T) {
		findings := []Finding{
			mkFinding(ToolTrivy, "a", "z.txt", CategorySCA, SeverityLow, 1),
			mkFinding(ToolTrivy, "b", "y.txt", CategorySCA, SeverityLow, 2),
			mkFinding(ToolTrivy, "c", "x.txt", CategorySCA, SeverityLow, 3),
			mkFinding(ToolTrivy, "d", "w.txt", CategorySCA, SeverityLow, 4),
		}
		for i := 0; i < 20; i++ {
			merged := DedupeFindings(findings)
			for j, want := range []string{"a", "b", "c", "d"} {
				if merged[j].RuleID != want {
					t.Fatalf("run %d: position %d = %q, want %q", i, j, merged[j].RuleID, want)
				}
			}
		}
	})

	// Sources is a slice, and a slice assignment shares its backing array.
	t.Run("does not mutate the caller's findings", func(t *testing.T) {
		input := []Finding{
			mkFinding(ToolTrivy, "aws-key", "config.py", CategorySecret, SeverityCritical, 4),
			mkFinding(ToolGitleaks, "aws-token", "config.py", CategorySecret, SeverityHigh, 4),
		}
		DedupeFindings(input)
		if len(input[0].Sources) != 1 {
			t.Errorf("input finding sources = %v, want the original single entry", input[0].Sources)
		}
	})
}

func TestDetectStack(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "go.mod"), "module x")
	mustWrite(t, filepath.Join(dir, "pom.xml"), "<project/>")
	if err := os.MkdirAll(filepath.Join(dir, "src", "App"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(dir, "src", "App", "App.csproj"), "<Project/>")

	stack := DetectStack(dir)
	for _, want := range []string{"go", "java", "csharp"} {
		if !contains(stack.Languages, want) {
			t.Errorf("%q not detected in %v", want, stack.Languages)
		}
	}
	if stack.IsGit {
		t.Error("IsGit = true for a directory with no .git")
	}
}

func TestResolveScanners(t *testing.T) {
	// Semgrep needs a recognized language; the other two always run.
	withLang := ResolveScanners(StackInfo{Languages: []string{"go"}})
	if len(withLang) != 3 || withLang[0] != ToolSemgrep {
		t.Errorf("got %v, want semgrep first of three", withLang)
	}
	bare := ResolveScanners(StackInfo{})
	if len(bare) != 2 || contains(toolNames(bare), "semgrep") {
		t.Errorf("got %v, want trivy and gitleaks only", bare)
	}
}

func findByRule(t *testing.T, findings []Finding, ruleID string) Finding {
	t.Helper()
	for _, f := range findings {
		if f.RuleID == ruleID {
			return f
		}
	}
	t.Fatalf("no finding with ruleId %q", ruleID)
	return Finding{}
}

func findByCategory(t *testing.T, findings []Finding, category Category) Finding {
	t.Helper()
	for _, f := range findings {
		if f.Category == category {
			return f
		}
	}
	t.Fatalf("no finding in category %q", category)
	return Finding{}
}

func hasSources(f Finding, want ...string) bool {
	if len(f.Sources) != len(want) {
		return false
	}
	for _, w := range want {
		if !contains(f.Sources, w) {
			return false
		}
	}
	return true
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func toolNames(tools []ToolName) []string {
	names := make([]string, len(tools))
	for i, t := range tools {
		names[i] = string(t)
	}
	return names
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return data
}
