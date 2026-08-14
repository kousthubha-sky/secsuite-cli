package secsuite

import (
	"os"
	"path/filepath"
	"regexp"
)

// StackInfo is what a scan target looks like: which language ecosystems are
// present, and whether it is a git repository.
type StackInfo struct {
	Languages []string // detected language/ecosystem keys, e.g. ["java", "go"]
	IsGit     bool
}

// manifests maps a language/ecosystem to the files that mark it. Semgrep's
// `--config auto` and trivy both have rules for all of these, so detecting any
// one is enough to run the SAST lane. Covers the six languages behind ~80% of
// new repos (GitHub Octoverse 2025) plus Go/Rust/PHP/Ruby.
//
// A slice of structs, not a map, because the detected languages are printed to
// the user and a Go map would list them in a different order on every run.
var manifests = []struct {
	lang  string
	files []string
}{
	{"js", []string{"package.json", "tsconfig.json"}},
	{"python", []string{"pyproject.toml", "requirements.txt", "setup.py", "Pipfile"}},
	{"java", []string{"pom.xml", "build.gradle", "build.gradle.kts"}}, // incl. Spring / J2EE
	{"go", []string{"go.mod"}},
	{"rust", []string{"Cargo.toml"}},
	{"php", []string{"composer.json"}},
	{"ruby", []string{"Gemfile"}},
}

// extensions covers languages keyed off a file extension rather than a fixed
// manifest name (a .NET repo has an arbitrarily-named .csproj/.sln, not a fixed
// filename). These are matched against a shallow directory walk, since a
// .csproj usually lives in a nested project folder (src/Foo/Foo.csproj), not
// the repo root.
//
// regexp.MustCompile at package level compiles the pattern once at startup and
// panics on a bad pattern, which is what you want for a literal you wrote.
var extensions = []struct {
	lang    string
	pattern *regexp.Regexp
}{
	{"csharp", regexp.MustCompile(`(?i)\.(csproj|sln)$`)}, // .NET / ASP.NET Core
}

// skipDirs are directories not worth walking when looking for project files.
var skipDirs = map[string]bool{
	"node_modules": true, ".git": true, "dist": true, "build": true,
	"bin": true, "obj": true, ".venv": true, "venv": true,
	"vendor": true, "target": true, ".idea": true, ".vs": true,
}

const walkDepth = 2 // root + 2 levels catches src/Foo/Foo.csproj

// DetectStack inspects targetDir and reports which ecosystems it contains.
func DetectStack(targetDir string) StackInfo {
	exists := func(name string) bool {
		_, err := os.Stat(filepath.Join(targetDir, name))
		return err == nil
	}
	hasAny := func(files []string) bool {
		for _, f := range files {
			if exists(f) {
				return true
			}
		}
		return false
	}

	var languages []string
	for _, m := range manifests {
		if hasAny(m.files) {
			languages = append(languages, m.lang)
		}
	}

	names := walkShallow(targetDir, walkDepth)
	for _, e := range extensions {
		for _, name := range names {
			if e.pattern.MatchString(name) {
				languages = append(languages, e.lang)
				break
			}
		}
	}

	return StackInfo{Languages: languages, IsGit: exists(".git")}
}

// ResolveScanners picks which scanners to run for a stack.
//
// Semgrep needs a recognized language to be useful; trivy and gitleaks are
// stack-agnostic (SCA/secrets/misconfig apply to any repo), so they always run.
func ResolveScanners(stack StackInfo) []ToolName {
	var scanners []ToolName
	if len(stack.Languages) > 0 {
		scanners = append(scanners, ToolSemgrep)
	}
	return append(scanners, ToolTrivy, ToolGitleaks)
}

// walkShallow collects file/dir names from dir down to maxDepth, skipping
// vendored and build directories. Names only (not full paths) - callers just
// extension-match.
func walkShallow(dir string, maxDepth int) []string {
	var names []string

	// Declared with `var visit func(...)` before being assigned, because a
	// recursive function literal cannot refer to itself inside its own
	// short-variable declaration - the name is not in scope yet.
	var visit func(d string, depth int)
	visit = func(d string, depth int) {
		entries, err := os.ReadDir(d)
		if err != nil {
			return // unreadable directory: skip it, same as the TS try/catch
		}
		for _, e := range entries {
			names = append(names, e.Name())
			if e.IsDir() && depth < maxDepth && !skipDirs[e.Name()] {
				visit(filepath.Join(d, e.Name()), depth+1)
			}
		}
	}
	visit(dir, 0)

	return names
}
