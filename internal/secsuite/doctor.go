package secsuite

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

// CheckResult is one environment check.
type CheckResult struct {
	Name   string
	OK     bool
	Detail string
	Hint   string
}

// installHints are the per-platform install commands shown for a missing tool.
var installHints = map[string]map[string]string{
	"semgrep": {
		"windows": "pipx install semgrep",
		"darwin":  "brew install semgrep",
		"linux":   "pipx install semgrep",
	},
	"trivy": {
		"windows": "winget install AquaSecurity.Trivy",
		"darwin":  "brew install trivy",
		"linux":   "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin",
	},
	"gitleaks": {
		"windows": "winget install Gitleaks.Gitleaks",
		"darwin":  "brew install gitleaks",
		"linux":   "download from https://github.com/gitleaks/gitleaks/releases",
	},
	"docker": {
		"windows": "install Docker Desktop and start it",
		"darwin":  "install Docker Desktop and start it",
		"linux":   "https://docs.docker.com/engine/install/",
	},
}

func hintFor(name string) string {
	perOS, ok := installHints[name]
	if !ok {
		return ""
	}
	// runtime.GOOS is fixed at compile time, which is why cross-compiled
	// binaries still print the right hint for the platform they were built for.
	key := runtime.GOOS
	if key != "windows" && key != "darwin" {
		key = "linux"
	}
	return perOS[key]
}

// checkBinary runs `name args...` and reports whether it worked.
func checkBinary(name string, args ...string) CheckResult {
	// Audited for semgrep's dangerous-exec-command: the only caller is the
	// probe loop below, whose name/args pairs are all string literals. Nothing
	// from the command line, the config file, or the environment reaches here.
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return CheckResult{Name: name, OK: false, Detail: "not found on PATH", Hint: hintFor(name)}
	}

	output := stdout.String()
	if strings.TrimSpace(output) == "" {
		output = stderr.String()
	}
	firstLine := strings.TrimSpace(strings.SplitN(output, "\n", 2)[0])
	if firstLine == "" {
		firstLine = "found"
	}
	return CheckResult{Name: name, OK: true, Detail: firstLine}
}

// scannerChecks probes every scanner concurrently and returns the results in a
// fixed order.
func scannerChecks(includeDocker bool) []CheckResult {
	probes := []struct {
		name string
		args []string
	}{
		{"semgrep", []string{"--version"}},
		{"trivy", []string{"--version"}},
		// gitleaks has no --version flag, only a `version` subcommand
		{"gitleaks", []string{"version"}},
	}
	if includeDocker {
		// `docker info` (not --version) is deliberate: it fails when the daemon
		// is installed but not running, which is the failure users actually hit.
		probes = append(probes, struct {
			name string
			args []string
		}{"docker", []string{"info"}})
	}

	results := make([]CheckResult, len(probes))
	var wg sync.WaitGroup
	for i, p := range probes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = checkBinary(p.name, p.args...)
		}()
	}
	wg.Wait()
	return results
}

// RunDoctor prints the full environment check.
//
// The TypeScript version checked the Node version first, because the CLI could
// not run without a new enough Node. This binary is statically linked and has
// no runtime to check, so that row is gone rather than ported.
func RunDoctor() {
	fmt.Println("secsuite doctor")
	fmt.Println()
	for _, c := range scannerChecks(true) {
		status := "MISSING"
		if c.OK {
			status = "ok"
		}
		fmt.Printf("  %-8s %-9s %s\n", status, c.Name, c.Detail)
		if !c.OK && c.Hint != "" {
			fmt.Printf("%sinstall: %s\n", strings.Repeat(" ", 11), c.Hint)
		}
	}
	fmt.Println()
	fmt.Println("Missing static scanners are skipped at scan time; docker is only needed for 'secsuite dast'.")
}

// RunStatus is what bare `secsuite` prints: live state, not help text.
func RunStatus(version string) {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	stack := DetectStack(cwd)

	detected := "no known manifests"
	if len(stack.Languages) > 0 {
		detected = strings.Join(stack.Languages, ", ")
	}

	scanners := make([]string, 0, 3)
	for _, c := range scannerChecks(false) {
		status := "MISSING"
		if c.OK {
			status = "ok"
		}
		scanners = append(scanners, c.Name+" "+status)
	}

	fmt.Printf("secsuite %s - stack-aware security scans\n", version)
	fmt.Printf("detected here: %s\n", detected)
	fmt.Printf("scanners: %s\n", strings.Join(scanners, ", "))
	fmt.Println()
	fmt.Println("  secsuite scan .          static scan (SAST + SCA + secrets + IaC)")
	fmt.Println("  secsuite dast <url>      dynamic scan of a running app (needs Docker)")
	fmt.Println("  secsuite baseline .      accept current findings, gate on new only")
	fmt.Println("  secsuite doctor          full environment check with install hints")
}
