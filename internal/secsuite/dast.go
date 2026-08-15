package secsuite

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// zapImage is the official OWASP ZAP image (the old owasp/zap2docker-stable is
// deprecated).
const zapImage = "zaproxy/zap-stable"

// DastRunResult records what happened when ZAP was invoked.
type DastRunResult struct {
	Ran        bool
	ReportPath string
	Error      string
}

func dockerAvailable() bool {
	return exec.Command("docker", "info").Run() == nil
}

// RunZapScan drives ZAP headless from its Docker image, writing its report into
// outDir (which the caller owns and cleans up).
//
// baseline = spider + passive rules (safe, non-attacking). full = active scan
// that sends real attack payloads, so it must only ever be pointed at a target
// you are authorized to test.
func RunZapScan(target, outDir string, full bool) DastRunResult {
	if !dockerAvailable() {
		fmt.Fprintln(os.Stderr, "[secsuite] docker not available - the DAST lane needs Docker running. Skipping.")
		return DastRunResult{Ran: false, Error: "docker not available"}
	}

	const reportName = "report.json"
	script := "zap-baseline.py"
	if full {
		script = "zap-full-scan.py"
		fmt.Fprintf(os.Stderr, "[secsuite] running ZAP ACTIVE scan against %s - only do this on targets you are authorized to test.\n", target)
	}

	// Mount the host out-dir at ZAP's working dir so the report lands on the
	// host. Docker's `-v` splits on ':', and a Windows path (C:\Users\...) has
	// both a drive colon and backslashes; Docker Desktop accepts a
	// forward-slashed path (C:/Users/...), so normalize separators. Omit the
	// ":rw" mode (rw is the default) to keep one fewer colon in the argument.
	mountSrc := filepath.ToSlash(outDir)
	args := []string{
		"run", "--rm",
		"-v", mountSrc + ":/zap/wrk",
		"-t", zapImage,
		script, "-t", target, "-J", reportName,
	}

	// stderr, not stdout: stdout is reserved for the report (or `--json -`).
	fmt.Fprintf(os.Stderr, "[secsuite] starting ZAP (%s) against %s - first run pulls the image, this can take a few minutes.\n", script, target)

	// Elapsed ticker (TTY only) so a minutes-long ZAP run never looks stuck.
	started := time.Now()
	stopTicker := startElapsedTicker("[secsuite] ZAP running...", started)

	cmd := exec.Command("docker", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()

	stopTicker()
	fmt.Fprintf(os.Stderr, "[secsuite] ZAP finished (%.1fs)\n", time.Since(started).Seconds())

	exitCode := -1
	if err == nil {
		exitCode = 0
	} else {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
	}

	// ZAP exits nonzero when it finds issues (1) or fails (2/3); trust the
	// report file over the exit code, same as the static scanners.
	reportPath := filepath.Join(outDir, reportName)
	if _, statErr := os.Stat(reportPath); statErr == nil {
		return DastRunResult{Ran: true, ReportPath: reportPath}
	}

	fmt.Fprintf(os.Stderr, "[secsuite] ZAP produced no report (exit %d). %s\n", exitCode, truncate(stderr.String(), 300))
	return DastRunResult{Ran: false, Error: fmt.Sprintf("zap execution error (exit %d)", exitCode)}
}

// startElapsedTicker prints a one-line elapsed counter to stderr once a second
// and returns the function that stops it. On a non-TTY it does nothing and the
// returned function is a no-op, which keeps CI logs clean.
func startElapsedTicker(label string, started time.Time) func() {
	if !isTerminal(os.Stderr) {
		return func() {}
	}

	stop := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				fmt.Fprintf(os.Stderr, "\r%s %ds", label, int(time.Since(started).Seconds()))
			}
		}
	}()

	return func() {
		close(stop)
		<-stopped // wait for the goroutine to stop writing before clearing
		fmt.Fprint(os.Stderr, "\r\x1b[2K")
	}
}

// IsHTTPURL reports whether target is an http(s) URL, the only thing the DAST
// lane can point at.
func IsHTTPURL(target string) bool {
	lower := strings.ToLower(target)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}
