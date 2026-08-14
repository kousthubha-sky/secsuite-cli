package secsuite

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ToolRunResult records what happened when one scanner was invoked.
type ToolRunResult struct {
	Tool      ToolName
	Ran       bool
	SarifPath string
	Error     string
}

// isAvailable reports whether bin can be executed.
func isAvailable(bin string) bool {
	// gitleaks has no --version flag, only a `version` subcommand - probing
	// with --version made every scan silently skip the gitleaks lane.
	arg := "--version"
	if bin == string(ToolGitleaks) {
		arg = "version"
	}
	// A nil error means the process ran and exited 0. Both "not on PATH" and
	// "exited nonzero" arrive as an error, which is all this needs to know.
	return exec.Command(bin, arg).Run() == nil
}

func buildCommand(tool ToolName, targetDir, sarifPath string, stack StackInfo) (string, []string, error) {
	switch tool {
	case ToolSemgrep:
		return "semgrep", []string{"scan", "--config", "auto", "--sarif", "--output", sarifPath, targetDir}, nil
	case ToolTrivy:
		return "trivy", []string{"fs", "--scanners", "vuln,misconfig,secret", "--format", "sarif", "--output", sarifPath, targetDir}, nil
	case ToolGitleaks:
		args := []string{"detect", "--source", targetDir, "--report-format", "sarif", "--report-path", sarifPath}
		if !stack.IsGit {
			args = append(args, "--no-git")
		}
		return "gitleaks", args, nil
	default:
		// zap is a DAST tool driven by dast.go, never the static runner.
		return "", nil, fmt.Errorf("buildCommand: %s is not a static scanner", tool)
	}
}

// isTerminal reports whether f is attached to a terminal rather than a pipe or
// a file. The standard library has no isatty, but a character device is what a
// console is on both Unix and Windows.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// progress writes live scan progress to stderr so a long scan never looks
// stuck. Everything goes to stderr (stdout is reserved for the report). On a
// TTY a single line ticks with elapsed time and what is still running; in CI it
// degrades to plain start/finish lines.
type progress struct {
	// Every field below is touched by the scanner goroutines AND by the ticker
	// goroutine at the same time. The TypeScript version needed no lock because
	// Node runs one thread; here, unsynchronized access is a data race that
	// `go test -race` will fail on.
	mu      sync.Mutex
	order   []ToolName
	pending map[ToolName]bool

	started time.Time
	isTTY   bool
	stop    chan struct{}
	done    sync.WaitGroup
}

func startProgress(tools []ToolName) *progress {
	p := &progress{
		order:   tools,
		pending: make(map[ToolName]bool, len(tools)),
		started: time.Now(),
		isTTY:   isTerminal(os.Stderr),
		stop:    make(chan struct{}),
	}
	for _, t := range tools {
		p.pending[t] = true
	}

	names := make([]string, len(tools))
	for i, t := range tools {
		names[i] = string(t)
	}
	fmt.Fprintf(os.Stderr, "[secsuite] running: %s\n", strings.Join(names, ", "))

	if !p.isTTY {
		return p
	}

	p.done.Add(1)
	go func() {
		defer p.done.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			// select blocks until one of its cases can proceed: either the
			// ticker fires, or Stop closes the channel. A closed channel always
			// receives immediately, which is the standard way to tell a
			// goroutine to exit.
			select {
			case <-p.stop:
				return
			case <-ticker.C:
				p.mu.Lock()
				fmt.Fprintf(os.Stderr, "\r[secsuite] scanning... %ds (waiting on: %s)",
					int(time.Since(p.started).Seconds()), strings.Join(p.pendingNames(), ", "))
				p.mu.Unlock()
			}
		}
	}()
	return p
}

// pendingNames lists the still-running tools in their original order. Callers
// must already hold p.mu.
func (p *progress) pendingNames() []string {
	var names []string
	for _, t := range p.order {
		if p.pending[t] {
			names = append(names, string(t))
		}
	}
	return names
}

func (p *progress) clearLine() {
	if p.isTTY {
		fmt.Fprint(os.Stderr, "\r\x1b[2K")
	}
}

// Done marks one tool finished and flushes any log lines it buffered, under the
// lock, so concurrent output never interleaves mid-message.
func (p *progress) Done(tool ToolName, ran bool, log []string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	delete(p.pending, tool)
	p.clearLine()
	verb := "skipped"
	if ran {
		verb = "finished"
	}
	fmt.Fprintf(os.Stderr, "[secsuite] %s %s (%.1fs)\n", tool, verb, time.Since(p.started).Seconds())
	for _, line := range log {
		fmt.Fprintln(os.Stderr, line)
	}
}

func (p *progress) Stop() {
	if p.isTTY {
		close(p.stop)
		p.done.Wait()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clearLine()
}

// RunScanners executes every scanner against targetDir and returns one result
// per scanner, in the order given. SARIF output is written into tmpDir, which
// the caller owns and must clean up once the adapters have read from it - the
// TypeScript version created the directory here and never deleted it, leaking
// one temp directory per scan.
func RunScanners(scanners []ToolName, targetDir, tmpDir string, stack StackInfo) []ToolRunResult {
	progress := startProgress(scanners)
	defer progress.Stop()

	// Scanners are independent processes, so run them concurrently. Each
	// goroutine writes to its own slice index, which is why no mutex is needed
	// for results: distinct elements of a slice are distinct memory. The
	// WaitGroup is what makes those writes visible to this goroutine afterwards.
	results := make([]ToolRunResult, len(scanners))
	var wg sync.WaitGroup
	for i, tool := range scanners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var log []string
			results[i] = runOne(tool, targetDir, stack, tmpDir, &log)
			progress.Done(tool, results[i].Ran, log)
		}()
	}
	wg.Wait()

	return results
}

func runOne(tool ToolName, targetDir string, stack StackInfo, tmpDir string, log *[]string) ToolRunResult {
	if !isAvailable(string(tool)) {
		*log = append(*log, fmt.Sprintf("[secsuite] %s not found on PATH, skipping.", tool))
		return ToolRunResult{Tool: tool, Ran: false, Error: "not found on PATH"}
	}

	sarifPath := filepath.Join(tmpDir, string(tool)+".sarif")
	command, args, err := buildCommand(tool, targetDir, sarifPath, stack)
	if err != nil {
		*log = append(*log, "[secsuite] "+err.Error())
		return ToolRunResult{Tool: tool, Ran: false, Error: err.Error()}
	}

	cmd := exec.Command(command, args...)
	cmd.Dir = targetDir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if tool == ToolSemgrep {
		// Semgrep is a Python tool that writes SARIF using the OS default
		// codepage unless told otherwise; on Windows that's cp1252, which
		// crashes on non-Latin-1 characters that show up in community rule
		// metadata (e.g. emoji). Force UTF-8 so the SARIF write can't fail.
		cmd.Env = append(os.Environ(), "PYTHONUTF8=1")
	}

	exitCode := -1
	if err := cmd.Run(); err == nil {
		exitCode = 0
	} else {
		// errors.As unwraps the error chain looking for an *exec.ExitError,
		// which is the only error type that carries a real exit code. Anything
		// else (the binary vanished mid-run, say) keeps -1.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
	}

	// These tools use a nonzero exit code to mean "findings were found", not
	// "the tool crashed" - trust the SARIF file over the exit code.
	if data, err := os.ReadFile(sarifPath); err == nil && json.Valid(data) {
		return ToolRunResult{Tool: tool, Ran: true, SarifPath: sarifPath}
	}

	*log = append(*log, fmt.Sprintf("[secsuite] %s failed to run (exit %d). %s",
		tool, exitCode, truncate(stderr.String(), 300)))
	return ToolRunResult{Tool: tool, Ran: false, Error: fmt.Sprintf("execution error (exit %d)", exitCode)}
}

// truncate cuts s to at most n runes.
func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n])
}
