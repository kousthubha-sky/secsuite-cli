package secsuite

import (
	"os"
	"strings"
	"sync"
	"testing"
)

// silenceStderr redirects os.Stderr for the duration of fn. The progress lines
// are noise in test output, and discarding them also proves nothing in here
// depends on stderr being a terminal.
func silenceStderr(t *testing.T, fn func()) {
	t.Helper()

	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("opening %s: %v", os.DevNull, err)
	}
	defer devNull.Close()

	original := os.Stderr
	os.Stderr = devNull
	defer func() { os.Stderr = original }()

	fn()
}

func TestBuildCommand(t *testing.T) {
	tests := []struct {
		name        string
		tool        ToolName
		stack       StackInfo
		wantCommand string
		wantArgs    []string
		wantErr     bool
	}{
		{
			name:        "semgrep writes sarif to the given path",
			tool:        ToolSemgrep,
			wantCommand: "semgrep",
			wantArgs:    []string{"scan", "--config", "auto", "--sarif", "--output", "/tmp/x.sarif", "/repo"},
		},
		{
			name:        "trivy runs all three scanner types",
			tool:        ToolTrivy,
			wantCommand: "trivy",
			wantArgs:    []string{"fs", "--scanners", "vuln,misconfig,secret", "--format", "sarif", "--output", "/tmp/x.sarif", "/repo"},
		},
		{
			name:        "gitleaks scans history in a git repo",
			tool:        ToolGitleaks,
			stack:       StackInfo{IsGit: true},
			wantCommand: "gitleaks",
			wantArgs:    []string{"detect", "--source", "/repo", "--report-format", "sarif", "--report-path", "/tmp/x.sarif"},
		},
		{
			// Without --no-git, gitleaks refuses to run outside a repository.
			name:        "gitleaks adds --no-git outside a repo",
			tool:        ToolGitleaks,
			stack:       StackInfo{IsGit: false},
			wantCommand: "gitleaks",
			wantArgs:    []string{"detect", "--source", "/repo", "--report-format", "sarif", "--report-path", "/tmp/x.sarif", "--no-git"},
		},
		{
			// zap is a DAST tool driven by dast.go, never the static runner.
			name:    "zap is not a static scanner",
			tool:    ToolZAP,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			command, args, err := buildCommand(tt.tool, "/repo", "/tmp/x.sarif", tt.stack)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if command != tt.wantCommand {
				t.Errorf("command = %q, want %q", command, tt.wantCommand)
			}
			if strings.Join(args, " ") != strings.Join(tt.wantArgs, " ") {
				t.Errorf("args = %v, want %v", args, tt.wantArgs)
			}
		})
	}
}

// Every scanner reports its own completion from its own goroutine, so the
// progress state is shared across threads. Node needed no lock for this;
// Go does, and `go test -race` is what proves it.
func TestProgressIsConcurrencySafe(t *testing.T) {
	tools := []ToolName{ToolSemgrep, ToolTrivy, ToolGitleaks}

	silenceStderr(t, func() {
		p := startProgress(tools)

		var wg sync.WaitGroup
		for _, tool := range tools {
			wg.Add(1)
			go func() {
				defer wg.Done()
				p.Done(tool, true, []string{"[secsuite] " + string(tool) + " log line"})
			}()
		}
		wg.Wait()
		p.Stop()

		if len(p.pending) != 0 {
			t.Errorf("pending = %v, want empty after every tool reported", p.pending)
		}
	})
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		name string
		in   string
		n    int
		want string
	}{
		{"shorter than the limit", "abc", 10, "abc"},
		{"exactly the limit", "abcde", 5, "abcde"},
		{"longer than the limit", "abcdefgh", 3, "abc"},
		// Counted in runes: cutting bytes here would split a character and
		// produce invalid UTF-8 in the error message.
		{"multibyte characters", "héllo wörld", 5, "héllo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := truncate(tt.in, tt.n); got != tt.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.in, tt.n, got, tt.want)
			}
		})
	}
}

func TestTruncateTitle(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"first line only", "summary line\nmore detail\nand more", "summary line"},
		{"trimmed", "  padded  \nrest", "padded"},
		{"empty", "", ""},
		{
			name: "long titles are cut with an ellipsis",
			in:   strings.Repeat("a", 150),
			want: strings.Repeat("a", 97) + "...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TruncateTitle(tt.in); got != tt.want {
				t.Errorf("TruncateTitle() = %q, want %q", got, tt.want)
			}
		})
	}
}
