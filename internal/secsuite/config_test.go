package secsuite

import (
	"os"
	"path/filepath"
	"testing"
)

// The default ignore list is the highest-risk part of the port: every "dir/"
// pattern is rewritten to "**/dir/**" and relies on `**` matching ZERO path
// segments. Node's path.matchesGlob did; if doublestar disagreed, the ignores
// would silently stop matching and every scan would fill with node_modules
// noise rather than failing loudly. These cases are what proves it.
func TestIsIgnoredDefaults(t *testing.T) {
	paths := DefaultConfig().IgnorePaths

	tests := []struct {
		name string
		file string
		want bool
	}{
		// Real-world case: scan started one directory above the repo, so every
		// path carries a "k-p/" prefix - ignores must still match.
		{"build output one level down", "k-p/.next/static/chunks/app/page.js", true},
		{"nested build manifest", "k-p/.next/server/server-reference-manifest.json", true},
		{"deps one level down", "k-p/node_modules/lodash/index.js", true},
		// Root-level (no prefix) still matches - `**/` matches zero segments.
		{"build output at root", ".next/static/chunks/main.js", true},
		{"deps at root", "node_modules/x/y.js", true},
		{"dist at root", "dist/bundle.js", true},

		// Rust/Maven, Python, Gradle, .NET, iOS, Elixir, Flutter, Terraform
		{"cargo target", "myapp/target/debug/build/serde-abc/output", true},
		{"pycache", "api/__pycache__/views.cpython-312.pyc", true},
		{"venv", "api/venv/lib/python3.12/site-packages/x.py", true},
		{"gradle cache", "android/.gradle/caches/x.bin", true},
		{"dotnet obj", "Service/obj/Debug/net8.0/Service.dll", true},
		{"cocoapods", "ios/Pods/Alamofire/Source/Session.swift", true},
		{"elixir build", "phoenix/_build/dev/lib/app/ebin/app.beam", true},
		{"elixir deps", "phoenix/deps/ecto/lib/ecto.ex", true},
		{"flutter tool", "flutter/.dart_tool/package_config.json", true},
		{"terraform providers", "infra/.terraform/providers/aws/provider.exe", true},

		{"app source", "src/app/page.tsx", false},
		{"component", "components/JsonLd.jsx", false},
		{"lockfile", "package-lock.json", false},
		{"prefixed lockfile", "k-p/package-lock.json", false},
		// lockfiles are how trivy finds dep CVEs - must never be ignored
		{"cargo lock", "Cargo.lock", false},
		{"go mod", "go.mod", false},
		{"poetry lock", "poetry.lock", false},
		// "deps"/"obj" only match as whole path segments, not substrings
		{"deps as substring", "src/deps_parser.ts", false},
		{"obj as substring", "src/object_store.rs", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsIgnored(tt.file, paths); got != tt.want {
				t.Errorf("IsIgnored(%q) = %v, want %v", tt.file, got, tt.want)
			}
		})
	}
}

// Windows produces backslash-separated paths but every ignore pattern is
// written with forward slashes, so IsIgnored has to normalize first.
func TestIsIgnoredNormalizesSeparators(t *testing.T) {
	paths := DefaultConfig().IgnorePaths
	if !IsIgnored(filepath.Join("k-p", "node_modules", "lodash", "index.js"), paths) {
		t.Error("a path built with the OS separator should still match")
	}
}

func TestDefaultConfigIsNotShared(t *testing.T) {
	first := DefaultConfig()
	first.IgnorePaths[0] = "mutated/"

	if DefaultConfig().IgnorePaths[0] == "mutated/" {
		t.Error("DefaultConfig handed out a slice backed by shared state")
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir() // removed automatically when the test ends

	t.Run("missing implicit config falls back to defaults", func(t *testing.T) {
		config, err := LoadConfig("", dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if config.SeverityThreshold != SeverityMedium {
			t.Errorf("threshold = %q, want medium", config.SeverityThreshold)
		}
	})

	t.Run("missing explicit config is an error", func(t *testing.T) {
		if _, err := LoadConfig(filepath.Join(dir, "nope.yaml"), dir); err == nil {
			t.Error("an explicit --config that does not exist must fail loudly")
		}
	})

	t.Run("file values override defaults", func(t *testing.T) {
		path := filepath.Join(dir, "custom.yaml")
		write(t, path, "version: 1\nseverity_threshold: high\nignore:\n  paths:\n    - only/\n")

		config, err := LoadConfig(path, dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if config.SeverityThreshold != SeverityHigh {
			t.Errorf("threshold = %q, want high", config.SeverityThreshold)
		}
		if len(config.IgnorePaths) != 1 || config.IgnorePaths[0] != "only/" {
			t.Errorf("ignore paths = %v, want [only/]", config.IgnorePaths)
		}
	})

	t.Run("omitted keys keep their defaults", func(t *testing.T) {
		path := filepath.Join(dir, "partial.yaml")
		write(t, path, "version: 1\nscan:\n  static: true\n")

		config, err := LoadConfig(path, dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if config.SeverityThreshold != SeverityMedium {
			t.Errorf("threshold = %q, want medium", config.SeverityThreshold)
		}
		if len(config.IgnorePaths) != len(defaultIgnorePaths) {
			t.Errorf("ignore paths = %d entries, want the %d defaults", len(config.IgnorePaths), len(defaultIgnorePaths))
		}
	})

	// A typo here used to survive all the way to a scan that reported nothing,
	// which reads exactly like a pass.
	t.Run("a bogus severity_threshold fails loudly", func(t *testing.T) {
		path := filepath.Join(dir, "bogus.yaml")
		write(t, path, "severity_threshold: hgih\n")

		if _, err := LoadConfig(path, dir); err == nil {
			t.Error("an unknown severity_threshold must be rejected")
		}
	})
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}
