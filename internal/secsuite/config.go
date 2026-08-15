package secsuite

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"
)

// ConfigFilename is the config file looked for in the scan target when
// --config is not given.
const ConfigFilename = "secsuite.yaml"

// Config is the resolved configuration for one run.
type Config struct {
	SeverityThreshold Severity
	IgnorePaths       []string
}

// defaultIgnorePaths are the paths ignored when no config file says otherwise.
var defaultIgnorePaths = []string{
	"tests/",
	"**/migrations/**",
	// dependency dirs (in-repo installs; deps themselves are CVE-checked
	// via lockfiles regardless of these ignores)
	"node_modules/",
	".venv/",
	"venv/",
	"vendor/",
	"Pods/",
	"deps/",
	// build output - generated files trip SAST/secret rules constantly
	// (e.g. webpack eval() shims, Next.js action hashes) and their real
	// source is scanned anyway. Covers JS, Rust/Maven (target/), .NET
	// (obj/), Elixir (_build/), Flutter (.dart_tool/), Gradle, Terraform.
	".next/",
	".nuxt/",
	"dist/",
	"build/",
	"out/",
	"target/",
	"coverage/",
	"__pycache__/",
	".gradle/",
	"obj/",
	"_build/",
	".dart_tool/",
	".terraform/",
}

// DefaultConfig returns the configuration used when no config file is present.
//
// This is a function, not the exported `DEFAULT_CONFIG` constant the TypeScript
// version had. A Go package-level var holding a slice is shared mutable state:
// any caller could append to it, or overwrite an element, and every later call
// would see the damage. Handing out a fresh copy each time costs nothing here
// and removes the whole class of bug.
func DefaultConfig() Config {
	return Config{
		SeverityThreshold: SeverityMedium,
		IgnorePaths:       append([]string(nil), defaultIgnorePaths...),
	}
}

// rawConfig is the on-disk YAML shape, which uses snake_case keys and is
// entirely optional. It is deliberately separate from Config: the file format
// is a contract with users, while Config is what the rest of the code wants.
type rawConfig struct {
	Version int `yaml:"version"`
	Scan    struct {
		Static bool `yaml:"static"`
	} `yaml:"scan"`
	SeverityThreshold Severity `yaml:"severity_threshold"`
	Ignore            struct {
		Paths []string `yaml:"paths"`
	} `yaml:"ignore"`
}

// LoadConfig reads configPath, or <targetDir>/secsuite.yaml when configPath is
// empty. Any field the file omits keeps its default.
func LoadConfig(configPath, targetDir string) (Config, error) {
	resolvedPath := configPath
	if resolvedPath == "" {
		resolvedPath = filepath.Join(targetDir, ConfigFilename)
	}

	data, err := os.ReadFile(resolvedPath)
	if err != nil {
		// An explicit --config path that doesn't exist is a user error; the
		// implicit default location is optional and silently falls back.
		if os.IsNotExist(err) && configPath == "" {
			return DefaultConfig(), nil
		}
		if os.IsNotExist(err) {
			return Config{}, fmt.Errorf("config file not found: %s", configPath)
		}
		return Config{}, fmt.Errorf("reading config %s: %w", resolvedPath, err)
	}

	var raw rawConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return Config{}, fmt.Errorf("parsing config %s: %w", resolvedPath, err)
	}

	// An empty or absent key unmarshals to the zero value ("" or nil), which is
	// how "not set" is detected - Go has no undefined to compare against.
	config := DefaultConfig()
	if raw.SeverityThreshold != "" {
		// The TypeScript version trusted this field. A typo there survived as
		// far as SEVERITY_ORDER.indexOf() returning -1, which silently filtered
		// out every finding - a scan that reports nothing looks like a pass.
		severity, err := ParseSeverity(string(raw.SeverityThreshold))
		if err != nil {
			return Config{}, fmt.Errorf("%s: %w", resolvedPath, err)
		}
		config.SeverityThreshold = severity
	}
	if raw.Ignore.Paths != nil {
		config.IgnorePaths = raw.Ignore.Paths
	}
	return config, nil
}

// IsIgnored reports whether relFile matches any ignore pattern.
func IsIgnored(relFile string, ignorePaths []string) bool {
	normalized := filepath.ToSlash(relFile)
	for _, pattern := range ignorePaths {
		// "dir/" means "everything under any dir/ at ANY depth" - a scan started
		// one level above the repo (paths like "k-p/node_modules/x") must still
		// match. `**/` also matches zero segments, so root-level dirs match too.
		glob := pattern
		if strings.HasSuffix(pattern, "/") {
			glob = "**/" + pattern + "**"
		}
		// doublestar replaces Node's path.matchesGlob. The standard library's
		// filepath.Match has no `**` at all, and every pattern above depends on
		// it. Match only errors on a malformed pattern, which would be a bug in
		// the pattern list, not in the file being tested - so a bad pattern
		// matches nothing rather than ignoring the whole scan.
		if ok, err := doublestar.Match(glob, normalized); err == nil && ok {
			return true
		}
	}
	return false
}
