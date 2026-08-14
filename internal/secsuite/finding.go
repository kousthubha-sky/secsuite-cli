// Package secsuite implements the scanning pipeline: stack detection, scanner
// execution, result normalization, deduplication, and reporting.
package secsuite

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Severity is a normalized severity level. Each adapter maps its scanner's own
// vocabulary onto these five values, so nothing past the adapter boundary has
// to know that trivy says "CRITICAL" and semgrep says "ERROR".
//
// Note what Go does not give you here: TypeScript's `"critical" | "high" | ...`
// was checked by the compiler, but Severity("banana") compiles fine. Validation
// moves from compile time to runtime, which is why Rank below has to handle a
// value that is not in the table.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// allSeverities lists every severity, most severe first. The report and the
// counts line range over this slice rather than over severityOrder, because a
// Go map has no iteration order at all - the runtime deliberately randomizes
// it, so ranging a map would shuffle the report sections on every run.
var allSeverities = []Severity{
	SeverityCritical,
	SeverityHigh,
	SeverityMedium,
	SeverityLow,
	SeverityInfo,
}

// severityOrder ranks each severity, most severe first. Derived from
// allSeverities so the two can never drift apart. Unexported (lowercase) so no
// other package can reach in and mutate it.
//
// The `func() T { ... }()` form is an immediately-invoked function used to
// build a package-level value that needs more than one expression.
var severityOrder = func() map[Severity]int {
	order := make(map[Severity]int, len(allSeverities))
	for rank, severity := range allSeverities {
		order[severity] = rank
	}
	return order
}()

// Rank returns the sort position of s, where lower means more severe.
//
// An unrecognized severity sorts last. The TypeScript version used
// SEVERITY_ORDER.indexOf(s), which returns -1 for an unknown value - that would
// have outranked "critical" in every comparison. The union type made it
// unreachable there; here it is reachable, so it is handled.
//
// The `value, ok := m[key]` form is how Go distinguishes "missing" from
// "present but zero". A plain m[key] returns 0 for both, which would silently
// rank an unknown severity as critical.
func (s Severity) Rank() int {
	if rank, ok := severityOrder[s]; ok {
		return rank
	}
	return len(severityOrder)
}

// ParseSeverity validates a severity string coming from a --severity flag or a
// config file. This is the runtime check that replaces TypeScript's union type:
// the compiler cannot reject Severity("banana") here, so something has to.
func ParseSeverity(s string) (Severity, error) {
	severity := Severity(s)
	if _, ok := severityOrder[severity]; !ok {
		names := make([]string, len(allSeverities))
		for i, known := range allSeverities {
			names[i] = string(known)
		}
		return "", fmt.Errorf("invalid severity %q, expected one of %s", s, strings.Join(names, ", "))
	}
	return severity, nil
}

// Category is what kind of problem a finding represents, independent of which
// tool found it. Dedupe keys on this, so two tools reporting the same secret on
// the same line collapse into one finding.
type Category string

const (
	CategorySAST      Category = "sast"
	CategorySCA       Category = "sca"
	CategorySecret    Category = "secret"
	CategoryIaC       Category = "iac"
	CategoryMisconfig Category = "misconfig"
	CategoryDAST      Category = "dast"
)

// ToolName is a scanner secsuite knows how to drive.
type ToolName string

const (
	ToolSemgrep  ToolName = "semgrep"
	ToolTrivy    ToolName = "trivy"
	ToolGitleaks ToolName = "gitleaks"
	ToolZAP      ToolName = "zap"
)

// Location is where a finding was reported.
//
// StartLine and EndLine are 0 when the scanner reported no line. SARIF lines are
// 1-indexed, so 0 is an unambiguous "absent" and saves carrying a *int through
// the whole pipeline just to model optionality.
// ponytail: 0-as-absent, switch to *int only if a scanner ever emits line 0.
type Location struct {
	File      string `json:"file"`
	StartLine int    `json:"startLine,omitempty"`
	EndLine   int    `json:"endLine,omitempty"`
}

// Finding is one normalized result. Adapters produce these from raw scanner
// output; everything downstream - filtering, dedupe, reporting, SARIF export -
// works only with this shape.
type Finding struct {
	ID          string   `json:"id"`
	Tool        ToolName `json:"tool"`
	Category    Category `json:"category"`
	RuleID      string   `json:"ruleId"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Location    Location `json:"location"`
	Remediation string   `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`

	// Sources lists every tool that reported this finding. It starts with one
	// entry and grows when dedupe merges a genuine cross-tool duplicate.
	Sources []string `json:"sources"`

	// Raw is the scanner's original payload, carried through to --raw output
	// without ever being parsed. json.RawMessage is the idiomatic stand-in for
	// TypeScript's `unknown`: underneath it is just []byte, so holding it costs
	// nothing and it re-marshals byte-for-byte.
	Raw json.RawMessage `json:"raw,omitempty"`
}
