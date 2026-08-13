// Package secsuite implements the scanning pipeline: stack detection, scanner
// execution, result normalization, deduplication, and reporting.
package secsuite

import "encoding/json"

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

// severityOrder ranks each severity, most severe first. Unexported (lowercase)
// so no other package can reach in and mutate it.
var severityOrder = map[Severity]int{
	SeverityCritical: 0,
	SeverityHigh:     1,
	SeverityMedium:   2,
	SeverityLow:      3,
	SeverityInfo:     4,
}

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
