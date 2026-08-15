package secsuite

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// SarifRule is the subset of a SARIF rule definition the adapters use.
//
// Every field is a plain value, not a pointer. TypeScript modelled "no rule
// matched this result" with an optional object and `?.` everywhere; here a
// missing rule is the zero value, whose empty strings hit exactly the same
// fallbacks. That trades one impossible nil dereference for nothing.
type SarifRule struct {
	ID               string
	ShortDescription string
	FullDescription  string
	HelpURI          string
	Tags             []string
	DefaultLevel     string
}

// SarifResultEntry is one SARIF result, flattened into the fields adapters need.
type SarifResultEntry struct {
	RuleID    string
	Level     string
	Message   string
	File      string // posix path, relative to the scan target
	StartLine int    // 0 when the scanner reported no line
	EndLine   int
	Rule      SarifRule
	Raw       json.RawMessage
}

// The on-disk SARIF shapes. These exist only to be unmarshalled into, so they
// are unexported and use anonymous nested structs that mirror the JSON exactly.
type sarifText struct {
	Text string `json:"text"`
}

type sarifDoc struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Rules []struct {
					ID               string    `json:"id"`
					ShortDescription sarifText `json:"shortDescription"`
					FullDescription  sarifText `json:"fullDescription"`
					HelpURI          string    `json:"helpUri"`
					Properties       struct {
						Tags []string `json:"tags"`
					} `json:"properties"`
					DefaultConfiguration struct {
						Level string `json:"level"`
					} `json:"defaultConfiguration"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		// Kept as raw JSON so each result can be unmarshalled into the struct
		// below AND carried through to --raw output byte-for-byte, without
		// re-encoding it.
		Results []json.RawMessage `json:"results"`
	} `json:"runs"`
}

type sarifResult struct {
	RuleID    string    `json:"ruleId"`
	Level     string    `json:"level"`
	Message   sarifText `json:"message"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine int `json:"startLine"`
				EndLine   int `json:"endLine"`
			} `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
	// SARIF 2.1.0 keeps suppressed results in the file and flags them here
	// instead of omitting them. Semgrep emits {"kind":"inSource"} for every
	// `// nosemgrep` comment, and Trivy does the same for its own ignore file,
	// so without this secsuite re-reports findings the author already reviewed
	// and dismissed in code.
	Suppressions []struct {
		Status string `json:"status"`
	} `json:"suppressions"`
}

// isSuppressed reports whether the scanner marked this result as dismissed.
//
// Per SARIF 2.1.0 a missing status means "accepted". "underReview" and
// "rejected" both leave the finding live, so only an accepted suppression
// hides it.
func (r sarifResult) isSuppressed() bool {
	for _, s := range r.Suppressions {
		if s.Status == "" || s.Status == "accepted" {
			return true
		}
	}
	return false
}

// ParseSarifResults reads a SARIF file and flattens every result in it.
func ParseSarifResults(sarifPath, targetDir string) ([]SarifResultEntry, error) {
	data, err := os.ReadFile(sarifPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", sarifPath, err)
	}

	var doc sarifDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", sarifPath, err)
	}

	var entries []SarifResultEntry
	for _, run := range doc.Runs {
		ruleByID := make(map[string]SarifRule, len(run.Tool.Driver.Rules))
		for _, r := range run.Tool.Driver.Rules {
			ruleByID[r.ID] = SarifRule{
				ID:               r.ID,
				ShortDescription: r.ShortDescription.Text,
				FullDescription:  r.FullDescription.Text,
				HelpURI:          r.HelpURI,
				Tags:             r.Properties.Tags,
				DefaultLevel:     r.DefaultConfiguration.Level,
			}
		}

		for _, rawResult := range run.Results {
			var result sarifResult
			if err := json.Unmarshal(rawResult, &result); err != nil {
				continue // one malformed result must not sink the whole file
			}

			// A `// nosemgrep` in the scanned code is the author saying "I
			// looked at this". Honor it rather than making them maintain a
			// second suppression list in the baseline.
			if result.isSuppressed() {
				continue
			}

			// Indexing Locations[0] without this length check is the single
			// easiest way to panic in this port: TypeScript's `?.[0]` returned
			// undefined, Go's [0] on an empty slice crashes the process.
			if len(result.Locations) == 0 {
				continue
			}
			loc := result.Locations[0].PhysicalLocation
			if loc.ArtifactLocation.URI == "" {
				continue
			}

			rule := ruleByID[result.RuleID] // absent -> zero value, see SarifRule

			// Per the SARIF spec, a result with no `level` inherits the rule's
			// `defaultConfiguration.level` - semgrep (and others) rely on this
			// instead of repeating the level on every result.
			level := result.Level
			if level == "" {
				level = rule.DefaultLevel
			}

			ruleID := result.RuleID
			if ruleID == "" {
				ruleID = "unknown"
			}

			entries = append(entries, SarifResultEntry{
				RuleID:    ruleID,
				Level:     level,
				Message:   result.Message.Text,
				File:      normalizeRelPath(loc.ArtifactLocation.URI, targetDir),
				StartLine: loc.Region.StartLine,
				EndLine:   loc.Region.EndLine,
				Rule:      rule,
				Raw:       rawResult,
			})
		}
	}

	return entries, nil
}

// windowsDriveURI matches the leading slash a file:// URI puts in front of a
// Windows drive letter, as in file:///C:/repo/app.js -> /C:/repo/app.js.
var windowsDriveURI = regexp.MustCompile(`^/[A-Za-z]:`)

// normalizeRelPath turns a SARIF artifact URI into a forward-slash path
// relative to targetDir.
func normalizeRelPath(uri, targetDir string) string {
	trimmed := strings.TrimPrefix(uri, "file://")
	decoded, err := url.PathUnescape(trimmed)
	if err != nil {
		decoded = trimmed // not percent-encoded; use it as-is
	}
	// Node treated "/C:/repo/app.js" as absolute on Windows. Go does not: an
	// absolute Windows path needs the volume first, so the leading slash has to
	// go or filepath.Rel resolves against the wrong root.
	decoded = windowsDriveURI.ReplaceAllStringFunc(decoded, func(s string) string {
		return s[1:]
	})

	abs := decoded
	if !filepath.IsAbs(decoded) {
		abs = filepath.Join(targetDir, decoded)
	}

	rel, err := filepath.Rel(targetDir, abs)
	if err != nil {
		// Different Windows volumes have no relative path between them; the
		// absolute path is still more useful than nothing.
		return filepath.ToSlash(abs)
	}
	return filepath.ToSlash(rel)
}

// MakeFindingID derives a finding's stable identity. Baselines match on this,
// so the inputs and their order must not change casually.
func MakeFindingID(tool, ruleID, file string, startLine int) string {
	line := ""
	if startLine != 0 {
		line = strconv.Itoa(startLine)
	}
	sum := sha256.Sum256([]byte(tool + "|" + ruleID + "|" + file + "|" + line))
	return hex.EncodeToString(sum[:])[:16]
}

// titleMaxLen is the longest a finding title may be before truncation. Go has
// no default parameter values, and nothing ever passed a different limit, so
// the TypeScript `max = 100` argument becomes a constant.
const titleMaxLen = 100

// TruncateTitle reduces text to its first line, capped at titleMaxLen.
func TruncateTitle(text string) string {
	firstLine := strings.TrimSpace(strings.SplitN(text, "\n", 2)[0])
	// Counted in runes, not bytes: len() on a string counts bytes, so a title
	// with any non-ASCII character would be cut short - or cut mid-character,
	// producing invalid UTF-8.
	runes := []rune(firstLine)
	if len(runes) <= titleMaxLen {
		return firstLine
	}
	return strings.TrimRight(string(runes[:titleMaxLen-3]), " \t") + "..."
}
