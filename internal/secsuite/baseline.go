package secsuite

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// BaselineFilename is the file `secsuite baseline` writes and `secsuite scan`
// reads back.
const BaselineFilename = ".secsuite-baseline.json"

// baselineEntry matches on id only; the other fields exist so a human reviewing
// the committed file can see exactly what was accepted.
type baselineEntry struct {
	ID        string `json:"id"`
	Tool      string `json:"tool"`
	RuleID    string `json:"ruleId"`
	File      string `json:"file"`
	StartLine int    `json:"startLine,omitempty"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
}

type baselineFile struct {
	Version  int             `json:"version"`
	Created  string          `json:"created"`
	Findings []baselineEntry `json:"findings"`
}

// WriteBaseline records every finding as accepted.
func WriteBaseline(filePath string, findings []Finding) error {
	doc := baselineFile{
		Version:  1,
		Created:  time.Now().UTC().Format(time.RFC3339),
		Findings: make([]baselineEntry, 0, len(findings)),
	}
	for _, f := range findings {
		doc.Findings = append(doc.Findings, baselineEntry{
			ID:        f.ID,
			Tool:      string(f.Tool),
			RuleID:    f.RuleID,
			File:      f.Location.File,
			StartLine: f.Location.StartLine,
			Severity:  string(f.Severity),
			Title:     f.Title,
		})
	}

	payload, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding baseline: %w", err)
	}
	if err := os.WriteFile(filePath, payload, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", filePath, err)
	}
	return nil
}

// LoadBaselineIDs reads the accepted finding ids from filePath.
//
// A nil result means there is no usable baseline; an empty non-nil map means
// the baseline exists but accepted nothing. Go distinguishes the two, which is
// what stands in for TypeScript's `Set | undefined` - and the caller needs the
// difference to decide whether to suggest creating one.
//
// A corrupt file warns and reads as absent, so a broken baseline can only ever
// surface MORE findings, never hide them.
func LoadBaselineIDs(filePath string) map[string]bool {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "[secsuite] ignoring unreadable baseline %s: %v\n", filePath, err)
		}
		return nil
	}

	var doc baselineFile
	if err := json.Unmarshal(data, &doc); err != nil {
		fmt.Fprintf(os.Stderr, "[secsuite] ignoring unreadable baseline %s: %v\n", filePath, err)
		return nil
	}
	if doc.Version != 1 {
		fmt.Fprintf(os.Stderr, "[secsuite] ignoring unreadable baseline %s: unexpected shape\n", filePath)
		return nil
	}

	ids := make(map[string]bool, len(doc.Findings))
	for _, e := range doc.Findings {
		ids[e.ID] = true
	}
	return ids
}

// SplitByBaseline separates findings the baseline already accepted from new
// ones. A nil baselineIDs means no baseline, so everything is fresh.
func SplitByBaseline(findings []Finding, baselineIDs map[string]bool) (fresh, baselined []Finding) {
	if baselineIDs == nil {
		return findings, nil
	}
	for _, f := range findings {
		if baselineIDs[f.ID] {
			baselined = append(baselined, f)
		} else {
			fresh = append(fresh, f)
		}
	}
	return fresh, baselined
}
