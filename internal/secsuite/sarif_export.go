package secsuite

import (
	"regexp"
	"strings"
)

// severityToLevel maps a normalized severity onto the three levels SARIF and
// GitHub Code Scanning understand.
var severityToLevel = map[Severity]string{
	SeverityCritical: "error",
	SeverityHigh:     "error",
	SeverityMedium:   "warning",
	SeverityLow:      "note",
	SeverityInfo:     "note",
}

// SARIFDocument and the types below are the output shape. Unlike the parser's
// input structs these are exported, so tests can assert on the tree without
// re-parsing JSON.
type SARIFDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool struct {
		Driver SARIFDriver `json:"driver"`
	} `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFDriver struct {
	Name           string          `json:"name"`
	Version        string          `json:"version"`
	InformationURI string          `json:"informationUri"`
	Rules          []SARIFRuleDesc `json:"rules"`
}

type SARIFRuleDesc struct {
	ID               string    `json:"id"`
	ShortDescription SARIFText `json:"shortDescription"`
	HelpURI          string    `json:"helpUri,omitempty"`
}

type SARIFText struct {
	Text string `json:"text"`
}

type SARIFResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             SARIFText         `json:"message"`
	Locations           []SARIFLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          SARIFResultProps  `json:"properties"`
}

type SARIFLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		// A pointer, so a DAST finding with no line omits `region` entirely
		// rather than emitting `"region": {"startLine": 0}`. This is the one
		// place in the port where optionality genuinely needs a pointer:
		// omitempty on a struct value does nothing.
		Region *SARIFRegion `json:"region,omitempty"`
	} `json:"physicalLocation"`
}

type SARIFRegion struct {
	StartLine int `json:"startLine"`
}

type SARIFResultProps struct {
	Severity Severity `json:"severity"`
	Category Category `json:"category"`
	Sources  []string `json:"sources"`
}

var httpURL = regexp.MustCompile(`(?i)^https?://`)

// toURI normalizes a finding location for SARIF. GitHub Code Scanning requires
// relative forward-slash URIs for files; DAST findings carry a URL and pass
// through untouched.
func toURI(file string) string {
	if httpURL.MatchString(file) {
		return file
	}
	return strings.ReplaceAll(file, `\`, "/")
}

// FindingsToSARIF renders findings as a SARIF 2.1.0 document with secsuite as
// the reporting tool.
func FindingsToSARIF(findings []Finding, version string) SARIFDocument {
	ruleIndex := make(map[string]int)
	rules := make([]SARIFRuleDesc, 0)
	results := make([]SARIFResult, 0, len(findings))

	for _, f := range findings {
		if _, seen := ruleIndex[f.RuleID]; !seen {
			ruleIndex[f.RuleID] = len(rules)
			rule := SARIFRuleDesc{ID: f.RuleID, ShortDescription: SARIFText{Text: f.Title}}
			if len(f.References) > 0 {
				rule.HelpURI = f.References[0]
			}
			rules = append(rules, rule)
		}

		var location SARIFLocation
		location.PhysicalLocation.ArtifactLocation.URI = toURI(f.Location.File)
		if f.Location.StartLine != 0 {
			location.PhysicalLocation.Region = &SARIFRegion{StartLine: f.Location.StartLine}
		}

		results = append(results, SARIFResult{
			RuleID:    f.RuleID,
			RuleIndex: ruleIndex[f.RuleID],
			Level:     severityToLevel[f.Severity],
			Message:   SARIFText{Text: f.Title},
			Locations: []SARIFLocation{location},
			// Stable across re-runs so GitHub alert tracking survives new scans.
			PartialFingerprints: map[string]string{"secsuiteId": f.ID},
			Properties: SARIFResultProps{
				Severity: f.Severity,
				Category: f.Category,
				Sources:  f.Sources,
			},
		})
	}

	doc := SARIFDocument{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs:    make([]SARIFRun, 1),
	}
	doc.Runs[0].Tool.Driver = SARIFDriver{
		Name:           "secsuite",
		Version:        version,
		InformationURI: "https://github.com/kousthubha-sky/secsuite-cli",
		Rules:          rules,
	}
	doc.Runs[0].Results = results
	return doc
}
