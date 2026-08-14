package secsuite

import (
	"regexp"
	"strings"
)

// tagToSeverity maps trivy's native severity, which it tags its SARIF rules
// with (e.g. rule.tags = ["CRITICAL"]), onto a normalized severity.
var tagToSeverity = map[string]Severity{
	"CRITICAL": SeverityCritical,
	"HIGH":     SeverityHigh,
	"MEDIUM":   SeverityMedium,
	"LOW":      SeverityLow,
	"UNKNOWN":  SeverityInfo,
}

var iacFilePattern = regexp.MustCompile(`(?i)(^|/)Dockerfile$|\.ya?ml$|\.tf$`)

func categoryFromTags(tags []string, file string) Category {
	for _, t := range tags {
		switch strings.ToLower(t) {
		case "secret":
			return CategorySecret
		case "misconfiguration":
			if iacFilePattern.MatchString(file) {
				return CategoryIaC
			}
			return CategoryMisconfig
		}
	}
	return CategorySCA // trivy's default scan type is vulnerability -> SCA
}

// AdaptTrivy turns a trivy SARIF file into findings.
func AdaptTrivy(sarifPath, targetDir string) ([]Finding, error) {
	results, err := ParseSarifResults(sarifPath, targetDir)
	if err != nil {
		return nil, err
	}

	findings := make([]Finding, 0, len(results))
	for _, r := range results {
		// Fall back to the same SARIF-level mapping semgrep uses when no
		// severity tag is present.
		severity, ok := levelToSeverity[r.Level]
		if !ok {
			severity = SeverityInfo
		}
		for _, tag := range r.Rule.Tags {
			if tagged, found := tagToSeverity[strings.ToUpper(tag)]; found {
				severity = tagged
				break
			}
		}

		title := r.Rule.ShortDescription
		if title == "" {
			title = TruncateTitle(r.Message)
		}
		if title == "" {
			title = r.RuleID
		}

		description := r.Message
		if description == "" {
			description = r.Rule.FullDescription
		}
		if description == "" {
			description = title
		}

		var references []string
		if r.Rule.HelpURI != "" {
			references = []string{r.Rule.HelpURI}
		}

		findings = append(findings, Finding{
			ID:          MakeFindingID("trivy", r.RuleID, r.File, r.StartLine),
			Tool:        ToolTrivy,
			Category:    categoryFromTags(r.Rule.Tags, r.File),
			RuleID:      r.RuleID,
			Severity:    severity,
			Title:       title,
			Description: description,
			Location:    Location{File: r.File, StartLine: r.StartLine, EndLine: r.EndLine},
			References:  references,
			Sources:     []string{string(ToolTrivy)},
			Raw:         r.Raw,
		})
	}
	return findings, nil
}
