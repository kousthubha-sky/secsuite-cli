package secsuite

// levelToSeverity maps a SARIF `level` (set by semgrep from its own
// ERROR/WARNING/INFO rule severities) onto a normalized severity:
//
//	error   -> high
//	warning -> medium
//	note    -> low
//	(none)  -> info
//
// Shared with the trivy adapter, which uses it as a fallback.
var levelToSeverity = map[string]Severity{
	"error":   SeverityHigh,
	"warning": SeverityMedium,
	"note":    SeverityLow,
}

// AdaptSemgrep turns a semgrep SARIF file into findings.
func AdaptSemgrep(sarifPath, targetDir string) ([]Finding, error) {
	results, err := ParseSarifResults(sarifPath, targetDir)
	if err != nil {
		return nil, err
	}

	findings := make([]Finding, 0, len(results))
	for _, r := range results {
		severity, ok := levelToSeverity[r.Level]
		if !ok {
			severity = SeverityInfo
		}

		// Semgrep's rule.shortDescription is a generic "Semgrep Finding: <ruleId>"
		// placeholder, not a real summary - the useful text lives in the message.
		title := TruncateTitle(r.Message)
		if title == "" {
			title = r.Rule.ShortDescription
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
			ID:          MakeFindingID("semgrep", r.RuleID, r.File, r.StartLine),
			Tool:        ToolSemgrep,
			Category:    CategorySAST,
			RuleID:      r.RuleID,
			Severity:    severity,
			Title:       title,
			Description: description,
			Location:    Location{File: r.File, StartLine: r.StartLine, EndLine: r.EndLine},
			References:  references,
			Sources:     []string{string(ToolSemgrep)},
			Raw:         r.Raw,
		})
	}
	return findings, nil
}
