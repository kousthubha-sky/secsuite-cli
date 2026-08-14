package secsuite

// Gitleaks only reports secrets, and a committed secret is always a serious
// finding - so every result maps to a fixed severity/category, no level table
// needed.

// AdaptGitleaks turns a gitleaks SARIF file into findings.
func AdaptGitleaks(sarifPath, targetDir string) ([]Finding, error) {
	results, err := ParseSarifResults(sarifPath, targetDir)
	if err != nil {
		return nil, err
	}

	findings := make([]Finding, 0, len(results))
	for _, r := range results {
		title := r.Rule.ShortDescription
		if title == "" {
			title = r.RuleID
		}
		description := r.Message
		if description == "" {
			description = title
		}

		findings = append(findings, Finding{
			ID:          MakeFindingID("gitleaks", r.RuleID, r.File, r.StartLine),
			Tool:        ToolGitleaks,
			Category:    CategorySecret,
			RuleID:      r.RuleID,
			Severity:    SeverityHigh,
			Title:       title,
			Description: description,
			Location:    Location{File: r.File, StartLine: r.StartLine, EndLine: r.EndLine},
			Sources:     []string{string(ToolGitleaks)},
			Raw:         r.Raw,
		})
	}
	return findings, nil
}
