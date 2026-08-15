package secsuite

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// ZAP's baseline/full-scan `-J` output is ZAP's own JSON shape, not SARIF, so
// this adapter parses it directly. Severity comes from `riskcode`:
//
//	3 -> High, 2 -> Medium, 1 -> Low, 0 -> Informational
//
// (ZAP's risk scale tops out at High; there is no "critical".)
var riskToSeverity = map[string]Severity{
	"3": SeverityHigh,
	"2": SeverityMedium,
	"1": SeverityLow,
	"0": SeverityInfo,
}

type zapDoc struct {
	Site []struct {
		// The JSON key really is "@name" - a struct tag can carry any key,
		// which is how Go reaches names that are not valid identifiers.
		Name string `json:"@name"`
		// Raw, so each alert can be both decoded and carried through to --raw
		// output unchanged, the same trick the SARIF parser uses for results.
		Alerts []json.RawMessage `json:"alerts"`
	} `json:"site"`
}

type zapAlert struct {
	PluginID  string `json:"pluginid"`
	AlertRef  string `json:"alertRef"`
	Alert     string `json:"alert"`
	Name      string `json:"name"`
	RiskCode  string `json:"riskcode"`
	Desc      string `json:"desc"`
	Solution  string `json:"solution"`
	Reference string `json:"reference"`
	CWEID     string `json:"cweid"`
	Instances []struct {
		URI    string `json:"uri"`
		Method string `json:"method"`
		Param  string `json:"param"`
	} `json:"instances"`
}

var (
	htmlTag        = regexp.MustCompile(`<[^>]+>`)
	whitespaceRuns = regexp.MustCompile(`\s+`)
)

// stripHTML flattens ZAP's HTML-wrapped descriptions for console output.
func stripHTML(s string) string {
	return strings.TrimSpace(whitespaceRuns.ReplaceAllString(htmlTag.ReplaceAllString(s, " "), " "))
}

// AdaptZap turns a ZAP JSON report into findings.
func AdaptZap(reportPath, target string) ([]Finding, error) {
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", reportPath, err)
	}

	var doc zapDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", reportPath, err)
	}

	var findings []Finding
	for _, site := range doc.Site {
		for _, rawAlert := range site.Alerts {
			var alert zapAlert
			if err := json.Unmarshal(rawAlert, &alert); err != nil {
				continue // one malformed alert must not sink the whole report
			}

			ruleID := alert.PluginID
			if ruleID == "" {
				ruleID = alert.AlertRef
			}
			if ruleID == "" {
				ruleID = "zap-unknown"
			}

			severity, ok := riskToSeverity[alert.RiskCode]
			if !ok {
				severity = SeverityInfo
			}

			// The location for a DAST finding is a URL, not a source file/line.
			// Use the first affected instance URI, falling back to the site or
			// target.
			url := ""
			if len(alert.Instances) > 0 {
				url = alert.Instances[0].URI
			}
			if url == "" {
				url = site.Name
			}
			if url == "" {
				url = target
			}

			title := alert.Name
			if title == "" {
				title = alert.Alert
			}
			if title == "" {
				title = ruleID
			}

			description := stripHTML(alert.Desc)
			if description == "" {
				description = title
			}

			var references []string
			if alert.CWEID != "" && alert.CWEID != "-1" {
				references = []string{"https://cwe.mitre.org/data/definitions/" + alert.CWEID + ".html"}
			}

			findings = append(findings, Finding{
				ID:       MakeFindingID("zap", ruleID, url, 0),
				Tool:     ToolZAP,
				Category: CategoryDAST,
				RuleID:   ruleID,
				Severity: severity,
				Title:    TruncateTitle(title),
				// DAST findings have no line number, so Location.StartLine
				// stays 0 - which is exactly the "absent" the report and the
				// SARIF export already check for.
				Location:    Location{File: url},
				Description: description,
				Remediation: stripHTML(alert.Solution),
				References:  references,
				Sources:     []string{string(ToolZAP)},
				Raw:         rawAlert,
			})
		}
	}

	return findings, nil
}
