import { readFileSync } from "node:fs";
import { Finding, Severity } from "../schema.js";
import { makeFindingId, truncateTitle } from "./sarif.js";

// ZAP's baseline/full-scan `-J` output is ZAP's own JSON shape, not SARIF, so
// this adapter parses it directly. Severity comes from `riskcode`:
//   3 -> High, 2 -> Medium, 1 -> Low, 0 -> Informational
// (ZAP's risk scale tops out at High; there is no "critical".)
const RISK_TO_SEVERITY: Record<string, Severity> = {
  "3": "high",
  "2": "medium",
  "1": "low",
  "0": "info",
};

interface ZapInstance {
  uri?: string;
  method?: string;
  param?: string;
}

interface ZapAlert {
  pluginid?: string;
  alertRef?: string;
  alert?: string;
  name?: string;
  riskcode?: string;
  desc?: string;
  solution?: string;
  reference?: string;
  cweid?: string;
  instances?: ZapInstance[];
}

interface ZapSite {
  "@name"?: string;
  alerts?: ZapAlert[];
}

// ZAP wraps descriptions/solutions in HTML; strip tags for console output.
function stripHtml(s: string | undefined): string {
  return (s ?? "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
}

export function adaptZap(reportPath: string, target: string): Finding[] {
  const doc = JSON.parse(readFileSync(reportPath, "utf8"));
  const sites: ZapSite[] = doc.site ?? [];
  const findings: Finding[] = [];

  for (const site of sites) {
    for (const alert of site.alerts ?? []) {
      const ruleId = alert.pluginid ?? alert.alertRef ?? "zap-unknown";
      const severity = RISK_TO_SEVERITY[alert.riskcode ?? ""] ?? "info";
      // The location for a DAST finding is a URL, not a source file/line. Use
      // the first affected instance URI, falling back to the site or target.
      const url = alert.instances?.[0]?.uri ?? site["@name"] ?? target;
      const title = alert.name ?? alert.alert ?? ruleId;
      const cwe = alert.cweid && alert.cweid !== "-1" ? `https://cwe.mitre.org/data/definitions/${alert.cweid}.html` : undefined;

      findings.push({
        id: makeFindingId("zap", ruleId, url),
        tool: "zap",
        category: "dast",
        ruleId,
        severity,
        title: truncateTitle(title),
        description: stripHtml(alert.desc) || title,
        location: { file: url },
        remediation: stripHtml(alert.solution) || undefined,
        references: cwe ? [cwe] : undefined,
        sources: ["zap"],
        raw: alert,
      });
    }
  }

  return findings;
}
