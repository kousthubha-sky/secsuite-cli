import { Finding, Severity } from "../schema.js";
import { parseSarifResults, makeFindingId, truncateTitle } from "./sarif.js";

// Semgrep SARIF severity mapping (SARIF `level`, set by semgrep from its own
// ERROR/WARNING/INFO rule severities):
//   error   -> high
//   warning -> medium
//   note    -> low
//   (none)  -> info
const LEVEL_TO_SEVERITY: Record<string, Severity> = {
  error: "high",
  warning: "medium",
  note: "low",
};

export function adaptSemgrep(sarifPath: string, targetDir: string): Finding[] {
  return parseSarifResults(sarifPath, targetDir).map((r) => {
    const severity = LEVEL_TO_SEVERITY[r.level] ?? "info";
    // Semgrep's rule.shortDescription is a generic "Semgrep Finding: <ruleId>"
    // placeholder, not a real summary - the useful text lives in the message.
    const title = (r.message && truncateTitle(r.message)) || r.rule?.shortDescription || r.ruleId;

    return {
      id: makeFindingId("semgrep", r.ruleId, r.file, r.startLine),
      tool: "semgrep",
      category: "sast",
      ruleId: r.ruleId,
      severity,
      title,
      description: r.message || r.rule?.fullDescription || title,
      location: { file: r.file, startLine: r.startLine, endLine: r.endLine },
      references: r.rule?.helpUri ? [r.rule.helpUri] : undefined,
      sources: ["semgrep"],
      raw: r.raw,
    };
  });
}
