import { Finding } from "../schema.js";
import { parseSarifResults, makeFindingId } from "./sarif.js";

// Gitleaks only reports secrets, and a committed secret is always a serious
// finding - so every result maps to a fixed severity/category, no level table needed.

export function adaptGitleaks(sarifPath: string, targetDir: string): Finding[] {
  return parseSarifResults(sarifPath, targetDir).map((r) => {
    const title = r.rule?.shortDescription ?? r.ruleId;

    return {
      id: makeFindingId("gitleaks", r.ruleId, r.file, r.startLine),
      tool: "gitleaks",
      category: "secret",
      ruleId: r.ruleId,
      severity: "high",
      title,
      description: r.message || title,
      location: { file: r.file, startLine: r.startLine, endLine: r.endLine },
      sources: ["gitleaks"],
      raw: r.raw,
    };
  });
}
