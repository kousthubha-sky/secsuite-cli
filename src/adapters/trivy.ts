import { Finding, Category, Severity } from "../schema.js";
import { parseSarifResults, makeFindingId, truncateTitle } from "./sarif.js";

// Trivy severity mapping (trivy tags its SARIF rules with its native
// severity string, e.g. rule.tags = ["CRITICAL"]):
//   CRITICAL -> critical
//   HIGH     -> high
//   MEDIUM   -> medium
//   LOW      -> low
//   UNKNOWN  -> info
const TAG_TO_SEVERITY: Record<string, Severity> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  UNKNOWN: "info",
};

// Fallback if no severity tag is present: same SARIF-level mapping used for semgrep.
const LEVEL_TO_SEVERITY: Record<string, Severity> = {
  error: "high",
  warning: "medium",
  note: "low",
};

const IAC_FILE_PATTERN = /(^|\/)Dockerfile$|\.ya?ml$|\.tf$/i;

function categoryFromTags(tags: string[], file: string): Category {
  const lower = tags.map((t) => t.toLowerCase());
  if (lower.includes("secret")) return "secret";
  if (lower.includes("misconfiguration")) {
    return IAC_FILE_PATTERN.test(file) ? "iac" : "misconfig";
  }
  return "sca"; // trivy's default scan type is vulnerability -> SCA
}

export function adaptTrivy(sarifPath: string, targetDir: string): Finding[] {
  return parseSarifResults(sarifPath, targetDir).map((r) => {
    const tags = r.rule?.tags ?? [];
    const severityTag = tags.find((t) => t.toUpperCase() in TAG_TO_SEVERITY);
    const severity = severityTag
      ? TAG_TO_SEVERITY[severityTag.toUpperCase()]
      : LEVEL_TO_SEVERITY[r.level] ?? "info";
    const category = categoryFromTags(tags, r.file);
    const title = r.rule?.shortDescription || truncateTitle(r.message) || r.ruleId;

    return {
      id: makeFindingId("trivy", r.ruleId, r.file, r.startLine),
      tool: "trivy",
      category,
      ruleId: r.ruleId,
      severity,
      title,
      description: r.message || r.rule?.fullDescription || title,
      location: { file: r.file, startLine: r.startLine, endLine: r.endLine },
      references: r.rule?.helpUri ? [r.rule.helpUri] : undefined,
      sources: ["trivy"],
      raw: r.raw,
    };
  });
}
