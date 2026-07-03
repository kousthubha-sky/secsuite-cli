import { Finding, severityRank } from "./schema.js";

// Duplicate key: file + line + category. Category (the normalized
// classification) stands in for "mapped rule/CWE" here - ruleId vocabularies
// never overlap between tools, so keying on raw ruleId would never catch the
// most common real duplicate (e.g. trivy's secret scanner and gitleaks both
// flagging the same hardcoded key on the same line).
// ponytail: no CWE extraction, category is the simple stand-in. Upgrade to
// real CWE matching if false-merges show up in practice.
function dedupeKey(f: Finding): string {
  return `${f.location.file}:${f.location.startLine ?? ""}:${f.category}`;
}

export function dedupeFindings(findings: Finding[]): Finding[] {
  const byKey = new Map<string, Finding>();

  for (const f of findings) {
    const key = dedupeKey(f);
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, { ...f, sources: [...f.sources] });
      continue;
    }
    existing.sources = Array.from(new Set([...existing.sources, ...f.sources]));
    if (severityRank(f.severity) < severityRank(existing.severity)) {
      existing.severity = f.severity;
    }
  }

  return Array.from(byKey.values());
}
