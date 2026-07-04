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

    // Merge only when a DIFFERENT tool reports the same location+category -
    // that is a genuine cross-tool duplicate (e.g. trivy and gitleaks both
    // flagging one hardcoded key). Two findings from the SAME tool at one
    // location are distinct issues - several CVEs on one dependency line, or
    // several ZAP alerts on one URL - so they must be kept separate.
    if (!existing.sources.includes(f.tool)) {
      existing.sources = Array.from(new Set([...existing.sources, ...f.sources]));
      if (severityRank(f.severity) < severityRank(existing.severity)) {
        existing.severity = f.severity;
      }
      continue;
    }

    // Same tool, same location+category: re-key with ruleId so the distinct
    // finding survives instead of being collapsed. An identical
    // tool+rule+location finding (a true duplicate) still folds into one.
    // ponytail: a same-tool finding won't also cross-tool-merge here; add that
    // if a tool ever re-reports another tool's exact location+category+rule.
    byKey.set(`${key}:${f.ruleId}`, { ...f, sources: [...f.sources] });
  }

  return Array.from(byKey.values());
}
