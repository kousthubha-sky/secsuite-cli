import { writeFileSync } from "node:fs";
import { Finding, Severity, SEVERITY_ORDER } from "./schema.js";

export function filterByThreshold(findings: Finding[], threshold: Severity): Finding[] {
  const minRank = SEVERITY_ORDER.indexOf(threshold);
  return findings.filter((f) => SEVERITY_ORDER.indexOf(f.severity) <= minRank);
}

// The raw scanner payload is by far the largest field and rarely needed;
// agents opt back in with --raw.
export function stripRaw(findings: Finding[]): object[] {
  return findings.map(({ raw: _raw, ...rest }) => rest);
}

export function printReport(
  findings: Finding[],
  threshold: Severity,
  jsonPath?: string,
  jsonFindings: object[] = findings
): Finding[] {
  const shown = filterByThreshold(findings, threshold);

  // Machine mode: `--json -` streams one compact JSON payload to stdout and
  // suppresses the human report - nothing else may touch stdout.
  if (jsonPath === "-") {
    console.log(JSON.stringify(jsonFindings));
    return shown;
  }

  if (shown.length === 0) {
    console.log(`No findings at or above severity "${threshold}".`);
  } else {
    for (const severity of SEVERITY_ORDER) {
      const atSeverity = shown.filter((f) => f.severity === severity);
      if (atSeverity.length === 0) continue;

      console.log(`\n${severity.toUpperCase()} (${atSeverity.length})`);
      for (const [category, items] of groupBy(atSeverity, (f) => f.category)) {
        console.log(`  ${category}:`);
        for (const f of items) {
          const loc = f.location.startLine ? `${f.location.file}:${f.location.startLine}` : f.location.file;
          const sources = f.sources.length > 1 ? ` [${f.sources.join(", ")}]` : "";
          console.log(`    - ${f.title} (${loc})${sources}`);
        }
      }
    }
  }

  const counts = SEVERITY_ORDER.map((s) => `${s}: ${shown.filter((f) => f.severity === s).length}`).join(", ");
  console.log(`\nTotal: ${shown.length} finding(s) at or above "${threshold}" (${counts})`);

  if (jsonPath) {
    writeFileSync(jsonPath, JSON.stringify(jsonFindings, null, 2));
    console.log(`Full findings (all severities) written to ${jsonPath}`);
  }

  return shown;
}

function groupBy<T, K>(items: T[], keyFn: (item: T) => K): Map<K, T[]> {
  const map = new Map<K, T[]>();
  for (const item of items) {
    const key = keyFn(item);
    const list = map.get(key);
    if (list) list.push(item);
    else map.set(key, [item]);
  }
  return map;
}
