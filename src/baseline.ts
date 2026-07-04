import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { Finding } from "./schema.js";

export const BASELINE_FILENAME = ".secsuite-baseline.json";

interface BaselineEntry {
  id: string;
  tool: string;
  ruleId: string;
  file: string;
  startLine?: number;
  severity: string;
  title: string;
}

interface BaselineFile {
  version: 1;
  created: string;
  findings: BaselineEntry[];
}

// Matching uses `id` only; the other fields exist so a human reviewing the
// committed file can see exactly what was accepted.
export function writeBaseline(filePath: string, findings: Finding[]): void {
  const doc: BaselineFile = {
    version: 1,
    created: new Date().toISOString(),
    findings: findings.map((f) => ({
      id: f.id,
      tool: f.tool,
      ruleId: f.ruleId,
      file: f.location.file,
      ...(f.location.startLine !== undefined ? { startLine: f.location.startLine } : {}),
      severity: f.severity,
      title: f.title,
    })),
  };
  writeFileSync(filePath, JSON.stringify(doc, null, 2));
}

// undefined = no usable baseline. A corrupt file warns and is ignored so a
// broken baseline can only ever surface MORE findings, never hide them.
export function loadBaselineIds(filePath: string): Set<string> | undefined {
  if (!existsSync(filePath)) return undefined;
  try {
    const doc = JSON.parse(readFileSync(filePath, "utf8")) as BaselineFile;
    if (doc.version !== 1 || !Array.isArray(doc.findings)) throw new Error("unexpected shape");
    return new Set(doc.findings.map((e) => e.id));
  } catch (err) {
    console.warn(`[secsuite] ignoring unreadable baseline ${filePath}: ${(err as Error).message}`);
    return undefined;
  }
}

export function splitByBaseline(
  findings: Finding[],
  baselineIds: Set<string> | undefined
): { fresh: Finding[]; baselined: Finding[] } {
  if (!baselineIds) return { fresh: findings, baselined: [] };
  const fresh: Finding[] = [];
  const baselined: Finding[] = [];
  for (const f of findings) (baselineIds.has(f.id) ? baselined : fresh).push(f);
  return { fresh, baselined };
}
