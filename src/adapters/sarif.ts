import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";

export interface SarifRule {
  id: string;
  shortDescription?: string;
  fullDescription?: string;
  helpUri?: string;
  tags: string[];
}

export interface SarifResultEntry {
  ruleId: string;
  level: string;
  message: string;
  file: string; // posix path, relative to the scan target
  startLine?: number;
  endLine?: number;
  rule?: SarifRule;
  raw: unknown;
}

export function parseSarifResults(sarifPath: string, targetDir: string): SarifResultEntry[] {
  const doc = JSON.parse(readFileSync(sarifPath, "utf8"));
  const entries: SarifResultEntry[] = [];

  for (const run of doc.runs ?? []) {
    const rules: (SarifRule & { defaultLevel?: string })[] = (run.tool?.driver?.rules ?? []).map((r: any) => ({
      id: r.id,
      shortDescription: r.shortDescription?.text,
      fullDescription: r.fullDescription?.text,
      helpUri: r.helpUri,
      tags: r.properties?.tags ?? [],
      defaultLevel: r.defaultConfiguration?.level,
    }));
    const ruleById = new Map(rules.map((r) => [r.id, r]));

    for (const result of run.results ?? []) {
      const loc = result.locations?.[0]?.physicalLocation;
      const uri: string | undefined = loc?.artifactLocation?.uri;
      if (!uri) continue;

      const rule = ruleById.get(result.ruleId);
      // Per the SARIF spec, a result with no `level` inherits the rule's
      // `defaultConfiguration.level` - semgrep (and others) rely on this
      // instead of repeating the level on every result.
      const level = result.level ?? rule?.defaultLevel ?? "";

      entries.push({
        ruleId: result.ruleId ?? "unknown",
        level,
        message: result.message?.text ?? "",
        file: normalizeRelPath(uri, targetDir),
        startLine: loc?.region?.startLine,
        endLine: loc?.region?.endLine,
        rule,
        raw: result,
      });
    }
  }

  return entries;
}

function normalizeRelPath(uri: string, targetDir: string): string {
  const decoded = decodeURIComponent(uri.replace(/^file:\/\//, ""));
  const abs = path.isAbsolute(decoded) ? decoded : path.resolve(targetDir, decoded);
  return path.relative(targetDir, abs).split(path.sep).join("/");
}

export function makeFindingId(tool: string, ruleId: string, file: string, startLine?: number): string {
  const hash = createHash("sha256").update(`${tool}|${ruleId}|${file}|${startLine ?? ""}`).digest("hex");
  return hash.slice(0, 16);
}

export function truncateTitle(text: string, max = 100): string {
  const firstLine = text.split("\n")[0].trim();
  return firstLine.length > max ? `${firstLine.slice(0, max - 3).trimEnd()}...` : firstLine;
}
