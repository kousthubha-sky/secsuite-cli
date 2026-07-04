import { Finding, Severity } from "./schema.js";

const LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

// GitHub Code Scanning requires relative forward-slash URIs for files;
// DAST findings carry a URL and pass through untouched.
function toUri(file: string): string {
  if (/^https?:\/\//i.test(file)) return file;
  return file.replace(/\\/g, "/");
}

export function findingsToSarif(findings: Finding[], version: string): object {
  const ruleIndex = new Map<string, number>();
  const rules: object[] = [];

  for (const f of findings) {
    if (ruleIndex.has(f.ruleId)) continue;
    ruleIndex.set(f.ruleId, rules.length);
    rules.push({
      id: f.ruleId,
      shortDescription: { text: f.title },
      ...(f.references?.length ? { helpUri: f.references[0] } : {}),
    });
  }

  const results = findings.map((f) => ({
    ruleId: f.ruleId,
    ruleIndex: ruleIndex.get(f.ruleId)!,
    level: LEVEL[f.severity],
    message: { text: f.title },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: toUri(f.location.file) },
          ...(f.location.startLine !== undefined ? { region: { startLine: f.location.startLine } } : {}),
        },
      },
    ],
    // Stable across re-runs so GitHub alert tracking survives new scans.
    partialFingerprints: { secsuiteId: f.id },
    properties: { severity: f.severity, category: f.category, sources: f.sources },
  }));

  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "secsuite",
            version,
            informationUri: "https://github.com/kousthubha-sky/secsuite-cli",
            rules,
          },
        },
        results,
      },
    ],
  };
}
