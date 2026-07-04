import { test } from "node:test";
import assert from "node:assert/strict";
import { findingsToSarif } from "../src/sarif-export.js";
import { Finding, ToolName, Category, Severity } from "../src/schema.js";

function mkFinding(
  tool: ToolName,
  ruleId: string,
  file: string,
  category: Category,
  severity: Severity = "high",
  startLine?: number
): Finding {
  return {
    id: `${tool}-${ruleId}-${file}-${startLine ?? ""}`,
    tool,
    category,
    ruleId,
    severity,
    title: `title for ${ruleId}`,
    description: "",
    location: { file, startLine },
    references: ["https://example.com/rule"],
    sources: [tool],
    raw: {},
  };
}

test("findingsToSarif emits a valid 2.1.0 shell with secsuite as the driver", () => {
  const sarif = findingsToSarif([mkFinding("trivy", "CVE-1", "requirements.txt", "sca", "critical", 2)], "0.2.0") as any;
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs.length, 1);
  assert.equal(sarif.runs[0].tool.driver.name, "secsuite");
  assert.equal(sarif.runs[0].tool.driver.version, "0.2.0");
  assert.equal(sarif.runs[0].results.length, 1);
});

test("severity maps to SARIF level: critical/high=error, medium=warning, low/info=note", () => {
  const findings = [
    mkFinding("trivy", "a", "f1", "sca", "critical", 1),
    mkFinding("trivy", "b", "f2", "sca", "high", 1),
    mkFinding("trivy", "c", "f3", "sca", "medium", 1),
    mkFinding("trivy", "d", "f4", "sca", "low", 1),
    mkFinding("trivy", "e", "f5", "sca", "info", 1),
  ];
  const levels = (findingsToSarif(findings, "0.2.0") as any).runs[0].results.map((r: any) => r.level);
  assert.deepEqual(levels, ["error", "error", "warning", "note", "note"]);
});

test("windows paths become forward-slash relative URIs; URLs pass through; DAST has no region", () => {
  const sarif = findingsToSarif(
    [
      mkFinding("semgrep", "r1", "src\\app\\main.py", "sast", "high", 10),
      mkFinding("zap", "40018", "https://staging.example.com/search", "dast", "high"),
    ],
    "0.2.0"
  ) as any;
  const [code, dast] = sarif.runs[0].results;
  assert.equal(code.locations[0].physicalLocation.artifactLocation.uri, "src/app/main.py");
  assert.equal(code.locations[0].physicalLocation.region.startLine, 10);
  assert.equal(dast.locations[0].physicalLocation.artifactLocation.uri, "https://staging.example.com/search");
  assert.equal(dast.locations[0].physicalLocation.region, undefined);
});

test("rules are unique per ruleId and results carry stable fingerprints", () => {
  const findings = [
    mkFinding("trivy", "CVE-1", "a.txt", "sca", "high", 1),
    mkFinding("trivy", "CVE-1", "b.txt", "sca", "high", 2),
  ];
  const run = (findingsToSarif(findings, "0.2.0") as any).runs[0];
  assert.equal(run.tool.driver.rules.length, 1);
  assert.equal(run.tool.driver.rules[0].id, "CVE-1");
  assert.equal(run.results[0].ruleIndex, 0);
  assert.equal(run.results[1].ruleIndex, 0);
  assert.equal(run.results[0].partialFingerprints.secsuiteId, findings[0].id);
  assert.equal(run.results[0].properties.category, "sca");
});
