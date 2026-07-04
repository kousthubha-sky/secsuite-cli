import { test } from "node:test";
import assert from "node:assert/strict";
import { stripRaw, printReport } from "../src/report.js";
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
    title: ruleId,
    description: "",
    location: { file, startLine },
    sources: [tool],
    raw: { huge: "scanner payload" },
  };
}

test("stripRaw removes the raw payload and keeps every other field", () => {
  const [lean] = stripRaw([mkFinding("trivy", "CVE-1", "a.txt", "sca", "critical", 3)]) as any[];
  assert.equal(lean.raw, undefined);
  assert.equal(lean.ruleId, "CVE-1");
  assert.equal(lean.severity, "critical");
  assert.equal(lean.location.startLine, 3);
  assert.deepEqual(lean.sources, ["trivy"]);
});

test("--json - machine mode prints exactly one compact JSON payload on stdout", () => {
  const logs: string[] = [];
  const orig = console.log;
  console.log = (s: unknown) => {
    logs.push(String(s));
  };
  try {
    const shown = printReport([mkFinding("trivy", "CVE-1", "a.txt", "sca", "high", 1)], "medium", "-");
    assert.equal(shown.length, 1); // the gate still computes
  } finally {
    console.log = orig;
  }
  assert.equal(logs.length, 1);
  const parsed = JSON.parse(logs[0]);
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0].ruleId, "CVE-1");
  assert.ok(!logs[0].includes("\n"), "compact, single line");
});
