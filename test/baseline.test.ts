import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import os from "node:os";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { writeBaseline, loadBaselineIds, splitByBaseline, BASELINE_FILENAME } from "../src/baseline.js";
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
    raw: {},
  };
}

test("baseline round-trips: written findings load back as the same id set", () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "secsuite-baseline-"));
  try {
    const findings = [
      mkFinding("trivy", "CVE-1", "requirements.txt", "sca", "critical", 1),
      mkFinding("gitleaks", "aws-key", "config.py", "secret", "high", 4),
    ];
    const file = path.join(dir, BASELINE_FILENAME);
    writeBaseline(file, findings);
    const ids = loadBaselineIds(file)!;
    assert.equal(ids.size, 2);
    assert.ok(ids.has(findings[0].id));
    assert.ok(ids.has(findings[1].id));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("missing baseline file loads as undefined", () => {
  assert.equal(loadBaselineIds(path.join(os.tmpdir(), "does-not-exist.json")), undefined);
});

test("corrupt baseline file warns and loads as undefined", () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "secsuite-baseline-"));
  try {
    const file = path.join(dir, BASELINE_FILENAME);
    writeFileSync(file, "{ not json !!");
    assert.equal(loadBaselineIds(file), undefined);
    writeFileSync(file, JSON.stringify({ version: 99, findings: "nope" }));
    assert.equal(loadBaselineIds(file), undefined);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("splitByBaseline separates fresh from baselined; no baseline means all fresh", () => {
  const known = mkFinding("trivy", "CVE-1", "a.txt", "sca", "high", 1);
  const fresh = mkFinding("trivy", "CVE-2", "a.txt", "sca", "critical", 1);
  const withBaseline = splitByBaseline([known, fresh], new Set([known.id]));
  assert.deepEqual(withBaseline.fresh.map((f) => f.id), [fresh.id]);
  assert.deepEqual(withBaseline.baselined.map((f) => f.id), [known.id]);

  const noBaseline = splitByBaseline([known, fresh], undefined);
  assert.equal(noBaseline.fresh.length, 2);
  assert.equal(noBaseline.baselined.length, 0);
});
