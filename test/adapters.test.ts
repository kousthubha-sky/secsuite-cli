import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { adaptSemgrep } from "../src/adapters/semgrep.js";
import { adaptTrivy } from "../src/adapters/trivy.js";
import { adaptGitleaks } from "../src/adapters/gitleaks.js";
import { dedupeFindings } from "../src/dedupe.js";

// Fixture SARIF files live in the source tree (not copied to dist); tests
// always run via `npm test` from the repo root, so resolve from cwd.
const FIXTURES = path.join(process.cwd(), "test", "fixtures");
const TARGET_DIR = "/repo"; // arbitrary - the fixture SARIF uris are relative paths

test("semgrep adapter maps SARIF error level to high severity + sast category", () => {
  const findings = adaptSemgrep(path.join(FIXTURES, "semgrep.sarif"), TARGET_DIR);
  assert.equal(findings.length, 1);
  const [f] = findings;
  assert.equal(f.tool, "semgrep");
  assert.equal(f.category, "sast");
  assert.equal(f.severity, "high");
  assert.equal(f.location.file, "app.js");
  assert.equal(f.location.startLine, 5);
});

test("trivy adapter maps severity tags and splits sca vs secret category", () => {
  const findings = adaptTrivy(path.join(FIXTURES, "trivy.sarif"), TARGET_DIR);
  assert.equal(findings.length, 2);

  const vuln = findings.find((f) => f.ruleId === "CVE-2020-8203")!;
  assert.equal(vuln.category, "sca");
  assert.equal(vuln.severity, "high");

  const secret = findings.find((f) => f.ruleId === "aws-access-key-id")!;
  assert.equal(secret.category, "secret");
  assert.equal(secret.location.file, "config.py");
});

test("gitleaks adapter always maps to high severity + secret category", () => {
  const findings = adaptGitleaks(path.join(FIXTURES, "gitleaks.sarif"), TARGET_DIR);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "high");
  assert.equal(findings[0].category, "secret");
  assert.equal(findings[0].location.file, "config.py");
});

test("dedupe merges cross-tool findings on the same file+line+category and unions sources", () => {
  const trivyFindings = adaptTrivy(path.join(FIXTURES, "trivy.sarif"), TARGET_DIR);
  const gitleaksFindings = adaptGitleaks(path.join(FIXTURES, "gitleaks.sarif"), TARGET_DIR);
  const merged = dedupeFindings([...trivyFindings, ...gitleaksFindings]);

  // trivy has 2 findings (1 sca + 1 secret); gitleaks has 1 secret finding on
  // the same file+line as trivy's secret finding, so those two should merge.
  assert.equal(merged.length, 2);

  const secretFinding = merged.find((f) => f.category === "secret")!;
  assert.deepEqual(secretFinding.sources.sort(), ["gitleaks", "trivy"]);
});

test("dedupe keeps distinct findings separate when file/line/category differ", () => {
  const semgrepFindings = adaptSemgrep(path.join(FIXTURES, "semgrep.sarif"), TARGET_DIR);
  const trivyFindings = adaptTrivy(path.join(FIXTURES, "trivy.sarif"), TARGET_DIR);
  const merged = dedupeFindings([...semgrepFindings, ...trivyFindings]);
  assert.equal(merged.length, 3);
});
