import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import os from "node:os";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { adaptSemgrep } from "../src/adapters/semgrep.js";
import { adaptTrivy } from "../src/adapters/trivy.js";
import { adaptGitleaks } from "../src/adapters/gitleaks.js";
import { adaptZap } from "../src/adapters/zap.js";
import { dedupeFindings } from "../src/dedupe.js";
import { detectStack } from "../src/detect.js";
import { Finding, ToolName, Category, Severity } from "../src/schema.js";

// Minimal Finding builder for dedupe unit tests.
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

test("zap adapter maps riskcode to severity + dast category with URL locations", () => {
  const findings = adaptZap(path.join(FIXTURES, "zap.json"), "https://staging.example.com");
  assert.equal(findings.length, 3);

  const sqli = findings.find((f) => f.ruleId === "40018")!;
  assert.equal(sqli.tool, "zap");
  assert.equal(sqli.category, "dast");
  assert.equal(sqli.severity, "high"); // riskcode 3
  assert.equal(sqli.location.file, "https://staging.example.com/search?q=1");
  assert.equal(sqli.location.startLine, undefined); // DAST findings have no line
  assert.match(sqli.references![0], /cwe\.mitre\.org.*89/);

  assert.equal(findings.find((f) => f.ruleId === "10038")!.severity, "medium"); // riskcode 2
  assert.equal(findings.find((f) => f.ruleId === "10096")!.severity, "info"); // riskcode 0
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

test("dedupe does NOT merge distinct findings from the same tool at one location", () => {
  // Two CVEs on the same dependency line (trivy emits one per CVE) must both
  // survive - collapsing them under-counts real vulnerabilities.
  const findings = [
    mkFinding("trivy", "CVE-1111", "requirements.txt", "sca", "high", 1),
    mkFinding("trivy", "CVE-2222", "requirements.txt", "sca", "critical", 1),
  ];
  const merged = dedupeFindings(findings);
  assert.equal(merged.length, 2);
});

test("dedupe does NOT merge distinct ZAP alerts on the same URL", () => {
  // DAST findings have no line number, so several alerts on one URL share
  // file+category; they must not collapse into one.
  const findings = [
    mkFinding("zap", "40018", "https://app/", "dast", "high"),
    mkFinding("zap", "10038", "https://app/", "dast", "medium"),
  ];
  const merged = dedupeFindings(findings);
  assert.equal(merged.length, 2);
});

test("dedupe still merges the same location+category across DIFFERENT tools", () => {
  const findings = [
    mkFinding("trivy", "aws-key", "config.py", "secret", "critical", 4),
    mkFinding("gitleaks", "aws-access-token", "config.py", "secret", "high", 4),
  ];
  const merged = dedupeFindings(findings);
  assert.equal(merged.length, 1);
  assert.deepEqual(merged[0].sources.sort(), ["gitleaks", "trivy"]);
  assert.equal(merged[0].severity, "critical"); // keeps the most severe
});

test("detect finds polyglot manifests including a nested .csproj", () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "secsuite-detect-"));
  try {
    writeFileSync(path.join(dir, "go.mod"), "module x");
    writeFileSync(path.join(dir, "pom.xml"), "<project/>");
    mkdirSync(path.join(dir, "src", "App"), { recursive: true });
    writeFileSync(path.join(dir, "src", "App", "App.csproj"), "<Project/>");
    const stack = detectStack(dir);
    assert.ok(stack.languages.includes("go"), "go detected");
    assert.ok(stack.languages.includes("java"), "java detected");
    assert.ok(stack.languages.includes("csharp"), "nested csproj detected");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
