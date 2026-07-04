#!/usr/bin/env node
import { Command } from "commander";
import { existsSync, statSync } from "node:fs";
import path from "node:path";
import { loadConfig, isIgnored } from "./config.js";
import { detectStack } from "./detect.js";
import { resolveScanners } from "./resolve.js";
import { runScanners } from "./run.js";
import { adaptSemgrep } from "./adapters/semgrep.js";
import { adaptTrivy } from "./adapters/trivy.js";
import { adaptGitleaks } from "./adapters/gitleaks.js";
import { adaptZap } from "./adapters/zap.js";
import { runZapScan } from "./dast.js";
import { dedupeFindings } from "./dedupe.js";
import { printReport } from "./report.js";
import { Finding, Severity } from "./schema.js";

const program = new Command();

program
  .name("secsuite")
  .description("Detect your stack, run the right security scanners, get one clean report.");

program
  .command("scan")
  .description("Scan a directory and report findings.")
  .argument("[path]", "directory to scan", ".")
  .option("--severity <level>", "minimum severity to report (default: medium, or config's severity_threshold)")
  .option("--json <file>", "write full findings JSON to <file>")
  .option("--config <file>", "path to secsuite.yaml")
  .option("--static-only", "static analysis only (this is the only mode in v0)")
  .action(async (targetArg: string, opts) => {
    const targetDir = path.resolve(targetArg);

    if (!existsSync(targetDir) || !statSync(targetDir).isDirectory()) {
      console.error(`[secsuite] scan target is not a directory: ${targetDir}`);
      process.exitCode = 2;
      return;
    }

    const validSeverities: Severity[] = ["critical", "high", "medium", "low", "info"];
    if (opts.severity && !validSeverities.includes(opts.severity)) {
      console.error(`[secsuite] invalid --severity "${opts.severity}", expected one of ${validSeverities.join(", ")}`);
      process.exitCode = 2;
      return;
    }

    let config;
    try {
      config = loadConfig(opts.config, targetDir);
    } catch (err) {
      console.error(`[secsuite] ${(err as Error).message}`);
      process.exitCode = 2;
      return;
    }

    const stack = detectStack(targetDir);
    if (stack.languages.length === 0) {
      console.warn("[secsuite] no known language manifests found; running stack-agnostic scanners only.");
    } else {
      console.log(`[secsuite] detected: ${stack.languages.join(", ")}`);
    }

    const scanners = resolveScanners(stack);
    const runResults = await runScanners(scanners, targetDir, stack);

    if (runResults.every((r) => !r.ran)) {
      console.error("[secsuite] every scanner failed to run - nothing was actually scanned.");
      process.exitCode = 2;
      return;
    }

    const adapters: Record<string, (sarifPath: string, targetDir: string) => Finding[]> = {
      semgrep: adaptSemgrep,
      trivy: adaptTrivy,
      gitleaks: adaptGitleaks,
    };

    let findings: Finding[] = [];
    for (const result of runResults) {
      if (!result.ran || !result.sarifPath) continue;
      findings.push(...adapters[result.tool](result.sarifPath, targetDir));
    }

    findings = findings.filter((f) => !isIgnored(f.location.file, config.ignore.paths));
    findings = dedupeFindings(findings);

    const threshold = (opts.severity as Severity | undefined) ?? config.severityThreshold;
    const shown = printReport(findings, threshold, opts.json);

    process.exitCode = shown.length > 0 ? 1 : 0;
  });

program
  .command("dast")
  .description("Dynamic scan of a running app URL with OWASP ZAP (pre-prod / runtime lane).")
  .argument("<url>", "target URL, e.g. https://staging.example.com")
  .option("--full", "active scan (sends attack payloads - authorized targets only)")
  .option("--severity <level>", "minimum severity to report (default: medium)")
  .option("--json <file>", "write full findings JSON to <file>")
  .action(async (target: string, opts) => {
    if (!/^https?:\/\//i.test(target)) {
      console.error(`[secsuite] dast target must be an http(s) URL, got: ${target}`);
      process.exitCode = 2;
      return;
    }

    const validSeverities: Severity[] = ["critical", "high", "medium", "low", "info"];
    if (opts.severity && !validSeverities.includes(opts.severity)) {
      console.error(`[secsuite] invalid --severity "${opts.severity}", expected one of ${validSeverities.join(", ")}`);
      process.exitCode = 2;
      return;
    }

    const result = await runZapScan(target, { full: opts.full });
    if (!result.ran || !result.reportPath) {
      console.error("[secsuite] DAST scan did not run - nothing was scanned.");
      process.exitCode = 2;
      return;
    }

    const findings = dedupeFindings(adaptZap(result.reportPath, target));
    const threshold = (opts.severity as Severity | undefined) ?? "medium";
    const shown = printReport(findings, threshold, opts.json);

    process.exitCode = shown.length > 0 ? 1 : 0;
  });

program.parseAsync(process.argv);
