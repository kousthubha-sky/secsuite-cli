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
    if (!stack.js && !stack.py) {
      console.warn("[secsuite] no known JS/TS or Python manifests found; running stack-agnostic scanners only.");
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

program.parseAsync(process.argv);
