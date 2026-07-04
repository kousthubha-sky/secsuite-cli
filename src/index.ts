#!/usr/bin/env node
import { Command } from "commander";
import { existsSync, statSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { findingsToSarif } from "./sarif-export.js";
import { loadConfig } from "./config.js";
import { runStaticPipeline } from "./pipeline.js";
import { adaptZap } from "./adapters/zap.js";
import { runZapScan } from "./dast.js";
import { dedupeFindings } from "./dedupe.js";
import { printReport } from "./report.js";
import { Finding, Severity } from "./schema.js";

// dist/src/index.js -> ../../package.json is the package root at runtime.
const VERSION = (
  JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as { version: string }
).version;

const program = new Command();

program
  .name("secsuite")
  .version(VERSION)
  .description("Detect your stack, run the right security scanners, get one clean report.");

program
  .command("scan")
  .description("Scan a directory and report findings.")
  .argument("[path]", "directory to scan", ".")
  .option("--severity <level>", "minimum severity to report (default: medium, or config's severity_threshold)")
  .option("--json <file>", "write full findings JSON to <file>")
  .option("--sarif <file>", "write merged findings as SARIF 2.1.0 to <file> (for GitHub Code Scanning)")
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

    const { findings, anyRan } = await runStaticPipeline(targetDir, config);
    if (!anyRan) {
      console.error("[secsuite] every scanner failed to run - nothing was actually scanned.");
      process.exitCode = 2;
      return;
    }

    const threshold = (opts.severity as Severity | undefined) ?? config.severityThreshold;
    const shown = printReport(findings, threshold, opts.json);

    if (opts.sarif) {
      try {
        writeFileSync(opts.sarif, JSON.stringify(findingsToSarif(findings, VERSION), null, 2));
        console.log(`SARIF written to ${opts.sarif}`);
      } catch (err) {
        console.error(`[secsuite] failed to write SARIF: ${(err as Error).message}`);
        process.exitCode = 2;
        return;
      }
    }

    process.exitCode = shown.length > 0 ? 1 : 0;
  });

program
  .command("dast")
  .description("Dynamic scan of a running app URL with OWASP ZAP (pre-prod / runtime lane).")
  .argument("<url>", "target URL, e.g. https://staging.example.com")
  .option("--full", "active scan (sends attack payloads - authorized targets only)")
  .option("--severity <level>", "minimum severity to report (default: medium)")
  .option("--json <file>", "write full findings JSON to <file>")
  .option("--sarif <file>", "write merged findings as SARIF 2.1.0 to <file> (for GitHub Code Scanning)")
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

    if (opts.sarif) {
      try {
        writeFileSync(opts.sarif, JSON.stringify(findingsToSarif(findings, VERSION), null, 2));
        console.log(`SARIF written to ${opts.sarif}`);
      } catch (err) {
        console.error(`[secsuite] failed to write SARIF: ${(err as Error).message}`);
        process.exitCode = 2;
        return;
      }
    }

    process.exitCode = shown.length > 0 ? 1 : 0;
  });

program.parseAsync(process.argv);
