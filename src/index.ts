#!/usr/bin/env node
import { Command } from "commander";
import { existsSync, statSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { findingsToSarif } from "./sarif-export.js";
import { loadConfig } from "./config.js";
import { runStaticPipeline } from "./pipeline.js";
import { writeBaseline, loadBaselineIds, splitByBaseline, BASELINE_FILENAME } from "./baseline.js";
import { runDoctor, runStatus } from "./doctor.js";
import { adaptZap } from "./adapters/zap.js";
import { runZapScan } from "./dast.js";
import { dedupeFindings } from "./dedupe.js";
import { printReport, stripRaw } from "./report.js";
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
  .option("--baseline <file>", `baseline file (default: <path>/${BASELINE_FILENAME} when present)`)
  .option("--no-baseline", "ignore any baseline file")
  .option("--raw", "include each finding's raw scanner payload in --json output")
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

    const { findings, anyRan, skipped } = await runStaticPipeline(targetDir, config);
    if (!anyRan) {
      console.error("[secsuite] every scanner failed to run - nothing was actually scanned.");
      process.exitCode = 2;
      return;
    }

    let baselineIds: Set<string> | undefined;
    if (opts.baseline !== false) {
      const baselinePath =
        typeof opts.baseline === "string" ? path.resolve(opts.baseline) : path.join(targetDir, BASELINE_FILENAME);
      baselineIds = loadBaselineIds(baselinePath);
    }
    const { fresh, baselined } = splitByBaseline(findings, baselineIds);

    // JSON and SARIF always carry everything; only the gate and the console
    // report are filtered to fresh findings.
    const jsonFindings = [...fresh, ...baselined.map((f) => ({ ...f, baselined: true as const }))];

    const threshold = (opts.severity as Severity | undefined) ?? config.severityThreshold;
    const shown = printReport(
      fresh,
      threshold,
      opts.json,
      opts.raw ? jsonFindings : stripRaw(jsonFindings as Finding[])
    );

    // Human-mode extras; `--json -` keeps stdout machine-clean.
    if (opts.json !== "-") {
      if (baselined.length > 0) {
        console.log(`${baselined.length} baselined finding(s) suppressed (accepted in ${BASELINE_FILENAME}).`);
      }
      if (shown.length > 0 && baselineIds === undefined && opts.baseline !== false) {
        console.log(`help: secsuite baseline ${targetArg}  # accept these once, gate only on new findings`);
      }
      if (skipped.length > 0) {
        console.log(`help: secsuite doctor  # skipped: ${skipped.join(", ")}`);
      }
    }

    if (opts.sarif) {
      try {
        writeFileSync(opts.sarif, JSON.stringify(findingsToSarif(jsonFindings, VERSION), null, 2));
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
  .command("baseline")
  .description("Accept all current findings; future scans gate only on NEW findings.")
  .argument("[path]", "directory to scan", ".")
  .option("--config <file>", "path to secsuite.yaml")
  .action(async (targetArg: string, opts) => {
    const targetDir = path.resolve(targetArg);
    if (!existsSync(targetDir) || !statSync(targetDir).isDirectory()) {
      console.error(`[secsuite] baseline target is not a directory: ${targetDir}`);
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
      console.error("[secsuite] every scanner failed to run - refusing to write an empty baseline.");
      process.exitCode = 2;
      return;
    }

    const baselinePath = path.join(targetDir, BASELINE_FILENAME);
    writeBaseline(baselinePath, findings);
    console.log(
      `[secsuite] baseline written: ${findings.length} finding(s) accepted in ${baselinePath}.\n` +
        `Commit this file; \`secsuite scan\` now reports only new findings. Line shifts re-surface a finding as new.`
    );
  });

program
  .command("doctor")
  .description("Check that Node, the scanners, and Docker are installed and visible.")
  .action(async () => {
    await runDoctor();
  });

program
  .command("dast")
  .description("Dynamic scan of a running app URL with OWASP ZAP (pre-prod / runtime lane).")
  .argument("<url>", "target URL, e.g. https://staging.example.com")
  .option("--full", "active scan (sends attack payloads - authorized targets only)")
  .option("--severity <level>", "minimum severity to report (default: medium)")
  .option("--json <file>", "write full findings JSON to <file>")
  .option("--sarif <file>", "write merged findings as SARIF 2.1.0 to <file> (for GitHub Code Scanning)")
  .option("--raw", "include each finding's raw scanner payload in --json output")
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
    const shown = printReport(findings, threshold, opts.json, opts.raw ? findings : stripRaw(findings));

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

// AXI content-first: bare `secsuite` shows live status instead of help text.
program.action(async () => {
  await runStatus(VERSION);
});

program.exitOverride();
try {
  await program.parseAsync(process.argv);
} catch (err) {
  // Commander throws for --help/--version (exitCode 0) and usage errors
  // alike; map bad flags to 2 so agents never read "unknown option" as
  // "findings found" (exit 1).
  const code = (err as { exitCode?: number }).exitCode ?? 2;
  process.exit(code === 0 ? 0 : 2);
}
