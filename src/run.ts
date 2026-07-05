import { execa } from "execa";
import { mkdtempSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { ToolName } from "./schema.js";
import { StackInfo } from "./detect.js";

export interface ToolRunResult {
  tool: ToolName;
  ran: boolean;
  sarifPath?: string;
  error?: string;
}

async function isAvailable(bin: string): Promise<boolean> {
  const res = await execa(bin, ["--version"], { reject: false });
  return res.exitCode === 0;
}

function buildCommand(tool: ToolName, targetDir: string, sarifPath: string, stack: StackInfo) {
  switch (tool) {
    case "semgrep":
      return {
        command: "semgrep",
        args: ["scan", "--config", "auto", "--sarif", "--output", sarifPath, targetDir],
      };
    case "trivy":
      return {
        command: "trivy",
        args: ["fs", "--scanners", "vuln,misconfig,secret", "--format", "sarif", "--output", sarifPath, targetDir],
      };
    case "gitleaks": {
      const args = ["detect", "--source", targetDir, "--report-format", "sarif", "--report-path", sarifPath];
      if (!stack.isGit) args.push("--no-git");
      return { command: "gitleaks", args };
    }
    default:
      // zap is a DAST tool driven by src/dast.ts, never the static runner.
      throw new Error(`buildCommand: ${tool} is not a static scanner`);
  }
}

// Live progress so a long scan never looks stuck. Everything goes to stderr
// (stdout is reserved for the report). On a TTY a single line ticks with
// elapsed time and what is still running; in CI it degrades to plain
// start/finish lines.
function startProgress(tools: ToolName[]) {
  const pending = new Set<ToolName>(tools);
  const started = Date.now();
  const isTTY = process.stderr.isTTY === true;
  console.error(`[secsuite] running: ${tools.join(", ")}`);

  const clearLine = () => {
    if (isTTY) process.stderr.write("\r\x1b[2K");
  };
  const timer = isTTY
    ? setInterval(() => {
        const secs = Math.round((Date.now() - started) / 1000);
        process.stderr.write(`\r[secsuite] scanning... ${secs}s (waiting on: ${[...pending].join(", ")})`);
      }, 1000)
    : undefined;

  return {
    done(tool: ToolName, ran: boolean) {
      pending.delete(tool);
      clearLine();
      const secs = ((Date.now() - started) / 1000).toFixed(1);
      console.error(`[secsuite] ${tool} ${ran ? "finished" : "skipped"} (${secs}s)`);
    },
    stop() {
      if (timer) clearInterval(timer);
      clearLine();
    },
  };
}

export async function runScanners(
  scanners: ToolName[],
  targetDir: string,
  stack: StackInfo
): Promise<ToolRunResult[]> {
  const tmpDir = mkdtempSync(path.join(tmpdir(), "secsuite-"));
  const progress = startProgress(scanners);

  // Scanners are independent processes; run them concurrently. Promise.all
  // preserves input order. Each task buffers its own log lines and flushes
  // them on completion so concurrent output never interleaves mid-message.
  try {
    return await Promise.all(
      scanners.map(async (tool): Promise<ToolRunResult> => {
        const log: string[] = [];
        const result = await runOne(tool, targetDir, stack, tmpDir, log);
        progress.done(tool, result.ran);
        for (const line of log) console.warn(line);
        return result;
      })
    );
  } finally {
    progress.stop();
  }
}

async function runOne(
  tool: ToolName,
  targetDir: string,
  stack: StackInfo,
  tmpDir: string,
  log: string[]
): Promise<ToolRunResult> {
  if (!(await isAvailable(tool))) {
    log.push(`[secsuite] ${tool} not found on PATH, skipping.`);
    return { tool, ran: false, error: "not found on PATH" };
  }

  const sarifPath = path.join(tmpDir, `${tool}.sarif`);
  const { command, args } = buildCommand(tool, targetDir, sarifPath, stack);
  // Semgrep is a Python tool that writes SARIF using the OS default
  // codepage unless told otherwise; on Windows that's cp1252, which
  // crashes on non-Latin-1 characters that show up in community rule
  // metadata (e.g. emoji). Force UTF-8 so the SARIF write can't fail.
  const env = tool === "semgrep" ? { ...process.env, PYTHONUTF8: "1" } : undefined;
  const res = await execa(command, args, { reject: false, cwd: targetDir, env });

  // These tools use a nonzero exit code to mean "findings were found", not
  // "the tool crashed" - trust the SARIF file over the exit code.
  if (existsSync(sarifPath)) {
    try {
      JSON.parse(readFileSync(sarifPath, "utf8"));
      return { tool, ran: true, sarifPath };
    } catch {
      // unparseable output falls through to the execution-error path below
    }
  }

  log.push(`[secsuite] ${tool} failed to run (exit ${res.exitCode}). ${(res.stderr ?? "").slice(0, 300)}`);
  return { tool, ran: false, error: `execution error (exit ${res.exitCode})` };
}
