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
  }
}

export async function runScanners(
  scanners: ToolName[],
  targetDir: string,
  stack: StackInfo
): Promise<ToolRunResult[]> {
  const tmpDir = mkdtempSync(path.join(tmpdir(), "secsuite-"));
  const results: ToolRunResult[] = [];

  for (const tool of scanners) {
    const available = await isAvailable(tool);
    if (!available) {
      console.warn(`[secsuite] ${tool} not found on PATH, skipping.`);
      results.push({ tool, ran: false, error: "not found on PATH" });
      continue;
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
        results.push({ tool, ran: true, sarifPath });
        continue;
      } catch {
        // unparseable output falls through to the execution-error path below
      }
    }

    console.warn(
      `[secsuite] ${tool} failed to run (exit ${res.exitCode}). ${(res.stderr ?? "").slice(0, 300)}`
    );
    results.push({ tool, ran: false, error: `execution error (exit ${res.exitCode})` });
  }

  return results;
}
