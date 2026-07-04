import { detectStack } from "./detect.js";
import { resolveScanners } from "./resolve.js";
import { runScanners } from "./run.js";
import { adaptSemgrep } from "./adapters/semgrep.js";
import { adaptTrivy } from "./adapters/trivy.js";
import { adaptGitleaks } from "./adapters/gitleaks.js";
import { dedupeFindings } from "./dedupe.js";
import { isIgnored } from "./config.js";
import { Config, Finding, ToolName } from "./schema.js";

export interface PipelineResult {
  findings: Finding[];
  anyRan: boolean;
  skipped: ToolName[];
}

// The full static lane: detect -> resolve -> run -> adapt -> ignore-filter -> dedupe.
// Shared by `scan` and `baseline` so the two can never drift apart.
export async function runStaticPipeline(targetDir: string, config: Config): Promise<PipelineResult> {
  const stack = detectStack(targetDir);
  if (stack.languages.length === 0) {
    console.warn("[secsuite] no known language manifests found; running stack-agnostic scanners only.");
  } else {
    // stderr, not stdout: stdout is reserved for the report (or `--json -`).
    console.error(`[secsuite] detected: ${stack.languages.join(", ")}`);
  }

  const scanners = resolveScanners(stack);
  const runResults = await runScanners(scanners, targetDir, stack);
  if (runResults.every((r) => !r.ran)) {
    return { findings: [], anyRan: false, skipped: runResults.map((r) => r.tool) };
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
  return {
    findings: dedupeFindings(findings),
    anyRan: true,
    skipped: runResults.filter((r) => !r.ran).map((r) => r.tool),
  };
}
