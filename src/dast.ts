import { execa } from "execa";
import { mkdtempSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

export interface DastRunResult {
  ran: boolean;
  reportPath?: string;
  error?: string;
}

// Official OWASP ZAP image (the old owasp/zap2docker-stable is deprecated).
const ZAP_IMAGE = "zaproxy/zap-stable";

async function dockerAvailable(): Promise<boolean> {
  const res = await execa("docker", ["info"], { reject: false });
  return res.exitCode === 0;
}

// ZAP runs headless from its Docker image. baseline = spider + passive rules
// (safe, non-attacking). full = active scan that sends real attack payloads,
// so it must only ever be pointed at a target you are authorized to test.
export async function runZapScan(
  target: string,
  opts: { full?: boolean } = {}
): Promise<DastRunResult> {
  if (!(await dockerAvailable())) {
    console.warn("[secsuite] docker not available - the DAST lane needs Docker running. Skipping.");
    return { ran: false, error: "docker not available" };
  }

  const outDir = mkdtempSync(path.join(tmpdir(), "secsuite-dast-"));
  const reportName = "report.json";
  const script = opts.full ? "zap-full-scan.py" : "zap-baseline.py";

  if (opts.full) {
    console.warn(`[secsuite] running ZAP ACTIVE scan against ${target} - only do this on targets you are authorized to test.`);
  }

  // Mount the host out-dir at ZAP's working dir so the report lands on the host.
  // Docker's `-v` splits on ':', and a Windows path (C:\Users\...) has both a
  // drive colon and backslashes; Docker Desktop accepts a forward-slashed path
  // (C:/Users/...), so normalize separators. Omit the ":rw" mode (rw is the
  // default) to keep one fewer colon in the argument.
  const mountSrc = outDir.replace(/\\/g, "/");
  const args = [
    "run", "--rm",
    "-v", `${mountSrc}:/zap/wrk`,
    "-t", ZAP_IMAGE,
    script, "-t", target, "-J", reportName,
  ];

  // stderr, not stdout: stdout is reserved for the report (or `--json -`).
  console.error(`[secsuite] starting ZAP (${script}) against ${target} - first run pulls the image, this can take a few minutes.`);

  // Elapsed ticker (TTY only) so a minutes-long ZAP run never looks stuck.
  const started = Date.now();
  const isTTY = process.stderr.isTTY === true;
  const timer = isTTY
    ? setInterval(() => {
        process.stderr.write(`\r[secsuite] ZAP running... ${Math.round((Date.now() - started) / 1000)}s`);
      }, 1000)
    : undefined;

  let res;
  try {
    res = await execa("docker", args, { reject: false });
  } finally {
    if (timer) clearInterval(timer);
    if (isTTY) process.stderr.write("\r\x1b[2K");
    console.error(`[secsuite] ZAP finished (${((Date.now() - started) / 1000).toFixed(1)}s)`);
  }

  // ZAP exits nonzero when it finds issues (1) or fails (2/3); trust the report
  // file over the exit code, same as the static scanners.
  const reportPath = path.join(outDir, reportName);
  if (existsSync(reportPath)) {
    return { ran: true, reportPath };
  }

  console.warn(`[secsuite] ZAP produced no report (exit ${res.exitCode}). ${(res.stderr ?? "").slice(0, 300)}`);
  return { ran: false, error: `zap execution error (exit ${res.exitCode})` };
}
