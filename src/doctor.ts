import { execa } from "execa";
import { detectStack } from "./detect.js";

interface CheckResult {
  name: string;
  ok: boolean;
  detail: string;
  hint?: string;
}

const HINTS: Record<string, Record<"win32" | "darwin" | "linux", string>> = {
  semgrep: {
    win32: "pipx install semgrep",
    darwin: "brew install semgrep",
    linux: "pipx install semgrep",
  },
  trivy: {
    win32: "winget install AquaSecurity.Trivy",
    darwin: "brew install trivy",
    linux: "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin",
  },
  gitleaks: {
    win32: "winget install Gitleaks.Gitleaks",
    darwin: "brew install gitleaks",
    linux: "download from https://github.com/gitleaks/gitleaks/releases",
  },
  docker: {
    win32: "install Docker Desktop and start it",
    darwin: "install Docker Desktop and start it",
    linux: "https://docs.docker.com/engine/install/",
  },
};

function hintFor(name: string): string | undefined {
  const h = HINTS[name];
  if (!h) return undefined;
  const key = process.platform === "win32" ? "win32" : process.platform === "darwin" ? "darwin" : "linux";
  return h[key];
}

export function checkNode(versionString: string = process.versions.node): CheckResult {
  const [major, minor] = versionString.split(".").map(Number);
  const ok = major > 22 || (major === 22 && minor >= 5);
  return { name: "node", ok, detail: `v${versionString}${ok ? "" : " (need >=22.5)"}` };
}

async function checkBinary(name: string, args: string[]): Promise<CheckResult> {
  const res = await execa(name, args, { reject: false });
  if (res.exitCode === 0) {
    const firstLine = (res.stdout || res.stderr || "").split("\n")[0].trim();
    return { name, ok: true, detail: firstLine || "found" };
  }
  return { name, ok: false, detail: "not found on PATH", hint: hintFor(name) };
}

export async function runDoctor(): Promise<void> {
  const checks: CheckResult[] = [
    checkNode(),
    // `docker info` (not --version) is deliberate: it fails when the daemon
    // is installed but not running, which is the failure users actually hit.
    ...(await Promise.all([
      checkBinary("semgrep", ["--version"]),
      checkBinary("trivy", ["--version"]),
      // gitleaks has no --version flag, only a `version` subcommand
      checkBinary("gitleaks", ["version"]),
      checkBinary("docker", ["info"]),
    ])),
  ];

  console.log("secsuite doctor\n");
  for (const c of checks) {
    console.log(`  ${(c.ok ? "ok" : "MISSING").padEnd(8)} ${c.name.padEnd(9)} ${c.detail}`);
    if (!c.ok && c.hint) console.log(`${" ".repeat(11)}install: ${c.hint}`);
  }
  console.log("\nMissing static scanners are skipped at scan time; docker is only needed for 'secsuite dast'.");
}

// AXI content-first: bare `secsuite` shows live state, not help text.
export async function runStatus(version: string): Promise<void> {
  const stack = detectStack(process.cwd());
  const scanners = await Promise.all([
    checkBinary("semgrep", ["--version"]),
    checkBinary("trivy", ["--version"]),
    checkBinary("gitleaks", ["version"]),
  ]);

  console.log(`secsuite ${version} - stack-aware security scans`);
  console.log(`detected here: ${stack.languages.length > 0 ? stack.languages.join(", ") : "no known manifests"}`);
  console.log(`scanners: ${scanners.map((s) => `${s.name} ${s.ok ? "ok" : "MISSING"}`).join(", ")}`);
  console.log("");
  console.log("  secsuite scan .          static scan (SAST + SCA + secrets + IaC)");
  console.log("  secsuite dast <url>      dynamic scan of a running app (needs Docker)");
  console.log("  secsuite baseline .      accept current findings, gate on new only");
  console.log("  secsuite doctor          full environment check with install hints");
}
