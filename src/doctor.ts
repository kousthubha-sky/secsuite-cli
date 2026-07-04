import { execa } from "execa";

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
      checkBinary("gitleaks", ["--version"]),
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
