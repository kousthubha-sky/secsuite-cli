import { ToolName } from "./schema.js";
import { StackInfo } from "./detect.js";

// Semgrep needs a recognized language to be useful; trivy and gitleaks are
// stack-agnostic (SCA/secrets/misconfig apply to any repo), so they always run.
export function resolveScanners(stack: StackInfo): ToolName[] {
  const scanners: ToolName[] = [];
  if (stack.js || stack.py) scanners.push("semgrep");
  scanners.push("trivy", "gitleaks");
  return scanners;
}
