export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

export type Category = "sast" | "sca" | "secret" | "iac" | "misconfig" | "dast";

export type ToolName = "semgrep" | "trivy" | "gitleaks" | "zap";

export interface Finding {
  id: string;
  tool: ToolName;
  category: Category;
  ruleId: string;
  severity: Severity;
  title: string;
  description: string;
  location: { file: string; startLine?: number; endLine?: number };
  remediation?: string;
  references?: string[];
  sources: string[];
  raw: unknown;
}

export interface Config {
  severityThreshold: Severity;
  ignore: { paths: string[] };
}

export const DEFAULT_CONFIG: Config = {
  severityThreshold: "medium",
  ignore: {
    paths: [
      "tests/",
      "**/migrations/**",
      // dependency dirs
      "node_modules/",
      ".venv/",
      "vendor/",
      // build output - generated bundles trip SAST/secret rules constantly
      // (e.g. webpack eval() shims, Next.js action hashes) and their real
      // source is scanned anyway
      ".next/",
      ".nuxt/",
      "dist/",
      "build/",
      "out/",
      "target/",
      "coverage/",
    ],
  },
};
