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
      // dependency dirs (in-repo installs; deps themselves are CVE-checked
      // via lockfiles regardless of these ignores)
      "node_modules/",
      ".venv/",
      "venv/",
      "vendor/",
      "Pods/",
      "deps/",
      // build output - generated files trip SAST/secret rules constantly
      // (e.g. webpack eval() shims, Next.js action hashes) and their real
      // source is scanned anyway. Covers JS, Rust/Maven (target/), .NET
      // (obj/), Elixir (_build/), Flutter (.dart_tool/), Gradle, Terraform.
      ".next/",
      ".nuxt/",
      "dist/",
      "build/",
      "out/",
      "target/",
      "coverage/",
      "__pycache__/",
      ".gradle/",
      "obj/",
      "_build/",
      ".dart_tool/",
      ".terraform/",
    ],
  },
};
