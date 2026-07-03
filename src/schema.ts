export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

export type Category = "sast" | "sca" | "secret" | "iac" | "misconfig";

export type ToolName = "semgrep" | "trivy" | "gitleaks";

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
    paths: ["tests/", "**/migrations/**", "node_modules/", ".venv/"],
  },
};
