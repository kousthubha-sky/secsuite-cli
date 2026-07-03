import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { parse as parseYaml } from "yaml";
import { Config, DEFAULT_CONFIG, Severity } from "./schema.js";

interface RawConfig {
  version?: number;
  scan?: { static?: boolean };
  severity_threshold?: Severity;
  ignore?: { paths?: string[] };
}

export function loadConfig(configPath: string | undefined, targetDir: string): Config {
  const resolvedPath = configPath ?? path.join(targetDir, "secsuite.yaml");
  if (!existsSync(resolvedPath)) {
    // An explicit --config path that doesn't exist is a user error; the
    // implicit default location is optional and silently falls back.
    if (configPath) throw new Error(`Config file not found: ${configPath}`);
    return DEFAULT_CONFIG;
  }

  const raw = parseYaml(readFileSync(resolvedPath, "utf8")) as RawConfig | null;
  if (!raw) return DEFAULT_CONFIG;

  return {
    severityThreshold: raw.severity_threshold ?? DEFAULT_CONFIG.severityThreshold,
    ignore: { paths: raw.ignore?.paths ?? DEFAULT_CONFIG.ignore.paths },
  };
}

export function isIgnored(relFile: string, ignorePaths: string[]): boolean {
  const normalized = relFile.split(path.sep).join("/");
  return ignorePaths.some((pattern) => {
    // "dir/" means "everything under dir" - turn into a recursive glob.
    const glob = pattern.endsWith("/") ? `${pattern}**` : pattern;
    return path.matchesGlob(normalized, glob);
  });
}
