import { existsSync } from "node:fs";
import path from "node:path";

export interface StackInfo {
  js: boolean;
  py: boolean;
  isGit: boolean;
}

const JS_MANIFESTS = ["package.json", "tsconfig.json"];
const PY_MANIFESTS = ["pyproject.toml", "requirements.txt", "setup.py", "Pipfile"];

export function detectStack(targetDir: string): StackInfo {
  const has = (files: string[]) => files.some((f) => existsSync(path.join(targetDir, f)));
  return {
    js: has(JS_MANIFESTS),
    py: has(PY_MANIFESTS),
    isGit: existsSync(path.join(targetDir, ".git")),
  };
}
