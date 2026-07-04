import { existsSync, readdirSync } from "node:fs";
import path from "node:path";

export interface StackInfo {
  languages: string[]; // detected language/ecosystem keys, e.g. ["java", "go"]
  isGit: boolean;
}

// Manifest files that mark a language/ecosystem. Semgrep's `--config auto` and
// trivy both have rules for all of these, so detecting any one is enough to run
// the SAST lane. Covers the six languages behind ~80% of new repos (GitHub
// Octoverse 2025) plus Go/Rust/PHP/Ruby.
const MANIFESTS: Record<string, string[]> = {
  js: ["package.json", "tsconfig.json"],
  python: ["pyproject.toml", "requirements.txt", "setup.py", "Pipfile"],
  java: ["pom.xml", "build.gradle", "build.gradle.kts"], // incl. Spring / J2EE
  go: ["go.mod"],
  rust: ["Cargo.toml"],
  php: ["composer.json"],
  ruby: ["Gemfile"],
};

// Languages keyed off a file extension rather than a fixed manifest name
// (a .NET repo has an arbitrarily-named .csproj/.sln, not a fixed filename).
// These are matched against a shallow directory walk, since a .csproj usually
// lives in a nested project folder (src/Foo/Foo.csproj), not the repo root.
const EXTENSIONS: Record<string, RegExp> = {
  csharp: /\.(csproj|sln)$/i, // .NET / ASP.NET Core
};

// Directories not worth walking when looking for project files.
const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", "bin", "obj", ".venv", "venv",
  "vendor", "target", ".idea", ".vs",
]);

const WALK_DEPTH = 2; // root + 2 levels catches src/Foo/Foo.csproj

export function detectStack(targetDir: string): StackInfo {
  const has = (files: string[]) => files.some((f) => existsSync(path.join(targetDir, f)));
  const languages: string[] = [];

  for (const [lang, files] of Object.entries(MANIFESTS)) {
    if (has(files)) languages.push(lang);
  }

  const names = walkShallow(targetDir, WALK_DEPTH);
  for (const [lang, re] of Object.entries(EXTENSIONS)) {
    if (names.some((n) => re.test(n))) languages.push(lang);
  }

  return { languages, isGit: existsSync(path.join(targetDir, ".git")) };
}

// Collect file/dir names from targetDir down to maxDepth, skipping vendored and
// build directories. Names only (not full paths) - callers just extension-match.
function walkShallow(dir: string, maxDepth: number): string[] {
  const names: string[] = [];
  const visit = (d: string, depth: number) => {
    let entries;
    try {
      entries = readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      names.push(e.name);
      if (e.isDirectory() && depth < maxDepth && !SKIP_DIRS.has(e.name)) {
        visit(path.join(d, e.name), depth + 1);
      }
    }
  };
  visit(dir, 0);
  return names;
}
