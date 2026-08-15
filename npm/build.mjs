#!/usr/bin/env node
// Generates the npm half of a release: one package per platform, each holding a
// single cross-compiled binary, plus the launcher's optionalDependencies map.
//
//   node npm/build.mjs 0.3.0
//
// This runs `go build` itself rather than reading GoReleaser's dist/ layout.
// Cross-compiling costs nothing, and the two halves of the release stay
// decoupled - GoReleaser can rename its output directories without breaking npm.
//
// Note: this rewrites the repo's package.json (version + optionalDependencies).
// In CI that is a throwaway checkout; running it locally will dirty your tree.

import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outDir = path.join(root, "npm", "packages");

const version = process.argv[2];
if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version ?? "")) {
  console.error(`usage: node npm/build.mjs <version>   (got: ${version ?? "nothing"})`);
  process.exit(2);
}

// The package names use npm's spellings (process.platform / process.arch), not
// Go's, so bin/secsuite.js can interpolate them directly with no lookup table.
//
// The scope is @secsuite-cli, not @secsuite: npm keeps org names and package
// names in one namespace, so the existing `secsuite` package blocks an org of
// the same name.
const targets = [
  { os: "linux", cpu: "x64", goos: "linux", goarch: "amd64" },
  { os: "linux", cpu: "arm64", goos: "linux", goarch: "arm64" },
  { os: "darwin", cpu: "x64", goos: "darwin", goarch: "amd64" },
  { os: "darwin", cpu: "arm64", goos: "darwin", goarch: "arm64" },
  { os: "win32", cpu: "x64", goos: "windows", goarch: "amd64" },
];

const rootPkgPath = path.join(root, "package.json");
const rootPkg = JSON.parse(readFileSync(rootPkgPath, "utf8"));

rmSync(outDir, { recursive: true, force: true });

const optionalDependencies = {};

for (const target of targets) {
  const name = `@secsuite-cli/${target.os}-${target.cpu}`;
  const dir = path.join(outDir, `${target.os}-${target.cpu}`);
  const binary = target.os === "win32" ? "secsuite.exe" : "secsuite";

  mkdirSync(dir, { recursive: true });

  execFileSync(
    "go",
    ["build", "-ldflags", `-s -w -X main.version=${version}`, "-o", path.join(dir, binary), "./cmd/secsuite"],
    {
      cwd: root,
      stdio: "inherit",
      env: { ...process.env, GOOS: target.goos, GOARCH: target.goarch, CGO_ENABLED: "0" },
    }
  );

  // npm carries the mode bits from the tarball. Without this the launcher finds
  // the file and then cannot execute it.
  chmodSync(path.join(dir, binary), 0o755);

  writeFileSync(
    path.join(dir, "package.json"),
    JSON.stringify(
      {
        name,
        version,
        description: `secsuite binary for ${target.os} ${target.cpu}`,
        license: rootPkg.license,
        repository: rootPkg.repository,
        // npm refuses to install this package anywhere else, which is exactly
        // what makes the launcher's optionalDependencies resolve to one of five.
        os: [target.os],
        cpu: [target.cpu],
        files: [binary],
        // Yarn Berry keeps packages zipped by default; a zipped binary is not
        // executable.
        preferUnplugged: true,
      },
      null,
      2
    ) + "\n"
  );

  optionalDependencies[name] = version;
  console.log(`built ${name}`);
}

rootPkg.version = version;
rootPkg.optionalDependencies = optionalDependencies;
writeFileSync(rootPkgPath, JSON.stringify(rootPkg, null, 2) + "\n");
console.log(`launcher pinned to ${version}`);
