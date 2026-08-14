#!/usr/bin/env node
"use strict";
// The entire npm package. npm already installed exactly one of the five
// @secsuite/cli-* optionalDependencies - the one whose "os" and "cpu" fields
// match this machine - so the only job here is to find that binary and get out
// of the way. Node is the doorman, not the runtime.
const { spawnSync } = require("node:child_process");

const pkg = `@secsuite/cli-${process.platform}-${process.arch}`;
const binary = process.platform === "win32" ? "secsuite.exe" : "secsuite";

let bin;
try {
  bin = require.resolve(`${pkg}/${binary}`);
} catch {
  console.error(`[secsuite] no prebuilt binary for ${process.platform}-${process.arch}.`);
  console.error("[secsuite] build from source instead:");
  console.error("[secsuite]   go install github.com/kousthubha-sky/secsuite-cli/cmd/secsuite@latest");
  console.error("[secsuite] or ask for this platform: https://github.com/kousthubha-sky/secsuite-cli/issues");
  process.exit(2);
}

// Exit codes are the CLI contract - 0 clean, 1 findings, 2 error - and CI gates
// read them, so the child's code passes straight through. A signal death leaves
// status null; that is an error, never a clean scan.
const { status, error } = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
if (error) {
  console.error(`[secsuite] could not execute ${bin}: ${error.message}`);
  process.exit(2);
}
process.exit(status === null ? 2 : status);
