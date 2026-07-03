# secsuite

One command to run the right security checks for your stack, with one clean report.

`secsuite` detects your project's tech stack, runs the appropriate open-source
security scanners, and merges their results into a single normalized,
deduplicated report - readable in your terminal, and machine-readable as JSON
for CI.

This is a defensive DevSecOps orchestration layer: it contains no exploit or
attack code of its own.
It detects and shells out to existing, well-established open-source scanners
and unifies their output.

## v0 scope

This release covers a single lane: a repo containing JavaScript/TypeScript
and/or Python, scanned statically (no live/domain scanning, no OSINT, no
plugin marketplace yet).
The pipeline is: detect stack -> resolve scanners -> run them -> normalize
output -> deduplicate -> report.

## Prerequisites

`secsuite` does not bundle any scanner - it detects and shells out to
binaries already on your `PATH`.
Install the ones you want it to use; any that are missing are skipped with a
warning, not a hard failure.

| Tool | Purpose | License | Install |
|---|---|---|---|
| [Semgrep](https://semgrep.dev/) | SAST | LGPL | `pip install semgrep` (or `pipx install semgrep`) |
| [Trivy](https://trivy.dev/) | SCA, IaC misconfig, secrets | Apache-2.0 | `winget install AquaSecurity.Trivy` / `brew install trivy` |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Secret detection (incl. git history) | MIT | `winget install Gitleaks.Gitleaks` / `brew install gitleaks` |

Node.js >= 22.5 is required to run `secsuite` itself.

## Install

```bash
npm install
npm run build
```

Or run directly without installing globally:

```bash
node dist/src/index.js scan <path>
```

## Usage

```bash
secsuite scan [path]        # path defaults to "."
```

### Flags

| Flag | Description | Default |
|---|---|---|
| `--severity <level>` | minimum severity to report (`critical`\|`high`\|`medium`\|`low`\|`info`) | `medium` |
| `--json <file>` | write full findings JSON (all severities) to `<file>` | - |
| `--config <file>` | path to `secsuite.yaml` | `<path>/secsuite.yaml` if present |
| `--static-only` | reserved; v0 only does static analysis anyway | - |

### Try it on the vulnerable fixture

A small intentionally-vulnerable fixture ships in `fixtures/vulnerable/` -
a SQL-injection / `eval()` sink, outdated npm and pip dependencies, a
misconfigured `Dockerfile`, and a fake hardcoded AWS key.
It exists purely to exercise the scanners; nothing in it is a real secret.

```bash
secsuite scan fixtures/vulnerable --json out.json
```

You should see grouped findings across SAST, SCA, secrets, and misconfig
categories, with the hardcoded key reported once with both `trivy` and
`gitleaks` listed under its `sources` (deduplication in action).

## Configuration

Optional, and entirely defaults-driven if absent. Drop a `secsuite.yaml` in
your repo root:

```yaml
version: 1
scan:
  static: true
severity_threshold: medium
ignore:
  paths: ["tests/", "**/migrations/**", "node_modules/", ".venv/"]
```

## Exit codes (CI-friendly)

| Code | Meaning |
|---|---|
| `0` | no findings at or above `--severity` threshold |
| `1` | findings at or above the threshold |
| `2` | execution error (bad target path, bad config, or every scanner failed to run) |

A tool exiting non-zero because it *found something* (which is how Semgrep,
Trivy, and Gitleaks normally signal findings) is not treated as an execution
error - `secsuite` distinguishes "the scanner ran and found issues" from
"the scanner failed to run" by checking whether it produced valid SARIF
output.

## How findings are normalized

Every scanner's SARIF output is mapped into one shape:

```ts
interface Finding {
  id: string;            // stable hash of tool + ruleId + file + startLine
  tool: string;           // "semgrep" | "trivy" | "gitleaks"
  category: string;       // "sast" | "sca" | "secret" | "iac" | "misconfig"
  ruleId: string;
  severity: string;       // "critical" | "high" | "medium" | "low" | "info"
  title: string;
  description: string;
  location: { file: string; startLine?: number; endLine?: number };
  remediation?: string;
  references?: string[];
  sources: string[];      // which tools reported this finding
  raw: unknown;            // the original tool finding, untouched
}
```

Two findings are treated as duplicates when they share the same file,
start line, and normalized category; when that happens, the finding is kept
once with every reporting tool listed in `sources`.

## Project structure

```
src/
  index.ts        CLI entry (commander)
  detect.ts        stack detection from manifest files
  resolve.ts        stack -> scanner list
  run.ts             scanner spawn wrappers, PATH checks, SARIF collection
  adapters/          per-tool SARIF -> Finding[]
  config.ts          secsuite.yaml loading + ignore-path filtering
  dedupe.ts          deduplication
  report.ts          console + JSON reporting
  schema.ts          Finding + Config types
fixtures/vulnerable/  intentionally-vulnerable sample repo
test/                 node:test suite over checked-in sample SARIF files
```
