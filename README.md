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

## Application-protection lanes

`secsuite` maps onto the stages where you actually catch problems, from source
code through to a running app:

| Stage | Lane | What runs | Command |
|---|---|---|---|
| Build | Secure code review (SAST) | Semgrep | `secsuite scan` |
| Test | Software composition (SCA) + secrets + IaC misconfig | Trivy, Gitleaks | `secsuite scan` |
| Pre-prod | Automated OWASP pentest (DAST) | OWASP ZAP baseline | `secsuite dast <staging-url>` |
| Runtime | Live dynamic scan (DAST) | OWASP ZAP full / Burp\* | `secsuite dast <url> --full` |

\* Burp Suite is commercial and has no free headless API; see
[Runtime / Burp](#runtime--burp) below. ZAP covers both the pre-prod and
runtime lanes out of the box.

**Static lanes** (`scan`) work on any of the major stacks: JavaScript/TypeScript,
Python, Java/Kotlin (incl. Spring / J2EE), C#/.NET, Go, Rust, PHP, and Ruby.
Trivy and Gitleaks are language-agnostic; Semgrep's `--config auto` picks rules
per detected language. The static pipeline is: detect stack -> resolve scanners
-> run them -> normalize output -> deduplicate -> report.

**Dynamic lane** (`dast`) scans a running app over HTTP instead of a directory.

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
| [OWASP ZAP](https://www.zaproxy.org/) (via Docker) | DAST (`dast` command only) | Apache-2.0 | needs [Docker](https://www.docker.com/); image auto-pulls on first `dast` run |

Node.js >= 22.5 is required to run `secsuite` itself. The `dast` command
additionally needs Docker running (it pulls and runs the official
`zaproxy/zap-stable` image); the static `scan` command does not.

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
| `--static-only` | reserved; the `scan` command only does static analysis | - |

### Dynamic scanning (pre-prod / runtime)

```bash
secsuite dast https://staging.example.com          # ZAP baseline (passive, safe)
secsuite dast https://staging.example.com --full   # ZAP active scan (sends payloads)
```

The `dast` command runs OWASP ZAP against a running app and folds its findings
into the same normalized report (category `dast`, tool `zap`). The default
**baseline** scan is passive - it spiders the app and applies passive rules, so
it does not attack the target. `--full` runs an **active** scan that sends real
attack payloads and mutates state, so only ever point it at a target you are
authorized to test (staging or a prod mirror, not live production).

| Flag | Description | Default |
|---|---|---|
| `--full` | active scan (attack payloads - authorized targets only) | passive baseline |
| `--severity <level>` | minimum severity to report | `medium` |
| `--json <file>` | write full findings JSON to `<file>` | - |

<a name="runtime--burp"></a>
#### Runtime / Burp

Burp Suite Professional has no headless automation API, and Burp Suite
Enterprise/DAST (which does, via a GraphQL API) is a paid product. Rather than
ship code that can't be run or tested without a commercial licence, `secsuite`
uses ZAP for the runtime lane too - point `secsuite dast --full` at your running
app. If your organisation already owns Burp Enterprise, its scan export drops
into the same adapter interface as `adapters/zap.ts` (parse the tool's JSON into
`Finding[]`); that adapter is the intended extension point.

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
  tool: string;           // "semgrep" | "trivy" | "gitleaks" | "zap"
  category: string;       // "sast" | "sca" | "secret" | "iac" | "misconfig" | "dast"
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

Two findings are treated as duplicates only when **different tools** report the
same file, start line, and normalized category - for example Trivy and Gitleaks
both flagging one hardcoded key. When that happens the finding is kept once with
every reporting tool listed in `sources`. Multiple findings from the *same* tool
at one location are kept separate, since they are distinct issues (several CVEs
on one dependency line, or several ZAP alerts on one URL).

## Project structure

```
src/
  index.ts        CLI entry (commander)
  detect.ts        stack detection from manifest files (polyglot)
  resolve.ts        stack -> scanner list
  run.ts             static scanner spawn wrappers, PATH checks, SARIF collection
  dast.ts            OWASP ZAP runner (Docker) for the dynamic lane
  adapters/          per-tool output -> Finding[] (sarif.ts shared; zap.ts parses ZAP JSON)
  config.ts          secsuite.yaml loading + ignore-path filtering
  dedupe.ts          deduplication
  report.ts          console + JSON reporting
  schema.ts          Finding + Config types
fixtures/vulnerable/  intentionally-vulnerable sample repo
test/                 node:test suite over checked-in sample SARIF files
```
