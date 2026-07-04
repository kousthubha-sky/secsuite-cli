# secsuite

One command to run the right security checks for your stack, with one clean report.

[![npm version](https://img.shields.io/npm/v/secsuite)](https://www.npmjs.com/package/secsuite)
[![license: MIT](https://img.shields.io/npm/l/secsuite)](LICENSE)
[![node](https://img.shields.io/node/v/secsuite)](package.json)

`secsuite` detects your project's tech stack, runs the appropriate open-source
security scanners, and merges their results into a single normalized,
deduplicated report - readable in your terminal, and machine-readable as JSON
for CI.

This is a defensive DevSecOps orchestration layer: it contains no exploit or
attack code of its own.
It detects and shells out to existing, well-established open-source scanners
and unifies their output.

## Quick start

```bash
# scan the current project (needs the scanners on PATH - see Prerequisites)
npx secsuite scan .

# dynamic scan of a running app (needs Docker running)
npx secsuite dast https://staging.example.com
```

Or install it once: `npm i -g secsuite` (also works with `pnpm add -g secsuite`
/ `bun add -g secsuite`), then call `secsuite` directly.

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

Run `secsuite doctor` to check what is installed and get per-platform install
hints for anything missing.

## Install

### Docker (bundles all the static scanners)

The image ships `secsuite` with Semgrep, Trivy, and Gitleaks preinstalled, so
you don't install anything else. Mount the repo you want to scan:

```bash
docker build -t secsuite-cli .
docker run --rm -v "$PWD:/scan" secsuite-cli scan /scan
```

(The `dast` lane drives another Docker image, so running it *inside* this
container means docker-in-docker; for DAST, prefer the npm/local install below.)

### npm / npx / bun

```bash
npx secsuite scan .          # no install, one-off
npm install -g secsuite      # global CLI
bunx secsuite scan .         # bun works too - same published package
```

Static scanners are not bundled by the npm package - install the ones you want
(see [Prerequisites](#prerequisites)); missing ones are skipped with a warning.

### From source

```bash
npm install
npm run build
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
| `--sarif <file>` | write merged findings as SARIF 2.1.0 to `<file>` | - |
| `--config <file>` | path to `secsuite.yaml` | `<path>/secsuite.yaml` if present |
| `--baseline <file>` | baseline file to suppress accepted findings | `<path>/.secsuite-baseline.json` if present |
| `--no-baseline` | ignore any baseline file | - |
| `--static-only` | reserved; the `scan` command only does static analysis | - |

### Dynamic scanning (pre-prod / runtime)

```bash
secsuite dast https://staging.example.com          # ZAP baseline (passive, safe)
secsuite dast https://staging.example.com --full   # ZAP active scan (sends payloads)
```

Real output (baseline scan of a live site - the first run pulls the ZAP image):

```
[secsuite] starting ZAP (zap-baseline.py) against https://staging.example.com - first run pulls the image, this can take a few minutes.

MEDIUM (3)
  dast:
    - Content Security Policy (CSP) Header Not Set (https://staging.example.com)
    - Cross-Domain Misconfiguration (https://staging.example.com)
    - Missing Anti-clickjacking Header (https://staging.example.com)

Total: 3 finding(s) at or above "medium" (critical: 0, high: 0, medium: 3, low: 0, info: 0)
```

Because DAST findings have no source line, several alerts on one URL would
share a location; secsuite keeps them as distinct findings (they are distinct
issues), so a page with three missing headers reports three findings, not one.

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
| `--sarif <file>` | write merged findings as SARIF 2.1.0 to `<file>` | - |

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
secsuite scan fixtures/vulnerable --severity high
```

Real output (Semgrep + Trivy + Gitleaks all installed):

```
[secsuite] detected: js, python

CRITICAL (3)
  sca:
    - PyYAML: yaml.load() API could execute arbitrary code (requirements.txt:2)
  secret:
    - AWS Access Key ID (config.py:3)
    - AWS Secret Access Key (config.py:4) [trivy, gitleaks]

HIGH (5)
  sast:
    - By not specifying a USER, a program in the container may run as 'root'... (Dockerfile:7)
    - AWS Access Key ID Value detected... (config.py:3)
    - AWS Secret Access Key detected (config.py:4)
  sca:
    - python-flask: Denial of Service via crafted JSON file (requirements.txt:1)
  iac:
    - ':latest' tag used (Dockerfile:1)

Total: 8 finding(s) at or above "high" (critical: 3, high: 5, medium: 0, low: 0, info: 0)
```

Note the hardcoded AWS secret on `config.py:4` is reported once with both
`trivy` and `gitleaks` under its `sources` - cross-tool deduplication in action.

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

## Baseline: adopting secsuite in an existing repo

An existing repo's first scan usually reports old findings you cannot fix today,
which would leave the CI gate permanently red.
Accept the current state once:

```bash
secsuite baseline .        # scans and writes .secsuite-baseline.json
git add .secsuite-baseline.json && git commit -m "Accept current security baseline"
```

From then on `secsuite scan` gates only on NEW findings; baselined ones are
suppressed from the console report and the exit code, but stay in `--json` and
`--sarif` output marked `"baselined": true`.
Use `--no-baseline` to see everything, `--baseline <file>` to point elsewhere.

Known limit: matching is by exact tool + rule + file + line, so a finding whose
line number shifts reappears as new. Re-run `secsuite baseline` after big
refactors if that gets noisy.

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

## CI and gating deployments

Those exit codes are the whole point in CI: run `secsuite` on push/PR, and let
a non-zero exit fail the job and block the deploy.

`secsuite scan . --severity critical` exits `1` only when a critical finding
exists, so it fails the pipeline exactly when you want to stop a release. Set
the bar wherever you like (`--severity high` blocks on high and critical).

A copy-paste GitHub Actions workflow lives in
[`examples/ci/github-actions.yml`](examples/ci/github-actions.yml). The key idea:

```yaml
jobs:
  security:
    steps:
      - run: npx secsuite@latest scan . --severity high   # exit 1 fails the job
  deploy:
    needs: security   # deploy only runs if the security gate passed
    ...
```

Because `deploy` has `needs: security`, a finding at or above the threshold
fails the security job and the deploy never runs. The same works for the
dynamic lane against a deployed staging URL:
`secsuite dast https://staging.example.com --severity high`.

Instead of passing `--severity` on the command line, you can commit a
`secsuite.yaml` (below) with `severity_threshold: high` so the whole team - and
CI - shares one policy, and the workflow is just `npx secsuite scan .`.

### GitHub Code Scanning

`--sarif` writes the merged report as SARIF 2.1.0, which GitHub renders as
code-scanning alerts in the Security tab and as inline PR annotations:

```yaml
permissions:
  security-events: write
steps:
  - run: npx secsuite@latest scan . --severity high --sarif secsuite.sarif
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with:
      sarif_file: secsuite.sarif
```

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
  dedupe.ts          cross-tool deduplication
  report.ts          console + JSON reporting
  schema.ts          Finding + Config types
fixtures/vulnerable/  intentionally-vulnerable sample repo
test/                 node:test suite (checked-in SARIF/ZAP fixtures + dedupe/detect)
Dockerfile            bundles secsuite + Semgrep/Trivy/Gitleaks
```
