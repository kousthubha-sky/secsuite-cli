# secsuite

One command runs the right security scanners for your stack and merges everything into one clean, deduplicated report.

[![npm version](https://img.shields.io/npm/v/secsuite)](https://www.npmjs.com/package/secsuite)
[![docker](https://img.shields.io/docker/v/kousthubhaone/secsuite-cli?label=docker)](https://hub.docker.com/r/kousthubhaone/secsuite-cli)
[![license: MIT](https://img.shields.io/npm/l/secsuite)](LICENSE)

```bash
npx secsuite scan .                    # scan your code, dependencies, secrets, IaC
npx secsuite dast https://staging.app  # scan your running app (needs Docker)
```

secsuite detects your stack and shells out to [Semgrep](https://semgrep.dev/), [Trivy](https://trivy.dev/), [Gitleaks](https://github.com/gitleaks/gitleaks), and [OWASP ZAP](https://www.zaproxy.org/) - in parallel - then normalizes and deduplicates their findings into one report.
It is a defensive DevSecOps orchestrator and contains no attack code of its own.

Works on JavaScript/TypeScript, Python, Java/Kotlin, C#/.NET, Go, Rust, PHP, and Ruby.

## Commands

| Command | What it does |
|---|---|
| `secsuite scan [path]` | Static scan: code (SAST), dependencies (SCA), secrets, IaC misconfig |
| `secsuite dast <url>` | Dynamic scan of a running app with OWASP ZAP |
| `secsuite baseline [path]` | Accept current findings; future scans gate only on NEW ones |
| `secsuite doctor` | Check what is installed, with per-platform install hints |
| `secsuite` | Live status: detected stack + scanner availability |

## Install

**npm** (bring your own scanners - run `secsuite doctor` to see what is missing):

```bash
npm i -g secsuite     # or: pnpm add -g secsuite / bun add -g secsuite / npx secsuite
```

**Docker** (all static scanners bundled, nothing else to install):

```bash
docker run --rm -v "$PWD:/scan" kousthubhaone/secsuite-cli:0.2.0 scan /scan
```

Requirements: Node.js >= 22.5 for the npm install.
The `dast` command needs Docker running; the static `scan` does not.
Missing scanners are skipped with a warning, never a hard failure.

## Gate your CI

`scan` exits `1` when it finds anything at or above `--severity`, so a failed job blocks the deploy.
One step on GitHub Actions (Ubuntu runners):

```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }        # full history so Gitleaks can scan past commits
      - uses: kousthubha-sky/secsuite-cli@v0.2.0
        with:
          severity: high
          sarif-file: secsuite.sarif    # optional: for GitHub Code Scanning
  deploy:
    needs: security                     # deploy only runs if the gate passed
```

Upload the SARIF and findings appear in your repo's Security tab and as inline PR annotations:

```yaml
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: secsuite.sarif }
```

(Needs `permissions: security-events: write` on the job.)
A full copy-paste workflow, including a manual-install variant for non-Ubuntu runners, lives in [`examples/ci/github-actions.yml`](examples/ci/github-actions.yml).

## Adopting in an existing repo

Your first scan will report old findings you cannot fix today.
Accept them once instead of turning the gate off:

```bash
secsuite baseline .
git add .secsuite-baseline.json && git commit -m "Accept current security baseline"
```

From then on `scan` gates only on NEW findings.
Baselined ones stay visible in `--json`/`--sarif` output, marked `"baselined": true`.
Known limit: matching is exact (tool + rule + file + line), so a finding whose line shifts reappears as new - re-run `secsuite baseline` after big refactors.

## Dynamic scanning (DAST)

```bash
secsuite dast https://staging.example.com          # passive baseline scan (safe)
secsuite dast https://staging.example.com --full   # active scan - sends real attack payloads
```

The default baseline scan spiders the app and applies passive rules only.
`--full` attacks the target and mutates state: only point it at targets you are authorized to test, never live production.
Burp Suite has no free headless API; ZAP covers this lane, and `src/adapters/zap.ts` is the extension point if your organisation owns Burp Enterprise.

## Flags

`scan`:

| Flag | Description | Default |
|---|---|---|
| `--severity <level>` | minimum severity that reports/gates (`critical`\|`high`\|`medium`\|`low`\|`info`) | `medium` |
| `--json <file>` | write all findings as JSON (`-` = compact JSON to stdout) | - |
| `--sarif <file>` | write merged findings as SARIF 2.1.0 | - |
| `--baseline <file>` / `--no-baseline` | override / ignore the baseline file | auto-detect |
| `--raw` | include raw scanner payloads in JSON output | off |
| `--config <file>` | path to `secsuite.yaml` | `<path>/secsuite.yaml` |

`dast` supports `--full`, `--severity`, `--json`, `--sarif`, and `--raw`.

## Configuration (optional)

Commit a `secsuite.yaml` so your team and CI share one policy:

```yaml
severity_threshold: high
ignore:
  paths: ["tests/", "vendor/", "**/generated/**"]
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | no findings at or above the threshold |
| `1` | findings at or above the threshold |
| `2` | execution or usage error (bad path, bad config, unknown flag, every scanner failed) |

A scanner exiting non-zero because it found something is not an error - secsuite trusts the scanner's report file over its exit code.

## For AI agents

secsuite follows the [AXI](https://axi.md) agent-experience guidelines:

- Exit codes are the contract; an unknown flag exits `2`, never `1`.
- `--json -` prints one compact JSON payload to stdout; all progress goes to stderr.
- JSON omits raw scanner payloads unless `--raw` is passed.
- Human output appends `help:` lines suggesting the next command.
- Bare `secsuite` prints live status, not help text.

## How it works

```
detect stack -> run scanners in parallel -> normalize to one schema -> dedupe -> report
```

Every finding becomes `{ tool, category, ruleId, severity, title, location, sources, ... }` regardless of which scanner produced it.
Two findings merge only when **different** tools report the same file, line, and category (e.g. Trivy and Gitleaks both flagging one hardcoded key) - the survivor lists both in `sources`.
Multiple findings from the same tool at one location stay separate, because they are distinct issues.

## Try it on the built-in vulnerable fixture

```bash
secsuite scan fixtures/vulnerable --severity high
```

An intentionally-vulnerable sample (SQL injection, outdated deps, fake AWS keys, bad Dockerfile) ships in [`fixtures/vulnerable/`](fixtures/vulnerable/) to exercise the scanners.
Nothing in it is a real secret.

## License

[MIT](LICENSE)
