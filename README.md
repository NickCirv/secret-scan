# secret-scan

```
  SECRET-SCAN  v1.0.0

  Your repo has secrets.
  Let's find them before GitHub does.
```

[![npx secret-scan](https://img.shields.io/badge/run-npx%20secret--scan-3B82F6?style=flat-square)](https://www.npmjs.com/package/secret-scan)
[![Zero Config](https://img.shields.io/badge/config-zero-green?style=flat-square)](#)
[![No API Keys](https://img.shields.io/badge/API%20keys-none-brightgreen?style=flat-square)](#)
[![MIT License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](./LICENSE)
[![Node 18+](https://img.shields.io/badge/node-%3E%3D18-informational?style=flat-square)](#)

Pre-commit secret scanner. Finds API keys, tokens, passwords, private keys, and connection strings before they get pushed. Zero configuration. No cloud services. Pure regex + entropy analysis.

---

## Quick Start

```bash
npx secret-scan .
```

That's it. No config files. No accounts. No API calls.

---

## Sample Output

```
  SECRET-SCAN  v1.0.0

  → Scanning: /Users/you/project
  Scanning 47 files...

  CRITICAL  AWS Secret Key found
            src/config.js:23
            AKIA████████████████

  HIGH      Stripe Secret Key found
            lib/payments.js:8
            sk_live_████████████

  MEDIUM    Generic password assignment
            utils/db.js:15
            password = "██████"

  ──────────────────────────────────────────────────
  3 secrets found  │  1 critical  │  1 high  │  1 medium
  ──────────────────────────────────────────────────

  Run secret-scan init to install pre-commit hook and catch these earlier.
```

Secrets are masked on output. You see enough to identify the location — not enough to leak the value.

---

## Install

**One-off scan (no install):**
```bash
npx secret-scan .
```

**Global install:**
```bash
npm install -g secret-scan
secret-scan .
```

**Project dev dependency:**
```bash
npm install --save-dev secret-scan
```

---

## Commands

| Command | Description |
|---------|-------------|
| `secret-scan .` | Scan current directory |
| `secret-scan /path/to/repo` | Scan a specific path |
| `secret-scan --staged` | Scan only git staged files (pre-commit mode) |
| `secret-scan --history` | Scan last 50 commits |
| `secret-scan --history 100` | Scan last N commits |
| `secret-scan --severity high` | Only report high + critical findings |
| `secret-scan --json` | Output results as JSON (CI-friendly) |
| `secret-scan --no-entropy` | Disable high-entropy string detection |
| `secret-scan init` | Install as git pre-commit hook |

---

## What It Catches

| Category | Patterns | Severity |
|----------|----------|----------|
| AWS Access Key ID | `AKIA...` | Critical |
| AWS Secret Access Key | env var pattern | Critical |
| GitHub Tokens | `ghp_`, `github_pat_`, `gho_`, `ghs_` | Critical |
| Stripe Secret Key | `sk_live_`, `sk_test_` | Critical / High |
| Stripe Webhook Secret | `whsec_` | High |
| Google API Key | `AIza...` | High |
| Google OAuth Secret | env var pattern | High |
| Slack Bot/User Token | `xoxb-`, `xoxp-` | High |
| Slack Webhook URL | `hooks.slack.com/services/...` | High |
| JWT Tokens | `eyJ...eyJ...` | High |
| RSA / EC / OpenSSH Private Keys | `-----BEGIN ... PRIVATE KEY-----` | Critical |
| npm Tokens | `npm_...` | Critical |
| Twilio Auth Token | env var pattern | High |
| SendGrid API Key | `SG....` | High |
| Mailgun API Key | `key-...` | High |
| Heroku API Key | UUID pattern | High |
| Azure Connection Strings | `DefaultEndpointsProtocol=https;...` | High |
| Firebase API Key | JSON config pattern | Medium |
| Telegram Bot Token | `<id>:<token>` | High |
| MongoDB Connection String | `mongodb://user:pass@host` | High |
| PostgreSQL Connection String | `postgres://user:pass@host` | High |
| MySQL Connection String | `mysql://user:pass@host` | High |
| Redis Connection String | `redis://:pass@host` | High |
| Generic Password Assignment | `password = "..."` | Medium |
| Generic Secret Assignment | `secret = "..."` | Medium |
| Generic Token Assignment | `token = "..."` | Medium |
| Env Var with Secret Value | `API_KEY=abc123...` | Medium |
| High-Entropy Strings | Shannon entropy > 4.5 | Medium |

---

## Pre-Commit Hook Setup

Run once in your repo root:

```bash
npx secret-scan init
```

This installs a `.git/hooks/pre-commit` script that runs `secret-scan --staged` before every commit. If secrets are found, the commit is blocked.

Commits with no findings pass through with exit code 0.

---

## CI Integration

### GitHub Actions

```yaml
name: Secret Scan

on: [push, pull_request]

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Scan for secrets
        run: npx secret-scan .

      - name: Scan git history
        run: npx secret-scan --history 100
```

### JSON Output for CI

Use `--json` for structured output you can parse or upload as an artifact:

```bash
npx secret-scan --json . > scan-results.json
```

Output format:
```json
{
  "version": "1.0.0",
  "timestamp": "2026-01-01T00:00:00.000Z",
  "total": 2,
  "findings": [
    {
      "name": "AWS Access Key ID",
      "severity": "critical",
      "file": "src/config.js",
      "lineNumber": 23,
      "matchedValue": "AKIA████"
    }
  ]
}
```

---

## Severity Levels

| Level | Color | Exit Code | Meaning |
|-------|-------|-----------|---------|
| `critical` | Red | 1 | Active credentials that provide immediate access |
| `high` | Yellow | 1 | High-confidence secrets with real impact |
| `medium` | Blue | 0* | Potential secrets, review recommended |
| `low` | Gray | 0 | Low-confidence, worth a look |

*Exit code 1 when critical or high findings are present in `--staged` mode.

Filter to only see what matters:
```bash
secret-scan --severity high .
```

---

## How It Works

1. **Pattern matching** — 30+ named regex patterns for known secret formats.
2. **Entropy analysis** — Shannon entropy check on long strings (catches obfuscated or generated secrets not matching any named pattern).
3. **Placeholder filtering** — Ignores obvious placeholders (`your_key_here`, `changeme`, `example`, etc.).
4. **Binary skip** — Skips images, compiled assets, lock files, binaries.
5. **History scan** — Parses `git log -p` output to catch secrets in old commits that may have been deleted but remain in history.

---

## Why Not TruffleHog or detect-secrets?

| Feature | secret-scan | TruffleHog | detect-secrets |
|---------|-------------|------------|----------------|
| Zero install | `npx` | Requires Python/Docker | Requires Python |
| Zero config | Yes | No (needs rules file) | No (needs `.secrets.baseline`) |
| No cloud | Yes | Verifies against APIs | Yes |
| Git history | Yes | Yes | No |
| Entropy scan | Yes | Yes | Yes |
| Speed | Fast | Slow (API calls) | Medium |
| False positive rate | Low | Very low | Medium |

TruffleHog and detect-secrets are excellent — they verify secrets against live APIs which reduces false positives significantly. secret-scan is for teams that want a fast, dependency-free, no-account-needed first pass that catches 90% of issues with zero friction.

---

## Ignoring False Positives

Add a comment to suppress a specific line:

```js
const EXAMPLE_KEY = "AIzaSyExampleKeyForDocumentation"; // secret-scan-ignore
```

Or create `.secretscanignore` in your repo root (glob patterns, one per line):

```
tests/fixtures/**
docs/examples/**
```

> `.secretscanignore` support coming in v1.1.0

---

## Contributing

PRs welcome. To add a new pattern:

1. Open `src/patterns.js`
2. Add an entry to the `PATTERNS` array: `{ name, regex, severity, description }`
3. Test it: `node bin/scan.js --staged` on a file with a test credential
4. Submit a PR

Please do not include real credentials in test fixtures — use clearly fake values.

---

## License

MIT — Nicholas Ashkar, 2026
