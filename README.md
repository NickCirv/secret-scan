![secret-scan — scan your entire git history for committed secrets and API keys](assets/banner.png)

<div align="center">

**Scan your entire git history for accidentally committed secrets. Because `git rm` doesn't actually remove them.**

![license](https://img.shields.io/badge/license-MIT-blue?labelColor=0B0A09)
![dependencies](https://img.shields.io/badge/dependencies-0-brightgreen?labelColor=0B0A09)
![node](https://img.shields.io/badge/node-%3E%3D18-brightgreen?labelColor=0B0A09)
![patterns](https://img.shields.io/badge/secret%20patterns-10%20classes-F87171?labelColor=0B0A09)

</div>

---

A committed secret lives in your git history **forever** — deleting the file in a new commit leaves the old blob fully recoverable. `secret-scan` walks every commit in your history, flags exposed keys with severity + location, and (with `--fix-advice`) hands you the exact commands to purge them.

```
secret-scan · scanning 847 commits
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠  FINDINGS (2)

[HIGH]   Stripe Key (sk_live_)
  commit: 7e9d3c1 (2023-11-02)
  file:   .env.backup:12
  line:   STRIPE_SECRET=sk_l...****

[MEDIUM] High-entropy string (base64)
  commit: 1a4f8e2 (2023-09-20)
  file:   scripts/deploy.sh:34
  line:   TOKEN="****...****"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Scanned: 847 commits · 2 findings · HIGH:1 MEDIUM:1 LOW:0
```

## Install

No install, no npm account — it runs straight from GitHub with zero dependencies:

```bash
npx github:NickCirv/secret-scan
```

## Usage

```bash
# scan the full history of the current repo
npx github:NickCirv/secret-scan

# a specific repo, last 200 commits
npx github:NickCirv/secret-scan --path /my/repo --depth 200

# JSON report for the last 6 months, saved to a file
npx github:NickCirv/secret-scan --since "6 months ago" --report json --output report.json

# show remediation commands, ignore known-safe matches
npx github:NickCirv/secret-scan --fix-advice --whitelist "example|test|placeholder"
```

| Flag | Description |
|------|-------------|
| `--path <dir>` | Repo to scan (default: current directory) |
| `--depth <N>` | Limit to last N commits (default: all) |
| `--since <date>` | e.g. `"6 months ago"`, `"2024-01-01"` |
| `--report text\|json` | Output format (default: text) |
| `--output <file>` | Save report to a file |
| `--whitelist <regex>` | Skip findings matching this pattern |
| `--fix-advice` | Print BFG / `git filter-repo` commands to remove each finding |
| `--help` | Show help |

## What it catches

| Category | Examples |
|----------|----------|
| AWS | Access Key IDs (`AKIA…`) |
| Anthropic | `sk-ant-api03-…` |
| OpenAI | `sk-…` |
| GitHub | `ghp_`, `gho_`, `ghs_`, `ghr_` |
| Stripe | `sk_live_`, `sk_test_`, `rk_live_`, `pk_live_` |
| Private keys | RSA / PEM headers |
| JWT | Three-part base64url tokens |
| Env assignments | `PASSWORD=`, `SECRET=`, `API_KEY=`, `TOKEN=` with values |
| URL credentials | `proto://user:password@host` |
| High-entropy | Base64/hex strings > 40 chars, entropy > 4.0 bits |

## CI usage

Exit code is `1` if any secret is found, `0` if clean — so it fails the build:

```yaml
- name: Scan git history for secrets
  run: npx github:NickCirv/secret-scan --depth 100
```

## What it is NOT

- **Not a secrets manager or a prevention tool.** It audits history *after the fact* — pair it with a pre-commit hook to stop new leaks before they land.
- **Not a guarantee.** Detection is pattern + entropy based: it can miss novel key formats and surface false positives. Tune with `--whitelist`.
- **It doesn't rewrite history for you.** `--fix-advice` prints the exact BFG / `git filter-repo` commands — you run the remediation deliberately.

---

<div align="center">
<sub>Zero dependencies · Node 18+ · MIT · by <a href="https://github.com/NickCirv">NickCirv</a></sub>
</div>
