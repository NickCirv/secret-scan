# secret-scan
> Scan your entire git history for accidentally committed secrets. Because `git rm` doesn't actually help.

```bash
npx secret-scan
```

```
secret-scan · scanning 847 commits
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠  FINDINGS (3)

[HIGH] AWS Access Key
  commit: 3f2a1b8 (2024-01-15)
  file:   src/config.js
  value:  AKIA****...****XYZ0

[HIGH] Stripe Secret Key
  commit: 7e9d3c1 (2023-11-02)
  file:   .env.backup
  value:  sk_l****...****4321

[MEDIUM] High-entropy string (H=4.89)
  commit: 1a4f8e2 (2023-09-20)
  file:   scripts/deploy.sh
  value:  ghp_****...****abcd

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Scanned: 847 commits · 3 findings · 2 HIGH, 1 MEDIUM
```

## Commands

| Command | Description |
|---------|-------------|
| `secret-scan` | Scan full git history of current directory |
| `--path <dir>` | Scan any repo by path |
| `--depth N` | Limit to last N commits |
| `--since "6 months ago"` | Time-based limit |
| `--fix-advice` | Show BFG commands to remove secrets from history |
| `--report json\|text` | Output format (default: text) |
| `--output <file>` | Save report to file |
| `--whitelist <regex>` | Skip patterns matching this regex |
| `--help` | Show help |

## Patterns Detected

| Category | Patterns |
|----------|----------|
| **AWS** | Access keys (`AKIA...`), Secret key env vars |
| **Anthropic** | `sk-ant-...` API keys |
| **OpenAI** | `sk-` API keys |
| **GitHub** | `ghp_`, `gho_`, `ghs_`, `ghr_` tokens |
| **Stripe** | `sk_live_`, `sk_test_`, `rk_live_`, `pk_live_` |
| **Google** | `AIza...` API keys |
| **Slack** | `xoxb-`, `xoxp-`, `xoxa-` tokens |
| **SendGrid** | `SG....` API keys |
| **JWT** | 3-part `eyJ...` tokens |
| **Private Keys** | RSA, EC, DSA, OpenSSH private keys |
| **Passwords in URLs** | `://user:pass@host` patterns |
| **Environment vars** | `PASSWORD=`, `SECRET=`, `API_KEY=` with non-placeholder values |
| **High-entropy strings** | Shannon entropy > 4.5 on strings 40+ chars |

## Examples

```bash
# Scan current repo (all history)
npx secret-scan

# Or install globally
npm install -g secret-scan
sscan

# Scan a specific repo
secret-scan --path ~/projects/my-app

# Limit scope
secret-scan --depth 100
secret-scan --since "2024-01-01"
secret-scan --since "6 months ago"

# Get fix commands
secret-scan --fix-advice

# JSON output for CI pipelines
secret-scan --report json --output secrets-report.json

# Skip known-safe patterns
secret-scan --whitelist "test|example|dummy"
```

## CI/CD Integration

Exit code `1` when secrets are found, `0` when clean — works with any CI system.

```yaml
# GitHub Actions
- name: Scan for secrets
  run: npx secret-scan --depth 50
```

## Fixing Secrets in History

When secrets are found, use one of these tools to actually remove them:

1. **[BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/)** (fast, simple)
   ```bash
   java -jar bfg.jar --replace-text secrets.txt
   git reflog expire --expire=now --all && git gc --prune=now --aggressive
   git push --force --all
   ```

2. **[git-filter-repo](https://github.com/newren/git-filter-repo)** (flexible)
   ```bash
   pip install git-filter-repo
   git filter-repo --replace-text secrets.txt
   ```

> **Important:** After rewriting history, revoke and rotate every exposed secret immediately. History rewriting alone is not enough if secrets were ever pushed to a remote.

## Install

```bash
# Run once (no install)
npx secret-scan

# Global install
npm install -g secret-scan

# Both aliases work
secret-scan
sscan
```

---

**Zero dependencies** · **Node 18+** · Made by [NickCirv](https://github.com/NickCirv) · MIT
