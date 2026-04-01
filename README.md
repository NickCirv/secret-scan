![Banner](banner.svg)

# secret-scan
> Scan your entire git history for accidentally committed secrets. Because git rm doesn't actually help.

```bash
npx secret-scan
```

```
secret-scan · scanning 847 commits
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠  FINDINGS (2)

[HIGH] Stripe Key (sk_live_)
  commit: 7e9d3c1 (2023-11-02)
  file:   .env.backup:12
  line:   STRIPE_SECRET=sk_l...****

[MEDIUM] High-entropy string (base64)
  commit: 1a4f8e2 (2023-09-20)
  file:   scripts/deploy.sh:34
  line:   TOKEN="****...****"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Scanned: 847 commits · 2 findings in 2 files · HIGH:1 MEDIUM:1 LOW:0
```

## Commands
| Command | Description |
|---------|-------------|
| `secret-scan` | Scan full git history of current repo |
| `--path <dir>` | Scan a specific repository path |
| `--depth N` | Limit to last N commits |
| `--since <date>` | e.g. `"6 months ago"` or `"2024-01-01"` |
| `--fix-advice` | Show BFG/filter-repo commands to remove secrets |
| `--report json\|text` | Output format (default: text) |
| `--output <file>` | Save report to file |
| `--whitelist <regex>` | Skip findings matching this regex |

## Patterns Detected

| Category | Examples |
|----------|---------|
| AWS | Access Key IDs (`AKIA...`) |
| Anthropic | `sk-ant-api03-...` API keys |
| OpenAI | `sk-...` API keys |
| GitHub | `ghp_`, `gho_`, `ghs_`, `ghr_` tokens |
| Stripe | `sk_live_`, `sk_test_`, `rk_live_`, `pk_live_` |
| Private Keys | RSA/PEM private key headers |
| JWT Tokens | Three-part base64url tokens |
| Env assignments | `PASSWORD=`, `SECRET=`, `API_KEY=`, `TOKEN=` with values |
| URL credentials | `proto://user:password@host` |
| High-entropy strings | Base64/hex strings >40 chars with entropy >4.0 bits |

## CI Usage

Exit code `1` if any findings, `0` if clean:

```yaml
- name: Scan git history for secrets
  run: npx secret-scan --depth 100
```

## Install
```bash
npx secret-scan          # no install needed
npm install -g secret-scan  # global install
```

---
**Zero dependencies** · **Node 18+** · Made by [NickCirv](https://github.com/NickCirv) · MIT
