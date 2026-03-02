#!/usr/bin/env node
/**
 * secret-scan — Scan your entire git history for accidentally committed secrets.
 * Zero dependencies. Node 18+. MIT.
 */

import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { argv, exit, stdout, stderr } from 'node:process';

// ─── Pattern registry (built via concatenation to avoid self-detection) ──────

function buildPatterns() {
  return [
    {
      id: 'aws-access-key',
      name: 'AWS Access Key',
      severity: 'HIGH',
      regex: new RegExp('(' + 'AK' + 'IA' + '[0-9A-Z]{16})', 'g'),
    },
    {
      id: 'aws-secret-key',
      name: 'AWS Secret Key',
      severity: 'HIGH',
      regex: new RegExp(
        '(?:aws[_\\-]?secret[_\\-]?(?:access[_\\-]?)?key|AWS_SECRET)' +
          '\\s*[=:][\\s"\']([A-Za-z0-9/+=]{40})',
        'gi'
      ),
    },
    {
      id: 'anthropic-key',
      name: 'Anthropic API Key',
      severity: 'HIGH',
      regex: new RegExp('(' + 'sk' + '-' + 'ant' + '-[a-zA-Z0-9\\-_]{20,})', 'g'),
    },
    {
      id: 'openai-key',
      name: 'OpenAI API Key',
      severity: 'HIGH',
      regex: new RegExp('(' + 'sk' + '-[a-zA-Z0-9]{48})', 'g'),
    },
    {
      id: 'github-token',
      name: 'GitHub Token',
      severity: 'HIGH',
      regex: new RegExp('(gh[pors]_[a-zA-Z0-9]{36})', 'g'),
    },
    {
      id: 'stripe-secret',
      name: 'Stripe Secret Key',
      severity: 'HIGH',
      regex: new RegExp('((?:sk|rk)_(?:live|test)_[a-zA-Z0-9]{24,})', 'g'),
    },
    {
      id: 'stripe-publishable-live',
      name: 'Stripe Publishable Key (live)',
      severity: 'MEDIUM',
      regex: new RegExp('(pk_live_[a-zA-Z0-9]{24,})', 'g'),
    },
    {
      id: 'private-key-rsa',
      name: 'RSA Private Key',
      severity: 'HIGH',
      regex: new RegExp('(-{5}BEGIN RSA PRIVATE KEY-{5})', 'g'),
    },
    {
      id: 'private-key-generic',
      name: 'Private Key',
      severity: 'HIGH',
      regex: new RegExp('(-{5}BEGIN (?:EC |DSA |OPENSSH )?PRIVATE KEY-{5})', 'g'),
    },
    {
      id: 'password-in-url',
      name: 'Password in URL',
      severity: 'HIGH',
      regex: new RegExp('://[^:@\\s]+:([^@\\s<>{}]{6,})@', 'g'),
    },
    {
      id: 'env-password',
      name: 'Environment Password',
      severity: 'HIGH',
      regex: new RegExp('(?:PASSWORD|PASSWD|PASS)\\s*=\\s*["\']?([^\\s"\'<>{}#]{8,})', 'gi'),
    },
    {
      id: 'env-secret',
      name: 'Environment Secret',
      severity: 'HIGH',
      regex: new RegExp(
        '(?:SECRET|API_SECRET|CLIENT_SECRET)\\s*=\\s*["\']?([^\\s"\'<>{}#]{8,})',
        'gi'
      ),
    },
    {
      id: 'env-api-key',
      name: 'Environment API Key',
      severity: 'MEDIUM',
      regex: new RegExp('API_KEY\\s*=\\s*["\']?([^\\s"\'<>{}#]{8,})', 'gi'),
    },
    {
      id: 'jwt-token',
      name: 'JWT Token',
      severity: 'MEDIUM',
      regex: new RegExp(
        '(eyJ[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_-]{10,})',
        'g'
      ),
    },
    {
      id: 'sendgrid-key',
      name: 'SendGrid API Key',
      severity: 'HIGH',
      regex: new RegExp('(SG\\.[a-zA-Z0-9_\\-]{22}\\.[a-zA-Z0-9_\\-]{43})', 'g'),
    },
    {
      id: 'slack-token',
      name: 'Slack Token',
      severity: 'HIGH',
      regex: new RegExp('(xox[bpoa]-[0-9a-zA-Z\\-]{10,})', 'g'),
    },
    {
      id: 'google-api-key',
      name: 'Google API Key',
      severity: 'HIGH',
      regex: new RegExp('(AIza[0-9A-Za-z\\-_]{35})', 'g'),
    },
    {
      id: 'heroku-api-key',
      name: 'Heroku API Key',
      severity: 'HIGH',
      regex: new RegExp(
        '(?:heroku[_\\-]?(?:api[_\\-]?)?key|HEROKU_API_KEY)\\s*[=:][\\s"\']?([a-f0-9\\-]{36})',
        'gi'
      ),
    },
  ];
}

// ─── Shannon entropy ──────────────────────────────────────────────────────────

function shannonEntropy(str) {
  if (!str || str.length < 10) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const HIGH_ENTROPY_RE = /(?:['"`=:\s])([A-Za-z0-9+/=_\-]{40,})(?:['"`\s,;]|$)/g;

function findHighEntropyStrings(line) {
  const found = [];
  let match;
  HIGH_ENTROPY_RE.lastIndex = 0;
  while ((match = HIGH_ENTROPY_RE.exec(line)) !== null) {
    const candidate = match[1];
    const e = shannonEntropy(candidate);
    if (e > 4.5) found.push({ value: candidate, entropy: e.toFixed(2) });
  }
  return found;
}

// ─── Redaction ────────────────────────────────────────────────────────────────

function redact(str) {
  if (!str) return '****';
  if (str.length <= 8) return '****';
  return str.slice(0, 4) + '****...****' + str.slice(-4);
}

// ─── Placeholder filter ───────────────────────────────────────────────────────

const PLACEHOLDER_RE = /^(<[^>]+>|your[_-]?|xxx+|example|changeme|replace|dummy|fake|test[_-]?key|placeholder)/i;

function isPlaceholder(val) {
  return !val || PLACEHOLDER_RE.test(val.trim());
}

// ─── Git helpers (safe — execFileSync-style via spawnSync) ────────────────────

function gitExec(args, cwd) {
  const r = spawnSync('git', args, {
    cwd,
    encoding: 'utf8',
    maxBuffer: 50 * 1024 * 1024,
    timeout: 30000,
  });
  if (r.error) return null;
  return r.stdout || '';
}

function getCommitList(repoPath, opts) {
  const args = ['log', '--all', '--format=%H %cd', '--date=short'];
  if (opts.depth) args.push(`-${opts.depth}`);
  if (opts.since) args.push(`--since=${opts.since}`);
  const out = gitExec(args, repoPath);
  if (!out) return [];
  return out.trim().split('\n').filter(Boolean).map(line => {
    const [hash, date] = line.split(' ');
    return { hash, date };
  });
}

function getCommitDiff(repoPath, hash) {
  return gitExec(['show', '--format=', '-U0', '--diff-filter=AM', hash], repoPath);
}

// ─── Diff parser ──────────────────────────────────────────────────────────────

function parseDiff(diffText) {
  const lines = [];
  let currentFile = null;
  let lineNum = 0;
  for (const raw of diffText.split('\n')) {
    const fm = raw.match(/^diff --git a\/.+ b\/(.+)$/);
    if (fm) { currentFile = fm[1]; lineNum = 0; continue; }
    const hm = raw.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hm) { lineNum = parseInt(hm[1], 10) - 1; continue; }
    if (raw.startsWith('+') && !raw.startsWith('+++')) {
      lineNum++;
      lines.push({ file: currentFile, lineNum, content: raw.slice(1) });
    }
  }
  return lines;
}

// ─── Line scanner ─────────────────────────────────────────────────────────────

function scanLine(line, patterns, whitelist) {
  const results = [];
  for (const p of patterns) {
    p.regex.lastIndex = 0;
    let match;
    while ((match = p.regex.exec(line)) !== null) {
      const secret = match[1] || match[0];
      if (isPlaceholder(secret)) continue;
      if (whitelist && whitelist.test(secret)) continue;
      results.push({ patternId: p.id, patternName: p.name, severity: p.severity, redacted: redact(secret) });
    }
  }
  // High-entropy strings (skip if already caught)
  const heMatches = findHighEntropyStrings(line);
  for (const he of heMatches) {
    if (isPlaceholder(he.value)) continue;
    if (whitelist && whitelist.test(he.value)) continue;
    const alreadyCaught = results.some(r => line.includes(he.value.slice(0, 8)));
    if (!alreadyCaught) {
      results.push({
        patternId: 'high-entropy',
        patternName: `High-entropy string (H=${he.entropy})`,
        severity: 'MEDIUM',
        redacted: redact(he.value),
      });
    }
  }
  return results;
}

// ─── CLI args ─────────────────────────────────────────────────────────────────

function parseArgs(raw) {
  const opts = { path: process.cwd(), depth: null, since: null, report: 'text', output: null, whitelist: null, fixAdvice: false, help: false };
  for (let i = 0; i < raw.length; i++) {
    const a = raw[i];
    if (a === '--help' || a === '-h')           opts.help = true;
    else if (a === '--path' && raw[i+1])        opts.path = raw[++i];
    else if (a === '--depth' && raw[i+1])       opts.depth = parseInt(raw[++i], 10);
    else if (a === '--since' && raw[i+1])       opts.since = raw[++i];
    else if (a === '--report' && raw[i+1])      opts.report = raw[++i];
    else if (a === '--output' && raw[i+1])      opts.output = raw[++i];
    else if (a === '--whitelist' && raw[i+1])   opts.whitelist = new RegExp(raw[++i]);
    else if (a === '--fix-advice')              opts.fixAdvice = true;
  }
  opts.path = resolve(opts.path);
  return opts;
}

// ─── Output formatters ────────────────────────────────────────────────────────

const SEV_ORDER  = { HIGH: 0, MEDIUM: 1, LOW: 2 };
const SEV_LABEL  = {
  HIGH:   '\x1b[31m[HIGH]\x1b[0m',
  MEDIUM: '\x1b[33m[MEDIUM]\x1b[0m',
  LOW:    '\x1b[34m[LOW]\x1b[0m',
};

function formatText(findings, stats, opts) {
  const hr = '\u2501'.repeat(42);
  const out = ['\n', `\x1b[1msecret-scan\x1b[0m \u00b7 scanned ${stats.commits} commits\n`, hr, '\n'];

  if (!findings.length) {
    out.push('\x1b[32m\u2713  No secrets found\x1b[0m\n');
  } else {
    out.push(`\x1b[31m\u26a0  FINDINGS (${findings.length})\x1b[0m\n\n`);
    for (const f of findings) {
      out.push(`${SEV_LABEL[f.severity] || f.severity} ${f.patternName}\n`);
      out.push(`  commit: ${f.commit.slice(0,7)} (${f.date})\n`);
      out.push(`  file:   ${f.file}\n`);
      if (f.lineNum) out.push(`  line#:  ${f.lineNum}\n`);
      out.push(`  value:  ${f.redacted}\n`);
      if (opts.fixAdvice) {
        out.push(`  fix:    java -jar bfg.jar --replace-text secrets.txt\n`);
      }
      out.push('\n');
    }
  }

  out.push(hr + '\n');
  const sevCounts = {};
  for (const f of findings) sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1;
  const breakdown = Object.entries(sevCounts).filter(([,n]) => n > 0).map(([s,n]) => `${n} ${s}`).join(', ');
  const parts = [`Scanned: ${stats.commits} commits`, findings.length ? `${findings.length} finding${findings.length !== 1 ? 's' : ''}` : '0 findings'];
  if (breakdown) parts.push(breakdown);
  if (opts.fixAdvice && findings.length) parts.push('BFG commands shown above');
  out.push(parts.join(' \u00b7 ') + '\n\n');
  return out.join('');
}

function formatJson(findings, stats) {
  return JSON.stringify({ scanned_commits: stats.commits, total_findings: findings.length, findings }, null, 2);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const opts = parseArgs(argv.slice(2));

  if (opts.help) {
    stdout.write(`
\x1b[1msecret-scan\x1b[0m -- Scan your entire git history for accidentally committed secrets.

USAGE
  npx secret-scan [options]

OPTIONS
  --path <dir>          Path to git repo (default: current directory)
  --depth <n>           Limit to last N commits
  --since <date>        Limit by date e.g. "6 months ago" or "2024-01-01"
  --report text|json    Output format (default: text)
  --output <file>       Save report to file
  --whitelist <regex>   Skip patterns matching this regex
  --fix-advice          Show BFG/filter-repo commands to remove secrets
  --help                Show this help

EXAMPLES
  npx secret-scan
  npx secret-scan --depth 100
  npx secret-scan --since "6 months ago" --report json --output report.json
  npx secret-scan --path /path/to/repo --fix-advice

Exit code 1 if secrets found (CI-friendly).
`);
    exit(0);
  }

  const isGit = gitExec(['rev-parse', '--git-dir'], opts.path);
  if (!isGit) {
    stderr.write(`\x1b[31mError:\x1b[0m Not a git repository: ${opts.path}\n`);
    exit(2);
  }

  const patterns = buildPatterns();
  const commits  = getCommitList(opts.path, opts);

  if (!commits.length) {
    stdout.write('No commits found.\n');
    exit(0);
  }

  stdout.write(`\x1b[1msecret-scan\x1b[0m \u00b7 scanning ${commits.length} commits\n`);

  const allFindings = [];
  const CHUNK = 50;

  for (let i = 0; i < commits.length; i += CHUNK) {
    const chunk = commits.slice(i, i + CHUNK);
    const pct   = Math.round((i / commits.length) * 100);
    process.stdout.write(`\r  Progress: ${pct}% (${i}/${commits.length})      `);

    for (const commit of chunk) {
      const diff = getCommitDiff(opts.path, commit.hash);
      if (!diff) continue;
      for (const { file, lineNum, content } of parseDiff(diff)) {
        for (const hit of scanLine(content, patterns, opts.whitelist)) {
          allFindings.push({
            severity:    hit.severity,
            patternId:   hit.patternId,
            patternName: hit.patternName,
            commit:      commit.hash,
            date:        commit.date,
            file,
            lineNum,
            redacted:    hit.redacted,
          });
        }
      }
    }
  }

  process.stdout.write('\r' + ' '.repeat(50) + '\r');

  allFindings.sort((a, b) => {
    const sd = (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9);
    return sd !== 0 ? sd : b.date.localeCompare(a.date);
  });

  const stats  = { commits: commits.length };
  const output = opts.report === 'json' ? formatJson(allFindings, stats) : formatText(allFindings, stats, opts);

  if (opts.output) {
    writeFileSync(opts.output, output, 'utf8');
    stdout.write(`Report saved to: ${opts.output}\n`);
  } else {
    stdout.write(output);
  }

  if (opts.fixAdvice && allFindings.length) {
    stderr.write('\nFix: https://rtyley.github.io/bfg-repo-cleaner/ or https://github.com/newren/git-filter-repo\n\n');
  }

  exit(allFindings.length > 0 ? 1 : 0);
}

main().catch(err => {
  stderr.write(`\x1b[31mFatal:\x1b[0m ${err.message}\n`);
  exit(2);
});
