#!/usr/bin/env node
/**
 * secret-scan — Scan your entire git history for accidentally committed secrets.
 * Zero dependencies. Pure Node.js ES modules. Node 18+. MIT.
 */

import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

// ─── CLI ARGS ────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);

function getArg(flag, defaultVal = null) {
  const idx = args.indexOf(flag);
  if (idx === -1) return defaultVal;
  return args[idx + 1] ?? defaultVal;
}

function hasFlag(flag) {
  return args.includes(flag);
}

if (hasFlag('--help') || hasFlag('-h')) {
  console.log(`
secret-scan · Scan git history for accidentally committed secrets

USAGE
  npx secret-scan [options]
  sscan [options]

OPTIONS
  --path <dir>         Repo to scan (default: current directory)
  --depth <N>          Limit to last N commits (default: all)
  --since <date>       e.g. "6 months ago", "2024-01-01"
  --report text|json   Output format (default: text)
  --output <file>      Save report to file
  --whitelist <regex>  Skip findings matching this pattern
  --fix-advice         Show BFG commands to remediate each finding
  --help               Show this help

EXAMPLES
  npx secret-scan
  npx secret-scan --path /my/repo --depth 200
  npx secret-scan --since "6 months ago" --report json --output report.json
  npx secret-scan --fix-advice --whitelist "example|test|placeholder"

EXIT CODES
  0  No findings
  1  Findings detected (CI-friendly)
`);
  process.exit(0);
}

const scanPath   = resolve(getArg('--path', process.cwd()));
const depth      = getArg('--depth', null);
const since      = getArg('--since', null);
const reportFmt  = getArg('--report', 'text');
const outputFile = getArg('--output', null);
const whitelist  = getArg('--whitelist', null);
const fixAdvice  = hasFlag('--fix-advice');

// ─── PATTERNS (all built at runtime via concatenation to avoid self-detection) ─

function buildPatterns() {
  const p = [];

  // AWS Access Key ID
  const awsBody = 'AK' + 'IA' + '[0-9A-Z]{16}';
  p.push({
    id: 'aws-access-key', label: 'AWS Access Key ID', severity: 'HIGH',
    regex: new RegExp('(?<![A-Z0-9])(' + awsBody + ')(?![A-Z0-9])'),
  });

  // Anthropic API key (long form api03-)
  const antLong = 'sk' + '-ant-' + 'api03-' + '[A-Za-z0-9\\-_]{80,}';
  p.push({
    id: 'anthropic-key', label: 'Anthropic API Key', severity: 'HIGH',
    regex: new RegExp('(' + antLong + ')'),
  });

  // Anthropic API key (short form)
  const antShort = 'sk' + '-ant-[A-Za-z0-9\\-_]{30,}';
  p.push({
    id: 'anthropic-key-short', label: 'Anthropic API Key (short)', severity: 'HIGH',
    regex: new RegExp('(?<![A-Za-z0-9])(' + antShort + ')'),
  });

  // OpenAI API key
  const oaiBody = 'sk-[A-Za-z0-9]{32,}';
  p.push({
    id: 'openai-key', label: 'OpenAI API Key', severity: 'HIGH',
    regex: new RegExp('(?<![A-Za-z0-9])(' + oaiBody + ')'),
  });

  // GitHub tokens
  for (const prefix of ['ghp', 'gho', 'ghs', 'ghr']) {
    p.push({
      id: 'github-token-' + prefix, label: 'GitHub Token (' + prefix + '_)', severity: 'HIGH',
      regex: new RegExp('(?<![A-Za-z0-9])(' + prefix + '_[A-Za-z0-9]{36,})'),
    });
  }

  // Stripe keys (by prefix)
  const stripeVariants = [
    ['sk' + '_live_', 'HIGH'],
    ['sk' + '_test_', 'MEDIUM'],
    ['rk' + '_live_', 'HIGH'],
    ['pk' + '_live_', 'MEDIUM'],
  ];
  for (const [pfx, sev] of stripeVariants) {
    p.push({
      id: 'stripe-' + pfx.replace(/_/g, '-'),
      label: 'Stripe Key (' + pfx + ')',
      severity: sev,
      regex: new RegExp('(' + pfx + '[A-Za-z0-9]{16,})'),
    });
  }

  // Private key PEM headers
  p.push({
    id: 'private-key-rsa', label: 'RSA Private Key', severity: 'HIGH',
    regex: new RegExp('BEGIN' + ' RSA ' + 'PRIVATE' + ' KEY'),
  });
  p.push({
    id: 'private-key-generic', label: 'Private Key (PEM)', severity: 'HIGH',
    regex: new RegExp('BEGIN' + ' PRIVATE' + ' KEY'),
  });

  // ENV assignments: PASSWORD=secret, API_KEY=value, etc.
  const envKws = ['PASSWORD', 'SECRET', ['API', 'KEY'].join('_'), 'TOKEN', ['ACCESS', 'KEY'].join('_')];
  for (const kw of envKws) {
    p.push({
      id: 'env-' + kw.toLowerCase(),
      label: 'Env assignment: ' + kw,
      severity: 'MEDIUM',
      captureGroup: 2,
      regex: new RegExp(
        kw + '\\s*[=:]\\s*' +
        '(?!(?:"|\')?\\s*(?:\\$\\{|<|\\[|your|changeme|example|placeholder|xxx+|\\*+|\\$[A-Z_]+))' +
        '(["\']?)([A-Za-z0-9/+._\\-]{8,})\\1',
        'i'
      ),
    });
  }

  // Credentials in URLs  proto://user:PASS@host
  p.push({
    id: 'url-credentials', label: 'Credentials in URL', severity: 'MEDIUM',
    regex: /[a-z][a-z0-9+\-.]*:\/\/[^:@\s]{1,64}:([^@\s]{4,64})@/i,
  });

  // JWT tokens
  p.push({
    id: 'jwt-token', label: 'JWT Token', severity: 'MEDIUM',
    regex: /\b(ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/,
  });

  // High-entropy base64
  p.push({
    id: 'high-entropy-base64', label: 'High-entropy string (base64)', severity: 'LOW',
    regex: /(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/=])/,
    entropyCheck: true,
  });

  // High-entropy hex
  p.push({
    id: 'high-entropy-hex', label: 'High-entropy string (hex)', severity: 'LOW',
    regex: /(?<![0-9a-fA-F])([0-9a-fA-F]{40,})(?![0-9a-fA-F])/,
    entropyCheck: true,
  });

  return p;
}

// ─── UTILITIES ───────────────────────────────────────────────────────────────

function shannonEntropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] ?? 0) + 1;
  const len = str.length;
  let e = 0;
  for (const count of Object.values(freq)) {
    const prob = count / len;
    e -= prob * Math.log2(prob);
  }
  return e;
}

function redact(value) {
  if (!value) return '****';
  const s = String(value);
  if (s.length <= 8) return '****';
  return s.slice(0, 4) + '...' + s.slice(-4);
}

// ─── GIT HELPERS ─────────────────────────────────────────────────────────────

function git(cwd, ...gitArgs) {
  return execFileSync('git', gitArgs, {
    cwd,
    maxBuffer: 50 * 1024 * 1024,
    stdio: ['pipe', 'pipe', 'pipe'],
  }).toString();
}

function getCommitHashes(cwd) {
  const logArgs = ['log', '--all', '--format=%H %as %s'];
  if (depth) logArgs.push('-' + depth);
  if (since) logArgs.push('--since=' + since);
  const output = git(cwd, ...logArgs);
  return output.trim().split('\n').filter(Boolean).map(line => {
    const sp1 = line.indexOf(' ');
    const rest = line.slice(sp1 + 1);
    const sp2  = rest.indexOf(' ');
    return {
      hash:    line.slice(0, sp1),
      date:    rest.slice(0, sp2),
      subject: rest.slice(sp2 + 1),
    };
  });
}

function getDiffContent(cwd, hash) {
  try {
    return git(cwd, 'show', '--format=', '-U0', '--no-color', hash);
  } catch {
    return '';
  }
}

// ─── SCANNER ─────────────────────────────────────────────────────────────────

const PATTERNS = buildPatterns();

let whitelistRx = null;
if (whitelist) {
  try { whitelistRx = new RegExp(whitelist, 'i'); }
  catch { console.error('[secret-scan] Invalid --whitelist regex: ' + whitelist); process.exit(2); }
}

const seenKeys = new Set();

function scanDiff(diffText, commitMeta) {
  const findings = [];
  let currentFile = null;
  let lineNo = 0;

  for (const rawLine of diffText.split('\n')) {
    if (rawLine.startsWith('diff --git ')) {
      const m = rawLine.match(/b\/(.+)$/);
      currentFile = m ? m[1] : null;
      lineNo = 0;
      continue;
    }
    if (rawLine.startsWith('+++ b/')) { currentFile = rawLine.slice(6); continue; }
    if (rawLine.startsWith('@@ ')) {
      const m = rawLine.match(/\+(\d+)/);
      lineNo = m ? parseInt(m[1], 10) - 1 : lineNo;
      continue;
    }
    if (!rawLine.startsWith('+') || rawLine.startsWith('+++')) continue;
    lineNo++;
    const line = rawLine.slice(1);

    for (const pattern of PATTERNS) {
      const match = pattern.regex.exec(line);
      if (!match) continue;
      const capIdx   = pattern.captureGroup ?? 1;
      const captured = match[capIdx] ?? match[0];
      if (!captured || captured.length < 4) continue;
      if (pattern.entropyCheck && shannonEntropy(captured) < 4.0) continue;
      if (whitelistRx && whitelistRx.test(captured)) continue;
      const dk = (currentFile ?? '') + ':' + lineNo + ':' + pattern.id;
      if (seenKeys.has(dk)) continue;
      seenKeys.add(dk);
      const preview = (line.length > 120 ? line.slice(0, 120) + '…' : line)
        .replace(captured, redact(captured));
      findings.push({
        patternId:   pattern.id,
        label:       pattern.label,
        severity:    pattern.severity,
        file:        currentFile ?? '(unknown)',
        lineNo,
        commitHash:  commitMeta.hash,
        commitDate:  commitMeta.date,
        commitMsg:   commitMeta.subject,
        redacted:    redact(captured),
        linePreview: preview,
      });
    }
  }
  return findings;
}

// ─── FIX ADVICE ──────────────────────────────────────────────────────────────

function buildFixAdvice(f) {
  return [
    '  Remediation:',
    '  1. BFG Repo Cleaner (fastest):',
    '       bfg --delete-files "' + f.file.split('/').pop() + '" <repo-dir>',
    '       git reflog expire --expire=now --all && git gc --prune=now --aggressive',
    '  2. git filter-repo:',
    '       git filter-repo --path "' + f.file + '" --invert-paths',
    '  3. ROTATE the secret immediately if it was ever valid.',
    '  4. Force-push all branches after rewriting history.',
  ].join('\n');
}

// ─── ANSI ─────────────────────────────────────────────────────────────────────

const R = '\x1b[0m', B = '\x1b[1m', D = '\x1b[2m';
const RED = '\x1b[31m', YEL = '\x1b[33m', CYN = '\x1b[36m', GRN = '\x1b[32m';
const SEV_COLOR = { HIGH: RED, MEDIUM: YEL, LOW: CYN };

// ─── REPORTS ─────────────────────────────────────────────────────────────────

function renderText(findings, total) {
  const o = ['', B + 'secret-scan' + R + ' · scanning ' + total + ' commits', '━'.repeat(42)];
  if (!findings.length) {
    return o.concat(['', GRN + B + '✓  No secrets found' + R, '',
      D + 'Scanned: ' + total + ' commits · 0 findings' + R, '']).join('\n');
  }
  o.push('', B + '⚠  FINDINGS (' + findings.length + ')' + R, '');
  for (const f of findings) {
    const sc = SEV_COLOR[f.severity] ?? CYN;
    o.push(sc + B + '[' + f.severity + ']' + R + ' ' + f.label);
    o.push('  commit: ' + D + f.commitHash.slice(0, 7) + ' (' + f.commitDate + ')' + R);
    o.push('  file:   ' + f.file + ':' + f.lineNo);
    o.push('  line:   ' + D + f.linePreview.trim() + R);
    if (fixAdvice) { o.push('', buildFixAdvice(f)); }
    o.push('');
  }
  o.push('━'.repeat(42));
  const high = findings.filter(f => f.severity === 'HIGH').length;
  const med  = findings.filter(f => f.severity === 'MEDIUM').length;
  const low  = findings.filter(f => f.severity === 'LOW').length;
  const files = new Set(findings.map(f => f.file)).size;
  o.push(D + 'Scanned: ' + total + ' commits · ' + findings.length +
    ' finding' + (findings.length !== 1 ? 's' : '') + ' in ' + files +
    ' file' + (files !== 1 ? 's' : '') + ' · HIGH:' + high + ' MEDIUM:' + med + ' LOW:' + low +
    (fixAdvice ? '' : ' · Run with --fix-advice to remediate') + R, '');
  return o.join('\n');
}

function renderJson(findings, total) {
  return JSON.stringify({
    scannedCommits: total,
    totalFindings:  findings.length,
    summary: {
      high:   findings.filter(f => f.severity === 'HIGH').length,
      medium: findings.filter(f => f.severity === 'MEDIUM').length,
      low:    findings.filter(f => f.severity === 'LOW').length,
    },
    findings: findings.map(f => ({
      severity: f.severity, patternId: f.patternId, label: f.label,
      file: f.file, lineNo: f.lineNo,
      commitHash: f.commitHash, commitDate: f.commitDate, redacted: f.redacted,
    })),
  }, null, 2);
}

// ─── SORT ─────────────────────────────────────────────────────────────────────

const SEV_RANK = { HIGH: 0, MEDIUM: 1, LOW: 2 };

// ─── MAIN ────────────────────────────────────────────────────────────────────

async function main() {
  try { git(scanPath, 'rev-parse', '--git-dir'); }
  catch { console.error('[secret-scan] Not a git repository: ' + scanPath); process.exit(2); }

  process.stderr.write(D + 'Collecting commits…' + R + '\r');

  let commits;
  try { commits = getCommitHashes(scanPath); }
  catch (err) { console.error('[secret-scan] Failed to read git log: ' + err.message); process.exit(2); }

  const total = commits.length;
  if (!total) { console.log('[secret-scan] No commits found.'); process.exit(0); }

  const allFindings = [];
  const CHUNK = 50;

  for (let i = 0; i < commits.length; i += CHUNK) {
    const chunk = commits.slice(i, i + CHUNK);
    const done  = i + chunk.length;
    const pct   = Math.round((done / total) * 100);
    process.stderr.write(
      D + 'Scanning ' + done + '/' + total + ' commits (' + pct + '%)…' + R + '          \r'
    );
    for (const commit of chunk) {
      allFindings.push(...scanDiff(getDiffContent(scanPath, commit.hash), commit));
    }
  }
  process.stderr.write(' '.repeat(60) + '\r');

  allFindings.sort((a, b) => {
    const d = SEV_RANK[a.severity] - SEV_RANK[b.severity];
    return d !== 0 ? d : b.commitDate.localeCompare(a.commitDate);
  });

  const report = reportFmt === 'json'
    ? renderJson(allFindings, total)
    : renderText(allFindings, total);

  if (outputFile) {
    writeFileSync(resolve(outputFile), report, 'utf8');
    console.log('[secret-scan] Report saved to: ' + outputFile);
  } else {
    console.log(report);
  }

  process.exit(allFindings.length > 0 ? 1 : 0);
}

main().catch(err => {
  console.error('[secret-scan] Fatal error: ' + err.message);
  process.exit(2);
});
