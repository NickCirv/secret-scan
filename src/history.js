import { execFile } from 'child_process';
import { promisify } from 'util';
import { PATTERNS, HIGH_ENTROPY_PATTERN, isHighEntropy } from './patterns.js';

const execFileAsync = promisify(execFile);

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function passesFilter(severity, filter) {
  return SEVERITY_ORDER[severity] <= SEVERITY_ORDER[filter];
}

function isPlaceholder(value) {
  if (!value) return true;
  const lower = value.toLowerCase();
  const placeholders = [
    'your', 'example', 'placeholder', 'changeme', 'replace',
    'xxxxxxxx', 'test', 'demo', 'fake', 'dummy', 'sample',
    'xxxx', '1234', 'abcd', 'secret', 'password', 'token',
  ];
  return placeholders.some((p) => lower.includes(p)) || value.length < 8;
}

function getLineNumber(content, index) {
  const before = content.slice(0, index);
  return before.split('\n').length;
}

/**
 * Parse a unified diff patch and extract added lines with their source file/line.
 */
function parsePatch(patchText) {
  const segments = [];
  let currentFile = null;
  let currentLineNo = 0;

  const lines = patchText.split('\n');
  for (const line of lines) {
    if (line.startsWith('diff --git')) {
      const m = line.match(/b\/(.+)$/);
      currentFile = m ? m[1] : null;
      currentLineNo = 0;
    } else if (line.startsWith('@@')) {
      const m = line.match(/@@ -\d+(?:,\d+)? \+(\d+)/);
      if (m) currentLineNo = parseInt(m[1], 10) - 1;
    } else if (line.startsWith('+') && !line.startsWith('+++')) {
      currentLineNo++;
      segments.push({
        file: currentFile,
        lineNumber: currentLineNo,
        content: line.slice(1),
      });
    } else if (!line.startsWith('-')) {
      currentLineNo++;
    }
  }

  return segments;
}

/**
 * Scan a diff segment for secrets using all patterns.
 */
function scanDiffLine(segment, options = {}) {
  const findings = [];
  const { severityFilter, entropyEnabled = true } = options;
  const { file, lineNumber, content } = segment;

  for (const pattern of PATTERNS) {
    if (severityFilter && !passesFilter(pattern.severity, severityFilter)) continue;

    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match;

    while ((match = regex.exec(content)) !== null) {
      const matchedValue = match[1] || match[0];
      if (isPlaceholder(matchedValue)) continue;

      findings.push({
        name: pattern.name,
        severity: pattern.severity,
        description: pattern.description,
        file: file || '(unknown)',
        lineNumber,
        lineContent: content.trim().slice(0, 120),
        matchedValue,
        fromHistory: true,
      });
    }
  }

  if (entropyEnabled && (!severityFilter || passesFilter('medium', severityFilter))) {
    const regex = new RegExp(HIGH_ENTROPY_PATTERN.regex.source, HIGH_ENTROPY_PATTERN.regex.flags);
    let match;

    while ((match = regex.exec(content)) !== null) {
      const candidate = match[1] || match[0];
      if (isHighEntropy(candidate) && !isPlaceholder(candidate)) {
        const alreadyCaught = findings.some((f) => f.matchedValue === candidate);
        if (!alreadyCaught) {
          findings.push({
            name: HIGH_ENTROPY_PATTERN.name,
            severity: HIGH_ENTROPY_PATTERN.severity,
            description: HIGH_ENTROPY_PATTERN.description,
            file: file || '(unknown)',
            lineNumber,
            lineContent: content.trim().slice(0, 120),
            matchedValue: candidate,
            fromHistory: true,
          });
        }
      }
    }
  }

  return findings;
}

/**
 * Scan git history for secrets introduced in commits.
 * @param {number} limit - Number of commits to scan (default: 50)
 */
export async function scanHistory(limit = 50, options = {}) {
  let logOutput;
  try {
    const { stdout } = await execFileAsync('git', [
      'log',
      `-${limit}`,
      '--unified=0',
      '--no-color',
      '-p',
      '--diff-filter=A',
    ]);
    logOutput = stdout;
  } catch (err) {
    return {
      findings: [],
      commitCount: 0,
      error: 'Not a git repository or git log failed.',
    };
  }

  // Extract commit count
  let commitCount = 0;
  try {
    const { stdout: countOut } = await execFileAsync('git', [
      'log',
      `--oneline`,
      `-${limit}`,
    ]);
    commitCount = countOut.trim().split('\n').filter(Boolean).length;
  } catch {
    commitCount = limit;
  }

  const segments = parsePatch(logOutput);
  const allFindings = [];

  for (const segment of segments) {
    const findings = scanDiffLine(segment, options);
    allFindings.push(...findings);
  }

  // Deduplicate by file + line + matched value
  const seen = new Set();
  const deduped = allFindings.filter((f) => {
    const key = `${f.file}:${f.lineNumber}:${f.matchedValue}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const sorted = deduped.sort((a, b) => {
    const sA = SEVERITY_ORDER[a.severity] ?? 99;
    const sB = SEVERITY_ORDER[b.severity] ?? 99;
    return sA - sB;
  });

  return {
    findings: sorted,
    commitCount,
  };
}
