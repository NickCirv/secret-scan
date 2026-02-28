import { readFile, readdir, stat } from 'fs/promises';
import { join, extname } from 'path';
import { PATTERNS, HIGH_ENTROPY_PATTERN, isHighEntropy } from './patterns.js';

const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.svg',
  '.pdf', '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.wasm',
  '.mp4', '.mp3', '.wav', '.mov', '.avi',
  '.ttf', '.otf', '.woff', '.woff2', '.eot',
  '.db', '.sqlite', '.sqlite3',
  '.lock',
]);

const IGNORED_DIRS = new Set([
  'node_modules', '.git', '.svn', '.hg',
  'dist', 'build', 'out', '.next', '.nuxt', '.cache',
  'vendor', '__pycache__', '.pytest_cache',
  'coverage', '.nyc_output',
]);

const IGNORED_FILES = new Set([
  'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb',
  'Gemfile.lock', 'Pipfile.lock', 'poetry.lock', 'Cargo.lock',
]);

async function collectFiles(dir) {
  const files = [];

  async function walk(current) {
    let entries;
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = join(current, entry.name);

      if (entry.isDirectory()) {
        if (!IGNORED_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
          await walk(fullPath);
        }
        continue;
      }

      if (entry.isFile()) {
        if (IGNORED_FILES.has(entry.name)) continue;
        if (BINARY_EXTENSIONS.has(extname(entry.name).toLowerCase())) continue;
        files.push(fullPath);
      }
    }
  }

  await walk(dir);
  return files;
}

function scanContent(content, filePath, patterns, options = {}) {
  const findings = [];
  const { severityFilter, entropyEnabled = true } = options;
  const lines = content.split('\n');

  for (const pattern of patterns) {
    if (severityFilter && !passesFilter(pattern.severity, severityFilter)) continue;

    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match;

    while ((match = regex.exec(content)) !== null) {
      const matchedValue = match[1] || match[0];
      const lineNumber = getLineNumber(content, match.index);
      const lineContent = lines[lineNumber - 1] || '';

      if (isPlaceholder(matchedValue)) continue;

      findings.push({
        name: pattern.name,
        severity: pattern.severity,
        description: pattern.description,
        file: filePath,
        lineNumber,
        lineContent: lineContent.trim().slice(0, 120),
        matchedValue,
      });
    }
  }

  if (entropyEnabled && (!severityFilter || passesFilter('medium', severityFilter))) {
    const entropyRegex = new RegExp(HIGH_ENTROPY_PATTERN.regex.source, HIGH_ENTROPY_PATTERN.regex.flags);
    let match;

    while ((match = entropyRegex.exec(content)) !== null) {
      const candidate = match[1] || match[0];
      if (isHighEntropy(candidate) && !isPlaceholder(candidate)) {
        const lineNumber = getLineNumber(content, match.index);
        const lineContent = lines[lineNumber - 1] || '';

        const alreadyCaught = findings.some(
          (f) => f.lineNumber === lineNumber && f.file === filePath && f.matchedValue === candidate
        );
        if (!alreadyCaught) {
          findings.push({
            name: HIGH_ENTROPY_PATTERN.name,
            severity: HIGH_ENTROPY_PATTERN.severity,
            description: HIGH_ENTROPY_PATTERN.description,
            file: filePath,
            lineNumber,
            lineContent: lineContent.trim().slice(0, 120),
            matchedValue: candidate,
          });
        }
      }
    }
  }

  return findings;
}

export async function scanDirectory(dirPath, options = {}) {
  const s = await stat(dirPath);
  if (s.isFile()) {
    return scanFiles([dirPath], options);
  }
  const files = await collectFiles(dirPath);
  return scanFiles(files, options);
}

export async function scanFiles(filePaths, options = {}) {
  const allFindings = [];

  for (const filePath of filePaths) {
    let content;
    try {
      const s = await stat(filePath);
      if (s.size > 5 * 1024 * 1024) continue;
      content = await readFile(filePath, 'utf-8');
    } catch {
      continue;
    }

    const findings = scanContent(content, filePath, PATTERNS, options);
    allFindings.push(...findings);
  }

  return {
    findings: sortFindings(allFindings),
    fileCount: filePaths.length,
  };
}

export async function scanStaged(options = {}) {
  const { execFile } = await import('child_process');
  const { promisify } = await import('util');
  const execFileAsync = promisify(execFile);

  let stagedFiles;
  try {
    const { stdout } = await execFileAsync('git', ['diff', '--cached', '--name-only', '--diff-filter=ACMR']);
    stagedFiles = stdout.trim().split('\n').filter(Boolean);
  } catch {
    return { findings: [], fileCount: 0, error: 'Not a git repository or no staged files.' };
  }

  if (stagedFiles.length === 0) {
    return { findings: [], fileCount: 0 };
  }

  const cwd = process.cwd();
  const fullPaths = stagedFiles.map((f) => join(cwd, f));
  const allFindings = [];

  for (let i = 0; i < fullPaths.length; i++) {
    const relPath = stagedFiles[i];
    let content;
    try {
      const { stdout } = await execFileAsync('git', ['show', ':' + relPath]);
      content = stdout;
    } catch {
      try {
        content = await readFile(fullPaths[i], 'utf-8');
      } catch {
        continue;
      }
    }

    const findings = scanContent(content, fullPaths[i], PATTERNS, options);
    allFindings.push(...findings);
  }

  return {
    findings: sortFindings(allFindings),
    fileCount: stagedFiles.length,
  };
}

function getLineNumber(content, index) {
  const before = content.slice(0, index);
  return before.split('\n').length;
}

function isPlaceholder(value) {
  if (!value) return true;
  if (value.length < 8) return true;

  const lower = value.toLowerCase().trim();

  // Exact match or near-exact placeholder values
  const exactPlaceholders = [
    'your_key_here', 'your_secret_here', 'your_token_here',
    'changeme', 'change_me', 'replace_me', 'fixme',
    'placeholder', 'xxxxxxxx', 'xxxxxxxxxxxx',
    'test1234', 'demo1234', 'fake1234', 'dummy1234',
    'sample_key', 'example_key', 'insert_key_here',
  ];
  if (exactPlaceholders.includes(lower)) return true;

  // Patterns that indicate placeholder values (full-value shape, not substring)
  const placeholderPatterns = [
    /^x{6,}$/i,                    // xxxxxx...
    /^0{6,}$/,                     // 000000...
    /^your[_-]/i,                  // your_api_key, your-secret
    /^<.*>$/,                      // <YOUR_KEY>
    /^\{.*\}$/,                    // {INSERT_KEY}
    /^replace[_-]/i,              // replace_with_key
    /^todo[_:\-]/i,               // todo:add_key
    /^fake[_-]/i,                 // fake_secret_key
    /^dummy[_-]/i,                // dummy_api_token
    /^sample[_-]/i,               // sample_auth_key
    /^insert[_-]/i,               // insert_token_here
    /^(test|demo)$/, // literal "test" or "demo" as full value
  ];

  return placeholderPatterns.some((p) => p.test(lower));
}

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function sortFindings(findings) {
  return findings.sort((a, b) => {
    const sA = SEVERITY_ORDER[a.severity] ?? 99;
    const sB = SEVERITY_ORDER[b.severity] ?? 99;
    if (sA !== sB) return sA - sB;
    return a.file.localeCompare(b.file);
  });
}

function passesFilter(severity, filter) {
  return SEVERITY_ORDER[severity] <= SEVERITY_ORDER[filter];
}
