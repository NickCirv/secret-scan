#!/usr/bin/env node

import { program } from 'commander';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { join, dirname, resolve } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(join(__dirname, '../package.json'), 'utf-8'));

program
  .name('secret-scan')
  .description('Pre-commit secret scanner — finds API keys, tokens, passwords before they ship.')
  .version(pkg.version);

// ─── Default command: scan directory ────────────────────────────────────────
program
  .argument('[path]', 'Directory or file to scan', '.')
  .option('--staged', 'Scan only git staged files (pre-commit mode)')
  .option('--history [commits]', 'Scan last N commits (default: 50)')
  .option('--severity <level>', 'Minimum severity to report (low|medium|high|critical)', null)
  .option('--json', 'Output results as JSON')
  .option('--no-entropy', 'Disable high-entropy string detection')
  .action(async (scanPath, opts) => {
    const {
      printHeader,
      printScanning,
      printFindings,
      printSummary,
      printJSON,
      printInfo,
      printError,
    } = await import('../src/reporter.js');

    const scanOptions = {
      severityFilter: opts.severity || null,
      entropyEnabled: opts.entropy !== false,
    };

    if (!opts.json) printHeader();

    try {
      if (opts.staged) {
        // ── Staged files mode ──────────────────────────────────────────────
        const { scanStaged } = await import('../src/scanner.js');

        if (!opts.json) printInfo('Mode: staged files (pre-commit)');
        const result = await scanStaged(scanOptions);

        if (result.error) {
          printError(result.error);
          process.exit(1);
        }

        if (!opts.json) printScanning(result.fileCount, 'staged file' + (result.fileCount !== 1 ? 's' : ''));

        if (opts.json) {
          const { printJSON } = await import('../src/reporter.js');
          printJSON(result.findings, { mode: 'staged', fileCount: result.fileCount });
        } else {
          printFindings(result.findings);
          printSummary(result.findings, result.fileCount, 'staged file' + (result.fileCount !== 1 ? 's' : ''));
        }

        process.exit(result.findings.some((f) => f.severity === 'critical' || f.severity === 'high') ? 1 : 0);

      } else if (opts.history !== undefined) {
        // ── Git history mode ───────────────────────────────────────────────
        const { scanHistory } = await import('../src/history.js');
        const commits = parseInt(opts.history, 10) || 50;

        if (!opts.json) printInfo(`Mode: git history (last ${commits} commits)`);
        const result = await scanHistory(commits, scanOptions);

        if (result.error) {
          printError(result.error);
          process.exit(1);
        }

        if (!opts.json) printScanning(result.commitCount, 'commit' + (result.commitCount !== 1 ? 's' : ''));

        if (opts.json) {
          printJSON(result.findings, { mode: 'history', commitCount: result.commitCount });
        } else {
          printFindings(result.findings);
          printSummary(result.findings, result.commitCount, 'commit' + (result.commitCount !== 1 ? 's' : ''));
        }

        process.exit(result.findings.length > 0 ? 1 : 0);

      } else {
        // ── Directory / file scan mode ─────────────────────────────────────
        const { scanDirectory } = await import('../src/scanner.js');
        const targetPath = resolve(process.cwd(), scanPath);

        if (!opts.json) printInfo(`Scanning: ${targetPath}`);
        const result = await scanDirectory(targetPath, scanOptions);

        if (!opts.json) printScanning(result.fileCount, 'file' + (result.fileCount !== 1 ? 's' : ''));

        if (opts.json) {
          printJSON(result.findings, { mode: 'directory', path: targetPath, fileCount: result.fileCount });
        } else {
          printFindings(result.findings);
          printSummary(result.findings, result.fileCount);
        }

        process.exit(result.findings.length > 0 ? 1 : 0);
      }
    } catch (err) {
      printError('Scan failed: ' + err.message);
      process.exit(2);
    }
  });

// ─── Init: install pre-commit hook ──────────────────────────────────────────
program
  .command('init')
  .description('Install secret-scan as a git pre-commit hook')
  .action(async () => {
    const { writeFile, mkdir, access, readFile } = await import('fs/promises');
    const { printHeader, printSuccess, printError, printInfo } = await import('../src/reporter.js');

    printHeader();

    const gitDir = join(process.cwd(), '.git');
    const hooksDir = join(gitDir, 'hooks');
    const hookFile = join(hooksDir, 'pre-commit');

    try {
      await access(gitDir);
    } catch {
      printError('Not a git repository. Run this from your project root.');
      process.exit(1);
    }

    try {
      await mkdir(hooksDir, { recursive: true });
    } catch {}

    const hookContent = [
      '#!/bin/sh',
      '# secret-scan pre-commit hook',
      '# Installed by: npx secret-scan init',
      '',
      'npx secret-scan --staged',
      'exit $?',
    ].join('\n') + '\n';

    // Check if hook already exists
    let existingHook = '';
    try {
      existingHook = await readFile(hookFile, 'utf-8');
    } catch {}

    if (existingHook.includes('secret-scan')) {
      printInfo('Pre-commit hook already installed.');
      process.exit(0);
    }

    if (existingHook && !existingHook.includes('secret-scan')) {
      // Append to existing hook
      const appended = existingHook.trimEnd() + '\n\n# secret-scan\nnpx secret-scan --staged\n';
      await writeFile(hookFile, appended, { mode: 0o755 });
      printSuccess('Appended secret-scan to existing pre-commit hook.');
    } else {
      await writeFile(hookFile, hookContent, { mode: 0o755 });
      printSuccess('Pre-commit hook installed at .git/hooks/pre-commit');
    }

    printInfo('Every commit will now be scanned for secrets.');
    process.exit(0);
  });

program.parse();
