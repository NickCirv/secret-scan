import chalk from 'chalk';
import {
  ACCENT,
  BRAND,
  SEVERITY_COLORS,
  SEVERITY_BADGES,
  maskSecret,
  formatPath,
  formatLine,
  hr,
  indent,
} from './formatter.js';

const VERSION = '1.0.0';

/**
 * Print the tool header banner.
 */
export function printHeader() {
  console.log();
  console.log(
    `  ${BRAND('SECRET-SCAN')}  ${chalk.dim('v' + VERSION)}`
  );
  console.log();
}

/**
 * Print a scanning progress line.
 */
export function printScanning(count, label = 'files') {
  console.log(
    `  ${chalk.dim('Scanning')} ${ACCENT(count)} ${chalk.dim(label + '...')}`
  );
  console.log();
}

/**
 * Print a single finding.
 * @param {Object} finding - { name, severity, file, line, lineNumber, matchedValue, description }
 */
export function printFinding(finding) {
  const { name, severity, file, lineNumber, matchedValue, description } = finding;

  const badge = SEVERITY_BADGES[severity] || SEVERITY_BADGES.low;
  const color = SEVERITY_COLORS[severity] || chalk.dim;

  console.log(`  ${badge}  ${color(name)}`);
  console.log(
    indent(`${chalk.dim(formatPath(file))}${lineNumber ? chalk.dim(':' + lineNumber) : ''}`, 12)
  );

  if (matchedValue) {
    const masked = maskSecret(matchedValue);
    console.log(indent(chalk.red(masked), 12));
  }

  console.log();
}

/**
 * Print findings grouped by severity.
 */
export function printFindings(findings) {
  const order = ['critical', 'high', 'medium', 'low'];
  const grouped = {};

  for (const f of findings) {
    if (!grouped[f.severity]) grouped[f.severity] = [];
    grouped[f.severity].push(f);
  }

  for (const severity of order) {
    if (!grouped[severity]) continue;
    for (const finding of grouped[severity]) {
      printFinding(finding);
    }
  }
}

/**
 * Print the summary footer.
 */
export function printSummary(findings, scannedCount, label = 'files') {
  const total = findings.length;
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };

  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  }

  console.log('  ' + hr('─', 50));

  if (total === 0) {
    console.log(
      `  ${chalk.green('✓')}  ${chalk.bold.green('No secrets found')}  ${chalk.dim('in')} ${ACCENT(scannedCount)} ${chalk.dim(label)}`
    );
  } else {
    const parts = [
      `  ${chalk.bold.red(total + ' secret' + (total !== 1 ? 's' : '') + ' found')}`,
    ];
    if (bySeverity.critical) parts.push(chalk.red.bold(bySeverity.critical + ' critical'));
    if (bySeverity.high) parts.push(chalk.yellow.bold(bySeverity.high + ' high'));
    if (bySeverity.medium) parts.push(ACCENT(bySeverity.medium + ' medium'));
    if (bySeverity.low) parts.push(chalk.dim(bySeverity.low + ' low'));

    console.log(parts.join(chalk.dim('  │  ')));
  }

  console.log('  ' + hr('─', 50));
  console.log();

  if (total === 0) {
    console.log(
      `  ${chalk.dim('Tip:')} Run ${ACCENT('secret-scan init')} to install as a pre-commit hook.`
    );
  } else {
    console.log(
      `  ${chalk.dim('Run')} ${ACCENT('secret-scan init')} ${chalk.dim('to install pre-commit hook and catch these earlier.')}`
    );
  }

  console.log();
}

/**
 * Print clean JSON output for CI pipelines.
 */
export function printJSON(findings, meta = {}) {
  const output = {
    version: VERSION,
    timestamp: new Date().toISOString(),
    ...meta,
    total: findings.length,
    findings: findings.map((f) => ({
      name: f.name,
      severity: f.severity,
      description: f.description,
      file: f.file,
      lineNumber: f.lineNumber || null,
      matchedValue: maskSecret(f.matchedValue || '', 4),
    })),
  };
  console.log(JSON.stringify(output, null, 2));
}

/**
 * Print an informational message.
 */
export function printInfo(msg) {
  console.log(`  ${chalk.dim('→')} ${msg}`);
}

/**
 * Print a success message.
 */
export function printSuccess(msg) {
  console.log(`  ${chalk.green('✓')} ${chalk.bold(msg)}`);
}

/**
 * Print an error message.
 */
export function printError(msg) {
  console.error(`  ${chalk.red('✗')} ${chalk.bold(msg)}`);
}
