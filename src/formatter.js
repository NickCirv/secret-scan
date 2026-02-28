import chalk from 'chalk';

export const ACCENT = chalk.hex('#3B82F6');
export const BRAND = chalk.bold.hex('#3B82F6');

export const SEVERITY_COLORS = {
  critical: chalk.bold.red,
  high: chalk.bold.yellow,
  medium: chalk.bold.blue,
  low: chalk.dim,
};

export const SEVERITY_BADGES = {
  critical: chalk.bgRed.white.bold(' CRITICAL '),
  high: chalk.bgYellow.black.bold('   HIGH   '),
  medium: chalk.bgBlue.white.bold('  MEDIUM  '),
  low: chalk.bgGray.white.bold('   LOW    '),
};

/**
 * Mask a secret value — show first N chars, replace rest with block chars.
 */
export function maskSecret(value, revealChars = 6) {
  if (!value || value.length <= revealChars) return '████████';
  const visible = value.slice(0, revealChars);
  const masked = '█'.repeat(Math.min(value.length - revealChars, 12));
  return visible + masked;
}

/**
 * Format a file path relative to cwd for cleaner output.
 */
export function formatPath(filePath, cwd = process.cwd()) {
  return filePath.startsWith(cwd)
    ? filePath.slice(cwd.length + 1)
    : filePath;
}

/**
 * Truncate a line for display, highlighting the secret portion.
 */
export function formatLine(line, matchedValue, revealChars = 6) {
  if (!line || !matchedValue) return line || '';
  const masked = maskSecret(matchedValue, revealChars);
  const truncated = line.trim().slice(0, 80);
  return truncated.replace(matchedValue, chalk.red(masked));
}

export function hr(char = '─', width = 50) {
  return chalk.dim(char.repeat(width));
}

export function indent(str, spaces = 12) {
  return ' '.repeat(spaces) + str;
}
