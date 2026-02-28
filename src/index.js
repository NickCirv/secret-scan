export { scanDirectory, scanFiles, scanStaged } from './scanner.js';
export { scanHistory } from './history.js';
export { PATTERNS, HIGH_ENTROPY_PATTERN, calculateEntropy, isHighEntropy } from './patterns.js';
export {
  printHeader,
  printScanning,
  printFinding,
  printFindings,
  printSummary,
  printJSON,
  printInfo,
  printSuccess,
  printError,
} from './reporter.js';
