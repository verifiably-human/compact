/**
 * Report Generator
 * Generates constraint analysis reports in multiple formats
 */

import { writeFileSync } from 'fs';
import type { AnalysisResult, CircuitMetrics, ReportOptions } from './types.js';
import { getWarningMessage } from './parser.js';

/**
 * Format bytes as human-readable size
 */
function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * Format time as human-readable duration
 */
function formatTime(seconds: number): string {
  if (seconds < 1) return `${Math.round(seconds * 1000)}ms`;
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
}

/**
 * Generate console report
 */
export function generateConsoleReport(result: AnalysisResult, options: ReportOptions): string {
  const lines: string[] = [];

  // Header
  lines.push('');
  lines.push('📊 Compact Circuit Analysis');
  lines.push('='.repeat(80));
  lines.push('');

  // Contract info
  lines.push(`Contract: ${result.contractFile}`);
  lines.push(`Compiled: ${result.timestamp}`);
  lines.push(`Duration: ${result.compilationTime}ms`);
  if (result.compilerVersion) {
    lines.push(`Compiler: compact ${result.compilerVersion}`);
  }
  lines.push('');

  // Circuits table
  if (result.circuits.length === 0) {
    lines.push('No circuits found.');
    return lines.join('\n');
  }

  lines.push(`Circuits (${result.circuits.length}):`);
  lines.push('');

  // Table header
  const header = [
    'Circuit'.padEnd(25),
    'Constraints'.padStart(12),
    'K-value'.padStart(8),
    'Proof Size'.padStart(12),
    'Proving Time'.padStart(13),
  ].join(' │ ');

  lines.push(header);
  lines.push('─'.repeat(header.length));

  // Table rows
  for (const circuit of result.circuits) {
    const row = [
      circuit.name.padEnd(25),
      circuit.constraints.toLocaleString().padStart(12),
      circuit.kValue.toString().padStart(8),
      formatBytes(circuit.proofSize).padStart(12),
      formatTime(circuit.provingTimeEstimate).padStart(13),
    ].join(' │ ');

    lines.push(row);
  }

  lines.push('─'.repeat(header.length));

  // Summary
  lines.push('');
  lines.push(`Total: ${result.totalConstraints.toLocaleString()} constraints across ${result.circuits.length} circuits`);

  // Warnings
  if (options.warnings) {
    const warnings = result.circuits
      .map((c) => getWarningMessage(c))
      .filter((w): w is string => w !== null);

    if (warnings.length > 0) {
      lines.push('');
      for (const warning of warnings) {
        lines.push(warning);
      }
    }
  }

  // Verbose details
  if (options.verbose) {
    lines.push('');
    lines.push('Detailed Metrics:');
    lines.push('');

    for (const circuit of result.circuits) {
      lines.push(`${circuit.name}:`);
      lines.push(`  Constraints: ${circuit.constraints.toLocaleString()}`);
      lines.push(`  K-value: ${circuit.kValue}`);
      lines.push(`  ZKIR Size: ${formatBytes(circuit.zkirSize)}`);
      lines.push(`  Proof Size: ${formatBytes(circuit.proofSize)}`);
      lines.push(`  Proving Time: ${formatTime(circuit.provingTimeEstimate)} (estimated)`);
      lines.push(`  Memory: ~${Math.round(circuit.memoryEstimate / 1024)}GB (estimated)`);
      lines.push('');
    }
  }

  lines.push('');

  return lines.join('\n');
}

/**
 * Generate markdown report
 */
export function generateMarkdownReport(result: AnalysisResult, options: ReportOptions): string {
  const lines: string[] = [];

  // Header
  lines.push(`# Circuit Analysis: ${result.contractFile}`);
  lines.push('');
  lines.push(`**Generated:** ${result.timestamp}`);
  lines.push(`**Compilation Time:** ${result.compilationTime}ms`);
  if (result.compilerVersion) {
    lines.push(`**Compiler Version:** compact ${result.compilerVersion}`);
  }
  lines.push('');

  // Summary
  lines.push('## Summary');
  lines.push('');
  lines.push(`- **Total Circuits:** ${result.circuits.length}`);
  lines.push(`- **Total Constraints:** ${result.totalConstraints.toLocaleString()}`);
  lines.push('');

  // Circuits table
  if (result.circuits.length === 0) {
    lines.push('No circuits compiled.');
    return lines.join('\n');
  }

  lines.push('## Circuits');
  lines.push('');
  lines.push('| Circuit | Constraints | K-value | Proof Size | Proving Time (est) |');
  lines.push('|---------|-------------|---------|------------|-------------------|');

  for (const circuit of result.circuits) {
    lines.push(
      `| ${circuit.name} | ${circuit.constraints.toLocaleString()} | ${circuit.kValue} | ${formatBytes(circuit.proofSize)} | ${formatTime(circuit.provingTimeEstimate)} |`
    );
  }

  lines.push('');

  // Warnings
  if (options.warnings) {
    const largeCircuits = result.circuits.filter((c) => c.constraints > 100000);

    if (largeCircuits.length > 0) {
      lines.push('## Warnings');
      lines.push('');

      for (const circuit of largeCircuits) {
        const warning = getWarningMessage(circuit);
        if (warning) {
          lines.push(`### ${circuit.name}`);
          lines.push('');
          lines.push(warning.replace(/⚠️\s+Warning:\s+[^(]+\(/g, '('));
          lines.push('');
          lines.push('**Recommendations:**');
          lines.push('- Consider breaking into smaller circuits');
          lines.push('- Optimize expensive operations (hashing, Merkle proofs)');
          lines.push('- Review circuit logic for unnecessary constraints');
          lines.push('');
        }
      }
    }
  }

  // Detailed metrics
  if (options.verbose) {
    lines.push('## Detailed Metrics');
    lines.push('');

    for (const circuit of result.circuits) {
      lines.push(`### ${circuit.name}`);
      lines.push('');
      lines.push('| Metric | Value |');
      lines.push('|--------|-------|');
      lines.push(`| Constraints | ${circuit.constraints.toLocaleString()} |`);
      lines.push(`| K-value | ${circuit.kValue} |`);
      lines.push(`| ZKIR File Size | ${formatBytes(circuit.zkirSize)} |`);
      lines.push(`| Proof Size | ${formatBytes(circuit.proofSize)} |`);
      lines.push(`| Proving Time (estimated) | ${formatTime(circuit.provingTimeEstimate)} |`);
      lines.push(`| Memory (estimated) | ~${Math.round(circuit.memoryEstimate / 1024)}GB |`);
      lines.push('');
    }
  }

  // Footer
  lines.push('---');
  lines.push('');
  lines.push('*Generated by compact-security-analyzer (compact-coip-security/tools/security-analyzer)*');
  lines.push('');

  return lines.join('\n');
}

/**
 * Generate JSON report
 */
export function generateJsonReport(result: AnalysisResult): string {
  return JSON.stringify(result, null, 2);
}

/**
 * Generate and output report
 */
export function generateReport(result: AnalysisResult, options: ReportOptions): void {
  let content: string;

  switch (options.format) {
    case 'console':
      content = generateConsoleReport(result, options);
      break;
    case 'markdown':
      content = generateMarkdownReport(result, options);
      break;
    case 'json':
      content = generateJsonReport(result);
      break;
    default:
      throw new Error(`Unknown format: ${options.format}`);
  }

  if (options.outputFile) {
    writeFileSync(options.outputFile, content, 'utf-8');
    console.log(`✅ Report saved to: ${options.outputFile}`);
  } else {
    console.log(content);
  }
}
