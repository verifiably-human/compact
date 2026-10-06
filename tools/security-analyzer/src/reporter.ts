/**
 * Report Generator
 * Generates circuit-size and security analysis reports in multiple formats
 */

import { writeFileSync } from 'fs';
import { basename, dirname } from 'path';
import type { AnalysisResult, CircuitMetrics, ReportOptions } from './types.js';
import { formatK, getWarningMessage } from './parser.js';
import { buildSarifLog, serialiseSarifLog } from './sarif.js';

/**
 * Format bytes as human-readable size
 */
function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * Format a circuit's row bound (2^k)
 */
function formatRows(circuit: CircuitMetrics): string {
  return circuit.domainRows === null ? 'unknown' : circuit.domainRows.toLocaleString();
}

/**
 * One-line size summary across all circuits
 */
function summaryLine(result: AnalysisResult): string {
  const largest = result.maxK === null ? 'unknown' : `k=${result.maxK}`;
  const unknown = result.unknownKCount > 0 ? `; k unknown for ${result.unknownKCount}` : '';
  return `${result.circuits.length} circuits; largest ${largest}${unknown}`;
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
    'k'.padStart(8),
    'Rows (≤ 2^k)'.padStart(14),
    'k source'.padStart(13),
  ].join(' │ ');

  lines.push(header);
  lines.push('─'.repeat(header.length));

  // Table rows
  for (const circuit of result.circuits) {
    const row = [
      circuit.name.padEnd(25),
      formatK(circuit).padStart(8),
      formatRows(circuit).padStart(14),
      circuit.kSource.padStart(13),
    ].join(' │ ');

    lines.push(row);
  }

  lines.push('─'.repeat(header.length));

  // Summary
  lines.push('');
  lines.push(summaryLine(result));
  for (const circuit of result.circuits.filter((c) => c.kNote)) {
    lines.push(`  ${circuit.name}: k unknown (${circuit.kNote})`);
  }

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
      lines.push(`  k: ${formatK(circuit)}${circuit.kNote ? ` (${circuit.kNote})` : ''}`);
      lines.push(`  Rows: ${formatRows(circuit)}`);
      lines.push(`  k source: ${circuit.kSource}`);
      lines.push(`  ZKIR version: ${circuit.zkirVersion ?? 'unknown'}`);
      lines.push(`  ZKIR Size: ${formatBytes(circuit.zkirSize)}`);
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
  lines.push(`- **Largest k:** ${result.maxK ?? 'unknown'}`);
  if (result.unknownKCount > 0) {
    lines.push(`- **Circuits with unknown k:** ${result.unknownKCount}`);
  }
  lines.push('');

  // Circuits table
  if (result.circuits.length === 0) {
    lines.push('No circuits compiled.');
    return lines.join('\n');
  }

  lines.push('## Circuits');
  lines.push('');
  lines.push('| Circuit | k | Rows (≤ 2^k) | k source |');
  lines.push('|---------|---|--------------|----------|');

  for (const circuit of result.circuits) {
    lines.push(
      `| ${circuit.name} | ${formatK(circuit)} | ${formatRows(circuit)} | ${circuit.kSource}${circuit.kNote ? ` (${circuit.kNote})` : ''} |`
    );
  }

  lines.push('');

  // Warnings
  if (options.warnings) {
    const largeCircuits = result.circuits.filter((c) => getWarningMessage(c) !== null);

    if (largeCircuits.length > 0) {
      lines.push('## Warnings');
      lines.push('');

      for (const circuit of largeCircuits) {
        const warning = getWarningMessage(circuit);
        if (warning) {
          lines.push(`### ${circuit.name}`);
          lines.push('');
          lines.push(warning.replace(/^⚠️\s+Warning:\s+/, ''));
          lines.push('');
          lines.push('**Recommendations:**');
          lines.push('- Consider breaking into smaller circuits');
          lines.push('- Optimize expensive operations (elliptic-curve multiplication, hashing, Merkle proofs)');
          lines.push('- A reduction only helps once the circuit drops below the next power of two');
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
      lines.push(`| k | ${formatK(circuit)} |`);
      lines.push(`| Rows (≤ 2^k) | ${formatRows(circuit)} |`);
      lines.push(`| k source | ${circuit.kSource}${circuit.kNote ? ` (${circuit.kNote})` : ''} |`);
      lines.push(`| ZKIR version | ${circuit.zkirVersion ?? 'unknown'} |`);
      lines.push(`| ZKIR File Size | ${formatBytes(circuit.zkirSize)} |`);
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
    case 'sarif':
      content = serialiseSarifLog(buildSarifLog({
        result,
        toolVersion: '1.0.0',
        contractUri: basename(result.contractFile),
        contractSrcDir: dirname(result.contractFile),
      }));
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
