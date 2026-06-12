/**
 * ZKIR File Parser
 * Extracts constraint information from compiled .zkir files
 */

import { readdirSync, statSync, existsSync } from 'fs';
import { join } from 'path';
import type { CircuitMetrics, ZkirFileInfo } from './types.js';

/**
 * Parse .zkir files in a directory
 */
export function parseZkirDirectory(zkirDir: string): ZkirFileInfo[] {
  if (!existsSync(zkirDir)) {
    return [];
  }

  const files = readdirSync(zkirDir);
  const zkirFiles: ZkirFileInfo[] = [];

  for (const file of files) {
    if (file.endsWith('.zkir')) {
      const filePath = join(zkirDir, file);
      const stats = statSync(filePath);
      const name = file.replace('.zkir', '');

      zkirFiles.push({
        name,
        size: stats.size,
        path: filePath,
      });
    }
  }

  return zkirFiles;
}

/**
 * Calculate K-value from constraint count
 * K-value determines circuit size for Plonk proof system
 * Formula: k = ceil(log2(constraints)) + 1
 */
export function calculateKValue(constraints: number): number {
  if (constraints === 0) return 0;
  return Math.ceil(Math.log2(constraints)) + 1;
}

/**
 * Estimate proof size from K-value
 * Plonk proof size (approximate):
 * - ~64 bytes per public input
 * - ~640 bytes for commitments (G1 points)
 * - ~128 bytes for evaluation proof
 * - Total base: ~832 bytes + (64 * num_public_inputs)
 *
 * For typical circuits with few public inputs: ~1 KB base
 * Scales with circuit complexity: larger K = slightly larger proof
 */
export function estimateProofSize(kValue: number, publicInputs: number = 1): number {
  const baseSize = 832;
  const publicInputSize = 64 * publicInputs;
  // Add small overhead for larger circuits
  const complexityOverhead = Math.max(0, (kValue - 15) * 50);

  return baseSize + publicInputSize + complexityOverhead;
}

/**
 * Estimate proving time from constraint count
 * Based on empirical measurements:
 * - ~50-100 µs per constraint on modern hardware
 * - Dominated by MSM (Multi-Scalar Multiplication)
 * - Scales roughly linearly with constraint count
 *
 * These are rough estimates and vary significantly based on:
 * - CPU (single-threaded performance)
 * - RAM speed
 * - Circuit structure
 */
export function estimateProvingTime(constraints: number): number {
  // Microseconds per constraint (conservative estimate)
  const MICROSECONDS_PER_CONSTRAINT = 75;

  // Base overhead (circuit setup, etc.)
  const BASE_OVERHEAD_MS = 100;

  const computeTimeMs = (constraints * MICROSECONDS_PER_CONSTRAINT) / 1000;

  return (BASE_OVERHEAD_MS + computeTimeMs) / 1000; // Convert to seconds
}

/**
 * Estimate memory requirements from constraint count
 * Plonk proving requires:
 * - Witness data: ~32 bytes per constraint
 * - Polynomial data: ~32 bytes per constraint
 * - FFT workspace: ~64 bytes per constraint
 * - Total: ~128 bytes per constraint
 *
 * Plus fixed overhead for proof system: ~500 MB
 */
export function estimateMemoryUsage(constraints: number): number {
  const BYTES_PER_CONSTRAINT = 128;
  const BASE_OVERHEAD_MB = 500;

  const constraintMemoryMB = (constraints * BYTES_PER_CONSTRAINT) / (1024 * 1024);

  return Math.ceil(BASE_OVERHEAD_MB + constraintMemoryMB);
}

/**
 * Convert ZKIR file to circuit metrics
 * Uses empirical formula: constraints ≈ zkir_size * 12
 */
export function zkirToMetrics(zkir: ZkirFileInfo): CircuitMetrics {
  // Empirical formula from calibration: 1 byte ≈ 12 constraints
  const constraints = Math.round(zkir.size * 12);

  const kValue = calculateKValue(constraints);
  const proofSize = estimateProofSize(kValue);
  const provingTimeEstimate = estimateProvingTime(constraints);
  const memoryEstimate = estimateMemoryUsage(constraints);

  return {
    name: zkir.name,
    constraints,
    kValue,
    proofSize,
    zkirSize: zkir.size,
    provingTimeEstimate,
    memoryEstimate,
  };
}

/**
 * Parse all circuits from a compilation output directory
 */
export function parseCircuits(zkirDir: string): CircuitMetrics[] {
  const zkirFiles = parseZkirDirectory(zkirDir);
  return zkirFiles.map(zkirToMetrics);
}

/**
 * Check if a constraint count warrants a warning
 */
export function shouldWarn(constraints: number): boolean {
  // Warn if > 100K constraints (slow proving)
  return constraints > 100000;
}

/**
 * Get warning message for large circuits
 */
export function getWarningMessage(metrics: CircuitMetrics): string | null {
  if (!shouldWarn(metrics.constraints)) {
    return null;
  }

  const issues: string[] = [];

  if (metrics.provingTimeEstimate > 30) {
    issues.push(`Proving time: ~${Math.round(metrics.provingTimeEstimate)}s`);
  }

  if (metrics.memoryEstimate > 4000) {
    issues.push(`Memory: ~${Math.round(metrics.memoryEstimate / 1024)}GB`);
  }

  if (issues.length === 0) {
    return null;
  }

  return `⚠️  Warning: ${metrics.name} is a large circuit (${metrics.constraints.toLocaleString()} constraints)\n    ${issues.join(', ')}`;
}
