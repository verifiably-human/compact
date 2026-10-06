/**
 * ZKIR circuit-size reader
 *
 * Reports each circuit's proving-domain size `k` (the circuit occupies at
 * most 2^k rows). `k` is the only size figure the analyzer reports, and it
 * is never estimated: it comes from the same code the proof server uses.
 *
 * The ZKIR major version is read from each file's header, and `k` is taken
 * from the first source that supports that version:
 *
 *   1. A local ZKIR package (`@midnight-ntwrk/zkir-v<major>`), whose
 *      `Zkir.getK()` computes `k` offline. Today only v2 is published.
 *   2. A proof server's `POST /k` endpoint, given the circuit's `.bzkir`
 *      file. This covers any ZKIR version the server's ledger supports,
 *      including v3 (`--feature-zkir-v3`). Configure it with
 *      `--proof-server <url>` or the `MIDNIGHT_PROOF_SERVER` variable.
 *
 * If neither is available, `k` is reported as unknown with the reason.
 * Earlier versions estimated constraints as `.zkir` size x 12. That was
 * off by 3-9 size steps (8x-512x) on measured circuits and did not even
 * preserve their order, so it has been removed, together with the proving
 * time, memory and proof size figures derived from it.
 */

import { readdirSync, readFileSync, statSync, existsSync } from 'fs';
import { createRequire } from 'module';
import { join } from 'path';
import type { CircuitMetrics, KSource, ZkirFileInfo } from './types.js';

const require = createRequire(import.meta.url);

/** `k` at or above which a circuit is flagged as expensive to prove. */
export const DEFAULT_LARGE_K = 17;

export interface CircuitSizeOptions {
  /** Proof server base URL, e.g. http://localhost:6300. */
  proofServer?: string;
  /** Per-request timeout for the proof server, in ms. */
  proofServerTimeoutMs?: number;
}

interface ZkirModule {
  Zkir: { fromJson(json: string): { getK(): number } };
}

/**
 * Parse .zkir files in a directory
 */
export function parseZkirDirectory(zkirDir: string): ZkirFileInfo[] {
  if (!existsSync(zkirDir)) {
    return [];
  }

  const zkirFiles: ZkirFileInfo[] = [];

  for (const file of readdirSync(zkirDir)) {
    if (file.endsWith('.zkir')) {
      const filePath = join(zkirDir, file);
      const name = file.replace(/\.zkir$/, '');
      const binaryPath = join(zkirDir, `${name}.bzkir`);

      zkirFiles.push({
        name,
        size: statSync(filePath).size,
        path: filePath,
        binaryPath: existsSync(binaryPath) ? binaryPath : undefined,
      });
    }
  }

  return zkirFiles;
}

/**
 * Read the ZKIR major version from a `.zkir` file's JSON header.
 */
export function readZkirMajorVersion(json: string): number | null {
  try {
    const major = JSON.parse(json)?.version?.major;
    return Number.isInteger(major) ? major : null;
  } catch {
    return null;
  }
}

const zkirModules = new Map<number, ZkirModule | null>();

/**
 * Load the local ZKIR package for a major version, if installed.
 */
function loadZkirModule(major: number): ZkirModule | null {
  if (!zkirModules.has(major)) {
    try {
      zkirModules.set(major, require(`@midnight-ntwrk/zkir-v${major}`) as ZkirModule);
    } catch {
      zkirModules.set(major, null);
    }
  }
  return zkirModules.get(major)!;
}

/**
 * Ask a proof server for a circuit's `k`.
 */
export async function fetchKFromProofServer(
  proofServer: string,
  bzkir: Uint8Array,
  timeoutMs = 30_000
): Promise<number> {
  const url = `${proofServer.replace(/\/+$/, '')}/k`;
  const response = await fetch(url, {
    method: 'POST',
    body: bzkir,
    signal: AbortSignal.timeout(timeoutMs),
  });
  const text = (await response.text()).trim();
  if (!response.ok) {
    throw new Error(`${url} returned HTTP ${response.status}: ${text.slice(0, 200)}`);
  }
  const k = Number(text);
  if (!Number.isInteger(k) || k < 0) {
    throw new Error(`${url} returned a non-integer k: ${text.slice(0, 200)}`);
  }
  return k;
}

/**
 * Determine a circuit's `k`, choosing the source by ZKIR version.
 */
export async function resolveCircuitK(
  zkir: ZkirFileInfo,
  options: CircuitSizeOptions = {}
): Promise<{ zkirVersion: number | null; kValue: number | null; kSource: KSource; kNote?: string }> {
  const json = readFileSync(zkir.path, 'utf8');
  const zkirVersion = readZkirMajorVersion(json);
  const reasons: string[] = [];

  if (zkirVersion !== null) {
    const local = loadZkirModule(zkirVersion);
    if (local) {
      try {
        return { zkirVersion, kValue: local.Zkir.fromJson(json).getK(), kSource: `zkir-v${zkirVersion}` };
      } catch (err) {
        reasons.push(`@midnight-ntwrk/zkir-v${zkirVersion} failed: ${err instanceof Error ? err.message : String(err)}`);
      }
    } else {
      reasons.push(`@midnight-ntwrk/zkir-v${zkirVersion} is not installed`);
    }
  } else {
    reasons.push('could not read the ZKIR version from the .zkir header');
  }

  const proofServer = options.proofServer ?? process.env.MIDNIGHT_PROOF_SERVER;
  if (proofServer) {
    if (zkir.binaryPath) {
      try {
        const kValue = await fetchKFromProofServer(
          proofServer,
          readFileSync(zkir.binaryPath),
          options.proofServerTimeoutMs
        );
        return { zkirVersion, kValue, kSource: 'proof-server' };
      } catch (err) {
        reasons.push(`proof server: ${err instanceof Error ? err.message : String(err)}`);
      }
    } else {
      reasons.push(`no ${zkir.name}.bzkir next to the .zkir file for the proof server`);
    }
  } else {
    reasons.push('no proof server configured (--proof-server or MIDNIGHT_PROOF_SERVER)');
  }

  return { zkirVersion, kValue: null, kSource: 'unavailable', kNote: reasons.join('; ') };
}

/**
 * Convert a ZKIR file to circuit metrics
 */
export async function zkirToMetrics(
  zkir: ZkirFileInfo,
  options: CircuitSizeOptions = {}
): Promise<CircuitMetrics> {
  const { zkirVersion, kValue, kSource, kNote } = await resolveCircuitK(zkir, options);

  return {
    name: zkir.name,
    zkirVersion,
    kValue,
    domainRows: kValue === null ? null : 2 ** kValue,
    kSource,
    kNote,
    zkirSize: zkir.size,
  };
}

/**
 * Parse all circuits from a compilation output directory
 */
export async function parseCircuits(
  zkirDir: string,
  options: CircuitSizeOptions = {}
): Promise<CircuitMetrics[]> {
  const metrics: CircuitMetrics[] = [];
  for (const zkir of parseZkirDirectory(zkirDir)) {
    metrics.push(await zkirToMetrics(zkir, options));
  }
  return metrics.sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * Check if a circuit's size warrants a warning
 */
export function shouldWarn(metrics: CircuitMetrics, largeK = DEFAULT_LARGE_K): boolean {
  return metrics.kValue !== null && metrics.kValue >= largeK;
}

/**
 * Get warning message for large circuits
 */
export function getWarningMessage(metrics: CircuitMetrics, largeK = DEFAULT_LARGE_K): string | null {
  if (!shouldWarn(metrics, largeK)) {
    return null;
  }

  return (
    `⚠️  Warning: ${metrics.name} has k=${metrics.kValue} (up to ${metrics.domainRows!.toLocaleString()} rows). ` +
    `Proving time roughly doubles with each step of k; measure it on your target hardware.`
  );
}

/**
 * Format `k` for display, with the reason when it is unknown.
 */
export function formatK(metrics: CircuitMetrics): string {
  return metrics.kValue === null ? 'unknown' : String(metrics.kValue);
}
