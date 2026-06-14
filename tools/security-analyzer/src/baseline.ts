/**
 * Baseline file handling. See specs/SPEC-1-baselines.md.
 *
 *   - load(path): reads and validates a baseline file.
 *   - apply(findings, baseline, mode): returns the filtered/annotated
 *     finding set plus accounting metadata.
 *   - write(path, baseline): emits a baseline file.
 *   - generate(currentFindings, prior?, reasonByIdFn): constructs a
 *     fresh baseline from the current findings (used by
 *     --update-baseline).
 *
 * The applier is uniform across security, nonce, and correlator
 * findings — anything with an `id` field that matches one of the three
 * recognised prefixes (sec-, nonce-, corr-).
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { isWellFormedFindingId } from './finding-id.js';
import type { SecurityFinding, FindingAck, SecuritySeverity } from './security-analyzer.js';
import type { NonceFinding, Correlator } from './types.js';

export const BASELINE_SCHEMA_VERSION = '1.0.0';

export type BaselineMode = 'suppress' | 'downgrade-to-info' | 'accounting-only';

export interface BaselineFile {
  schema_version: '1.0.0';
  generated_by: string;
  generated_at: string;
  contract_path_glob?: string;
  acks: AckEntry[];
}

export interface AckEntry {
  id: string;
  rule?: string;
  severity_at_time_of_ack: SecuritySeverity;
  title: string;
  ack_by: string;
  ack_at: string;
  ack_reason: string;
  ack_expires_at: string | null;
}

export interface BaselineApplication {
  acksApplied: number;
  netNewFindings: number;
  acksExpired: AckEntry[];
  acksUnmatched: AckEntry[]; // entries in the baseline that no current finding matches
  filteredSecurity: SecurityFinding[];
  filteredNonce: NonceFinding[];
  filteredCorrelator: Correlator[];
  suppressedSecurity: SecurityFinding[];
  suppressedNonce: NonceFinding[];
  suppressedCorrelator: Correlator[];
}

export interface BaselineLoadResult {
  baseline: BaselineFile;
  warnings: string[];
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

export function loadBaseline(path: string): BaselineLoadResult {
  if (!existsSync(path)) {
    throw new Error(`Baseline file not found: ${path}`);
  }
  const text = readFileSync(path, 'utf-8');
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    throw new Error(`Baseline file is not valid JSON: ${path} (${(e as Error).message})`);
  }
  return validateBaseline(raw, path);
}

export function validateBaseline(raw: unknown, source = '<inline>'): BaselineLoadResult {
  const warnings: string[] = [];
  if (typeof raw !== 'object' || raw === null) {
    throw new Error(`${source}: baseline must be an object`);
  }
  const obj = raw as Record<string, unknown>;
  if (obj.schema_version !== '1.0.0') {
    throw new Error(`${source}: unsupported schema_version "${String(obj.schema_version)}"; expected "1.0.0"`);
  }
  if (!Array.isArray(obj.acks)) {
    throw new Error(`${source}: missing acks array`);
  }

  const acks: AckEntry[] = [];
  for (let i = 0; i < obj.acks.length; i++) {
    const entry = obj.acks[i] as Record<string, unknown>;
    const where = `${source}: acks[${i}]`;
    if (typeof entry?.id !== 'string') throw new Error(`${where}: missing id`);
    if (!isWellFormedFindingId(entry.id)) {
      warnings.push(`${where}: id "${entry.id}" does not match the expected shape (sec|nonce|corr)-<12 hex>`);
    }
    if (typeof entry.ack_by !== 'string' || !entry.ack_by) throw new Error(`${where}: ack_by is required`);
    if (typeof entry.ack_at !== 'string') throw new Error(`${where}: ack_at is required (ISO-8601)`);
    if (typeof entry.ack_reason !== 'string' || !entry.ack_reason.trim()) {
      throw new Error(`${where}: ack_reason is required and must be non-empty`);
    }
    if (typeof entry.title !== 'string') throw new Error(`${where}: title is required`);
    if (
      typeof entry.severity_at_time_of_ack !== 'string' ||
      !['critical', 'high', 'medium', 'low', 'info'].includes(entry.severity_at_time_of_ack)
    ) {
      throw new Error(`${where}: severity_at_time_of_ack must be one of critical|high|medium|low|info`);
    }
    if (entry.ack_expires_at != null && typeof entry.ack_expires_at !== 'string') {
      throw new Error(`${where}: ack_expires_at must be a string or null`);
    }
    acks.push({
      id: entry.id,
      rule: typeof entry.rule === 'string' ? entry.rule : undefined,
      severity_at_time_of_ack: entry.severity_at_time_of_ack as SecuritySeverity,
      title: entry.title,
      ack_by: entry.ack_by,
      ack_at: entry.ack_at,
      ack_reason: entry.ack_reason,
      ack_expires_at: (entry.ack_expires_at as string | null) ?? null,
    });
  }

  return {
    baseline: {
      schema_version: '1.0.0',
      generated_by: typeof obj.generated_by === 'string' ? obj.generated_by : 'unknown',
      generated_at: typeof obj.generated_at === 'string' ? obj.generated_at : new Date(0).toISOString(),
      contract_path_glob: typeof obj.contract_path_glob === 'string' ? obj.contract_path_glob : undefined,
      acks,
    },
    warnings,
  };
}

// ---------------------------------------------------------------------------
// Applier
// ---------------------------------------------------------------------------

/**
 * Build a baseline equivalent to the inline `@audit-ack: <id>`
 * annotations in the contract source. Returns one synthetic ack entry
 * per annotation. The reason is the trailing reason lines of the
 * annotation; falls back to a generic message if absent.
 */
export function inlineAnnotationAcks(
  annotationsByCircuit: Map<string, { key: string; tag: string; reason: string; line: number }[]>,
  now: Date = new Date(),
): AckEntry[] {
  const acks: AckEntry[] = [];
  for (const [circuit, annos] of annotationsByCircuit) {
    for (const a of annos) {
      if (a.key !== 'audit-ack') continue;
      // The "tag" field carries the finding ID for audit-ack annotations.
      if (!isWellFormedFindingId(a.tag)) continue;
      acks.push({
        id: a.tag,
        rule: undefined,
        severity_at_time_of_ack: 'info',
        title: `[inline @audit-ack on circuit ${circuit}]`,
        ack_by: 'inline-annotation',
        ack_at: now.toISOString(),
        ack_reason: a.reason || `Acknowledged in-source on circuit ${circuit}`,
        ack_expires_at: null,
      });
    }
  }
  return acks;
}

/**
 * Apply a baseline plus optional inline acks to the analyzer's output.
 * The returned filtered* arrays carry the findings that should be
 * surfaced under the chosen mode; the suppressed* arrays carry the
 * acked findings (still useful for the report's "Suppressed" section).
 *
 * Accounting:
 *   - For modes `suppress` and `downgrade-to-info`, acked critical/high
 *     findings are NOT counted as net-new.
 *   - For mode `accounting-only`, findings stay visible but the
 *     net-new tally excludes them.
 */
export function applyBaseline(input: {
  security: SecurityFinding[];
  nonce: NonceFinding[];
  correlator: Correlator[];
  fileAcks: AckEntry[];
  inlineAcks: AckEntry[];
  mode: BaselineMode;
  now?: Date;
}): BaselineApplication {
  const now = input.now ?? new Date();
  const ackById = new Map<string, { entry: AckEntry; source: FindingAck['source'] }>();
  const acksExpired: AckEntry[] = [];

  // Inline annotations first so file acks can override (file ack has
  // richer metadata); both are recorded with their source.
  for (const a of input.inlineAcks) {
    if (a.ack_expires_at && new Date(a.ack_expires_at) < now) {
      acksExpired.push(a);
      continue;
    }
    ackById.set(a.id, { entry: a, source: 'inline-annotation' });
  }
  for (const a of input.fileAcks) {
    if (a.ack_expires_at && new Date(a.ack_expires_at) < now) {
      acksExpired.push(a);
      continue;
    }
    ackById.set(a.id, { entry: a, source: 'baseline-file' });
  }

  const consumed = new Set<string>();

  const result: BaselineApplication = {
    acksApplied: 0,
    netNewFindings: 0,
    acksExpired,
    acksUnmatched: [],
    filteredSecurity: [],
    filteredNonce: [],
    filteredCorrelator: [],
    suppressedSecurity: [],
    suppressedNonce: [],
    suppressedCorrelator: [],
  };

  const handle = <T extends { id?: string; severity?: SecuritySeverity }>(
    findings: T[],
    intoFiltered: T[],
    intoSuppressed: T[],
    decorate: (finding: T, ack: FindingAck) => T,
  ): void => {
    for (const f of findings) {
      const ackHit = f.id ? ackById.get(f.id) : undefined;
      if (!ackHit) {
        intoFiltered.push(f);
        if (f.severity === 'critical' || f.severity === 'high') {
          result.netNewFindings += 1;
        }
        continue;
      }
      consumed.add(ackHit.entry.id);
      result.acksApplied += 1;
      const escalated =
        ackHit.entry.severity_at_time_of_ack !== undefined &&
        rankSeverity(f.severity!) > rankSeverity(ackHit.entry.severity_at_time_of_ack);
      const ackFor: FindingAck = {
        source: ackHit.source,
        by: ackHit.entry.ack_by,
        at: ackHit.entry.ack_at,
        reason: ackHit.entry.ack_reason,
        expiresAt: ackHit.entry.ack_expires_at ?? undefined,
        severityAtAck: ackHit.entry.severity_at_time_of_ack,
        severityEscalatedSinceAck: escalated,
      };
      const decorated = decorate(f, ackFor);
      intoSuppressed.push(decorated);

      if (input.mode === 'accounting-only') {
        intoFiltered.push(decorated);
      } else if (input.mode === 'downgrade-to-info') {
        intoFiltered.push({ ...decorated, severity: 'info' } as T);
      }
      // mode === 'suppress' → not pushed to filtered
    }
  };

  handle(
    input.security,
    result.filteredSecurity,
    result.suppressedSecurity,
    (finding, ack) => ({ ...finding, ack }),
  );
  handle(
    input.nonce,
    result.filteredNonce,
    result.suppressedNonce,
    (finding, ack) => ({ ...finding, ack } as NonceFinding & { ack: FindingAck }),
  );
  handle(
    input.correlator,
    result.filteredCorrelator,
    result.suppressedCorrelator,
    (finding, ack) => ({ ...finding, ack } as Correlator & { ack: FindingAck }),
  );

  // Acks in the baseline that no current finding matched. Worth surfacing
  // because they likely mean the finding moved (renamed circuit) or was
  // genuinely fixed and the ack should be deleted.
  for (const [, ackHit] of ackById) {
    if (!consumed.has(ackHit.entry.id) && ackHit.source === 'baseline-file') {
      result.acksUnmatched.push(ackHit.entry);
    }
  }

  return result;
}

function rankSeverity(s: SecuritySeverity): number {
  switch (s) {
    case 'critical': return 4;
    case 'high': return 3;
    case 'medium': return 2;
    case 'low': return 1;
    case 'info': return 0;
  }
}

// ---------------------------------------------------------------------------
// Writer / generator
// ---------------------------------------------------------------------------

/**
 * Construct a baseline file body from the current finding set. If a
 * prior baseline is supplied, its existing acks are preserved (so an
 * --update-baseline run only adds new entries).
 *
 * `reasonByIdFn` is called for each NEW finding (no prior ack). If it
 * returns null/empty, that finding is NOT added to the baseline (the
 * caller is responsible for noting any skipped entries).
 */
export function generateBaseline(input: {
  security: SecurityFinding[];
  nonce: NonceFinding[];
  correlator: Correlator[];
  prior?: BaselineFile;
  reasonByIdFn: (id: string, finding: SecurityFinding | NonceFinding | Correlator) => string | null;
  ackBy: string;
  toolVersion: string;
  now?: Date;
}): BaselineFile {
  const now = input.now ?? new Date();
  const priorById = new Map<string, AckEntry>();
  if (input.prior) for (const a of input.prior.acks) priorById.set(a.id, a);

  const out: AckEntry[] = [];
  const consider = <T extends { id?: string; severity: SecuritySeverity; title?: string }>(findings: T[]) => {
    for (const f of findings) {
      if (!f.id) continue;
      const prior = priorById.get(f.id);
      if (prior) {
        out.push(prior); // preserve unchanged
        continue;
      }
      const reason = input.reasonByIdFn(f.id, f as unknown as SecurityFinding);
      if (!reason || !reason.trim()) continue;
      out.push({
        id: f.id,
        rule: undefined,
        severity_at_time_of_ack: f.severity,
        title: f.title ?? `<finding ${f.id}>`,
        ack_by: input.ackBy,
        ack_at: now.toISOString(),
        ack_reason: reason,
        ack_expires_at: null,
      });
    }
  };
  consider(input.security);
  consider(input.nonce);
  consider(input.correlator);

  return {
    schema_version: '1.0.0',
    generated_by: input.toolVersion,
    generated_at: now.toISOString(),
    contract_path_glob: input.prior?.contract_path_glob,
    acks: out,
  };
}

export function writeBaseline(path: string, baseline: BaselineFile): void {
  writeFileSync(path, JSON.stringify(baseline, null, 2) + '\n', 'utf-8');
}
