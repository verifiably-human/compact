/**
 * Stable ID derivation for security findings.
 *
 * Per SPEC-1, IDs are content-addressed: the same logical finding maps
 * to the same ID across runs, even when the report ordering or unrelated
 * parts of the contract change. Baselines (.security-analyzer-baseline.json)
 * and inline `@audit-ack: <id>` annotations reference these.
 *
 * Stability guarantees:
 *   - Stable across whitespace-only edits to unrelated circuits.
 *   - Stable across adding/removing unrelated circuits/witnesses.
 *   - Intentionally NOT stable across renaming the affected circuit, the
 *     affected witness, or moving the contract file (treated as a new
 *     finding so the human re-reviews).
 *
 * ID format across analyzer kinds:
 *   sec-<sha12>    security findings (this module)
 *   nonce-<sha12>  nonce findings (see nonce-analyzer.ts::makeId)
 *   corr-<sha12>   correlator findings (see correlator-analyzer.ts)
 *
 * Baselines and the `@audit-ack` annotation accept any of the three
 * prefixes; the consumer matches against actual findings.
 */

import { createHash } from 'node:crypto';
import type { SecurityFinding } from './security-analyzer.js';

const ID_PREFIX_SECURITY = 'sec';
const ID_HASH_LENGTH = 12;

function sha256Prefix(input: string): string {
  return createHash('sha256').update(input).digest('hex').slice(0, ID_HASH_LENGTH);
}

/**
 * Most analyzer titles take the form `<rule label>: <target>`
 * (e.g. "Missing authorization check: processCompliantPayment").
 * The target is what differentiates instances of the same rule.
 *
 * Falls back to the full title if no colon is present.
 */
function extractTarget(title: string): string {
  const colon = title.indexOf(':');
  if (colon < 0) return title.trim();
  return title.slice(colon + 1).trim();
}

/**
 * Strip leading bracketed tags such as `[Heuristic]` or `[Compiler]`
 * from the title so the ID doesn't change when a finding is promoted
 * between sources (e.g. heuristic detection getting compiler-confirmed).
 */
function stripSourceTag(title: string): string {
  return title.replace(/^\s*\[[^\]]+\]\s*/, '');
}

/**
 * Derive the stable rule key from a SecurityFinding's `type` and title.
 * Multiple titles can share a rule (every "Missing authorization check"
 * finding shares `access-control:missing`, varying only by target).
 */
export function deriveRuleKey(finding: SecurityFinding): string {
  const stripped = stripSourceTag(finding.title);
  switch (finding.type) {
    case 'access-control':
      if (/^Missing authorization check/i.test(stripped)) return 'access-control:missing';
      if (/^Disabled authorization check/i.test(stripped)) return 'access-control:disabled';
      return 'access-control:other';
    case 'privacy-leak':
      return 'privacy-leak';
    case 'state-mutation':
      return 'state-mutation';
    case 'nullifier':
      return 'nullifier';
    case 'taint':
      return 'taint';
    case 'side-channel':
      return 'side-channel';
    case 'info-flow':
      return 'info-flow';
    default:
      return `unknown:${(finding as { type: string }).type}`;
  }
}

/**
 * Stable ID for a security finding. Idempotent: re-running on the same
 * finding produces the same string.
 */
export function deriveSecurityFindingId(finding: SecurityFinding): string {
  const rule = deriveRuleKey(finding);
  const circuit = finding.location?.circuit ?? 'global';
  const target = extractTarget(stripSourceTag(finding.title));
  return `${ID_PREFIX_SECURITY}-${sha256Prefix(`${rule}|${circuit}|${target}`)}`;
}

/**
 * Loose well-formedness check for an externally-provided ID (from a
 * baseline file or inline annotation). Accepts any analyzer-kind prefix.
 */
export function isWellFormedFindingId(id: string): boolean {
  return /^(sec|nonce|corr)-[0-9a-f]{12}$/.test(id);
}

/**
 * Walk an array of SecurityFindings and assign each one a stable ID
 * in-place (only if not already set). Returns the same array for
 * chaining.
 */
export function addIdsToSecurityFindings(findings: SecurityFinding[]): SecurityFinding[] {
  for (const f of findings) {
    if (!f.id) f.id = deriveSecurityFindingId(f);
  }
  return findings;
}
