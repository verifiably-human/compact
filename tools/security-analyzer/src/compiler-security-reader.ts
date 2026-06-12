/**
 * Compiler Security Analysis Reader
 *
 * Consumes `compiler/security-analysis.json` emitted by the Compact compiler.
 * Schema: COIP "Machine-readable security-analysis output from the Compact
 * compiler", v1.0.0.
 *
 * See coips/coip-xxxx-security-analysis-output.md for the canonical schema.
 */

import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import type {
  SecurityFinding,
  SecurityAnalysisResult,
  SecuritySeverity,
} from './security-analyzer.js';

const SUPPORTED_SCHEMA_MAJOR = 1;

// ---------------------------------------------------------------------------
// COIP v1.0.0 schema types
// ---------------------------------------------------------------------------

export type SrcLoc =
  | { file: string; line: number; column: number }
  | { file: string; character: number };

export type Origin =
  | { kind: 'witness-return-value'; function: string; location: SrcLoc }
  | { kind: 'constructor-argument'; argument: string; location: SrcLoc }
  | {
      kind: 'circuit-argument';
      function: string;
      argument: string;
      location: SrcLoc;
    };

export interface Point {
  description: string;
  location: SrcLoc;
  exposure: string | null;
}

export interface Path {
  points: Point[];
  final_exposure: string;
}

export interface Witness {
  origin: Origin;
  paths: Path[];
}

export interface Disclosure {
  location: SrcLoc;
  witnesses: Witness[];
}

export interface Leak {
  location: SrcLoc;
  what: string;
  witnesses: Witness[];
}

export interface CompilerSecurityAnalysis {
  schema_version: string;
  status: 'clean' | 'leaks-found';
  witness_count: number;
  leaks: Leak[];
  disclosures: Disclosure[];
}

// ---------------------------------------------------------------------------
// File I/O
// ---------------------------------------------------------------------------

/**
 * Read `<outputDir>/compiler/security-analysis.json`.
 *
 * Returns `null` if the file is missing (compile failed, or the compiler does
 * not yet emit this artifact). Returns `null` and warns if the schema major
 * version is not supported by this reader.
 */
export function readCompilerSecurityAnalysis(
  outputDir: string
): CompilerSecurityAnalysis | null {
  const path = join(outputDir, 'compiler', 'security-analysis.json');

  if (!existsSync(path)) {
    return null;
  }

  let data: CompilerSecurityAnalysis;
  try {
    data = JSON.parse(readFileSync(path, 'utf8')) as CompilerSecurityAnalysis;
  } catch (error) {
    const msg = error instanceof Error ? error.message : 'Unknown error';
    console.warn(`⚠️  Failed to parse ${path}: ${msg}`);
    return null;
  }

  const declaredMajor = parseSchemaMajor(data.schema_version);
  if (declaredMajor === null) {
    console.warn(
      `⚠️  ${path}: missing or malformed schema_version (got ${JSON.stringify(data.schema_version)})`
    );
    return null;
  }
  if (declaredMajor !== SUPPORTED_SCHEMA_MAJOR) {
    console.warn(
      `⚠️  ${path}: schema_version ${data.schema_version} is incompatible with this reader (supports ${SUPPORTED_SCHEMA_MAJOR}.x.x)`
    );
    return null;
  }

  return data;
}

function parseSchemaMajor(version: unknown): number | null {
  if (typeof version !== 'string') return null;
  const match = version.match(/^(\d+)\./);
  return match ? Number(match[1]) : null;
}

// ---------------------------------------------------------------------------
// Conversion to internal SecurityFinding shape
// ---------------------------------------------------------------------------

/**
 * Convert the compiler's analysis into the internal finding list.
 *
 * - Every leak becomes a `critical` finding. In practice the file is only
 *   emitted on successful compiles, so `leaks` is empty — the schema reserves
 *   the field for forward compatibility.
 * - Every disclosure becomes a finding. Severity depends on `final_exposure`:
 *   a raw witness disclosure (`"the witness value"`) is `high`; any
 *   transformation (hash, commitment, …) is `info` because the compiler
 *   accepted it as an intentional privacy-preserving disclosure.
 */
export function convertCompilerFindings(
  analysis: CompilerSecurityAnalysis
): SecurityAnalysisResult {
  const findings: SecurityFinding[] = [
    ...analysis.leaks.flatMap(leakToFindings),
    ...analysis.disclosures.flatMap(disclosureToFindings),
  ];

  const summary = summarize(findings);
  const riskScore = score(summary);

  return { findings, riskScore, summary };
}

function leakToFindings(leak: Leak): SecurityFinding[] {
  return leak.witnesses.flatMap((w) =>
    w.paths.map((p) => buildFinding('leak', leak.location, w, p, leak.what))
  );
}

function disclosureToFindings(disclosure: Disclosure): SecurityFinding[] {
  return disclosure.witnesses.flatMap((w) =>
    w.paths.map((p) =>
      buildFinding('disclose', disclosure.location, w, p, null)
    )
  );
}

function buildFinding(
  kind: 'leak' | 'disclose',
  siteLoc: SrcLoc,
  witness: Witness,
  path: Path,
  leakWhat: string | null
): SecurityFinding {
  const isLeak = kind === 'leak';
  const isRaw = path.final_exposure === 'the witness value';

  const severity: SecuritySeverity = isLeak
    ? 'critical'
    : isRaw
      ? 'high'
      : 'info';

  const originLabel = describeOrigin(witness.origin);
  const circuit = circuitOf(witness.origin);
  const siteDesc = isLeak
    ? `leak site (${leakWhat ?? 'unknown'})`
    : `disclose() call`;
  const trace = renderPath(path);

  return {
    type: 'privacy-leak',
    severity,
    title: isLeak
      ? `Compiler-detected leak: ${path.final_exposure} reaches ${leakWhat ?? 'a leak site'}`
      : isRaw
        ? `Direct witness disclosure in ${circuit}`
        : `Transformed witness disclosure in ${circuit} (${path.final_exposure})`,
    description: [
      `Source: ${originLabel}`,
      `Site:   ${siteDesc} at ${formatLoc(siteLoc)}`,
      `Result: ${path.final_exposure}`,
      '',
      'Data-flow path (origin → site):',
      trace,
    ].join('\n'),
    location: {
      circuit,
      line: lineOf(siteLoc),
      code: `${formatLoc(siteLoc)} — ${path.final_exposure}`,
    },
    recommendation: isLeak
      ? 'The compiler refused to compile this. Add an explicit `disclose()` only if the exposure is intended; otherwise rewrite to keep the witness value private.'
      : isRaw
        ? 'A raw witness value is being disclosed on-chain. Confirm this is intentional. Where possible, disclose a commitment (e.g. `persistentHash(value)`) instead of the value itself.'
        : 'The compiler accepted this as an intentional privacy-preserving disclosure. Reviewer should confirm the transformation provides the intended privacy property.',
    impact: isLeak
      ? 'CRITICAL: An unintended witness exposure that the compiler blocked. Compilation cannot succeed until resolved.'
      : isRaw
        ? 'HIGH: The witness value itself is published. Anything reading on-chain state learns the secret.'
        : 'INFO: A derived value is published. Privacy depends on the chosen transformation being one-way / hiding.',
  };
}

// ---------------------------------------------------------------------------
// Origin / location helpers
// ---------------------------------------------------------------------------

function describeOrigin(origin: Origin): string {
  switch (origin.kind) {
    case 'witness-return-value':
      return `witness function \`${origin.function}\` (declared at ${formatLoc(origin.location)})`;
    case 'constructor-argument':
      return `constructor argument \`${origin.argument}\` (${formatLoc(origin.location)})`;
    case 'circuit-argument':
      return `argument \`${origin.argument}\` of circuit \`${origin.function}\` (${formatLoc(origin.location)})`;
  }
}

function circuitOf(origin: Origin): string {
  switch (origin.kind) {
    case 'witness-return-value':
    case 'circuit-argument':
      return origin.function;
    case 'constructor-argument':
      return 'constructor';
  }
}

function formatLoc(loc: SrcLoc): string {
  if ('line' in loc) return `${loc.file}:${loc.line}:${loc.column}`;
  return `${loc.file}@${loc.character}`;
}

function lineOf(loc: SrcLoc): number | undefined {
  return 'line' in loc ? loc.line : undefined;
}

function renderPath(path: Path): string {
  if (path.points.length === 0) {
    return '  (direct — no intermediate transformations)';
  }
  return path.points
    .map((p, i) => {
      const expo = p.exposure ? ` [exposure: ${p.exposure}]` : '';
      return `  ${i + 1}. ${p.description} @ ${formatLoc(p.location)}${expo}`;
    })
    .join('\n');
}

// ---------------------------------------------------------------------------
// Merge with heuristic findings
// ---------------------------------------------------------------------------

/**
 * Combine compiler findings with heuristic findings.
 *
 * Compiler findings are authoritative for privacy-leak claims; heuristic
 * privacy-leak findings that target a circuit the compiler already covered are
 * dropped. All other heuristic findings (access control, nullifier reuse, etc.)
 * are preserved and annotated.
 *
 * If the compiler analysis is unavailable, heuristic findings are returned
 * with a `[Heuristic]` prefix so reports make the provenance obvious.
 */
export function mergeSecurityFindings(
  compilerFindings: SecurityAnalysisResult | null,
  heuristicFindings: SecurityAnalysisResult
): SecurityAnalysisResult {
  if (!compilerFindings) {
    const annotated = heuristicFindings.findings.map((f) => ({
      ...f,
      title: `[Heuristic] ${f.title}`,
      description: `${f.description}\n\nNote: pattern-match heuristic, not semantic analysis. May be a false positive.`,
    }));
    return { ...heuristicFindings, findings: annotated };
  }

  const compilerCircuits = new Set(
    compilerFindings.findings
      .map((f) => f.location?.circuit)
      .filter((c): c is string => Boolean(c))
  );

  const all: SecurityFinding[] = [...compilerFindings.findings];

  for (const f of heuristicFindings.findings) {
    const circuit = f.location?.circuit;
    if (f.type === 'privacy-leak' && circuit && compilerCircuits.has(circuit)) {
      continue;
    }
    all.push({
      ...f,
      title: `[Heuristic] ${f.title}`,
      description: `${f.description}\n\nNote: pattern-match heuristic. Consider it a suggestion for manual review.`,
    });
  }

  const summary = summarize(all);
  return { findings: all, riskScore: score(summary), summary };
}

function summarize(
  findings: SecurityFinding[]
): SecurityAnalysisResult['summary'] {
  return {
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
    info: findings.filter((f) => f.severity === 'info').length,
  };
}

function score(summary: SecurityAnalysisResult['summary']): number {
  return Math.min(
    100,
    summary.critical * 20 +
      summary.high * 10 +
      summary.medium * 5 +
      summary.low * 2 +
      summary.info * 0.5
  );
}
