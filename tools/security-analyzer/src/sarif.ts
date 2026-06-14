/**
 * SARIF 2.1.0 serialiser. See specs/SPEC-2-sarif.md.
 *
 * Converts the analyzer's AnalysisResult into a SARIF run document
 * suitable for upload via `github/codeql-action/upload-sarif` or any
 * other consumer that speaks SARIF 2.1.0.
 *
 * Mapping summary:
 *   - One Result per finding (security + nonce + correlator).
 *   - Suppressed findings (acked via baseline or @audit-ack) keep
 *     their original severity in level/properties but emit a
 *     `suppressions` array so GitHub Code Scanning surfaces them as
 *     "dismissed by tool".
 *   - `tool.driver.rules` lists every defined rule (not only rules
 *     that fired) so on-hover help text is available in the GH UI.
 *   - Stable IDs are mirrored into partialFingerprints to let
 *     consumers correlate findings across runs.
 */

import type { AnalysisResult } from './types.js';
import type { SecurityFinding, SecuritySeverity } from './security-analyzer.js';
import type { NonceFinding, Correlator } from './types.js';
import { deriveRuleKey } from './finding-id.js';

export type SarifLevel = 'error' | 'warning' | 'note' | 'none';

export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: SarifRun[];
}

export interface SarifRun {
  tool: { driver: SarifToolDriver };
  results: SarifResult[];
  // Per the spec, originalUriBaseIds is recommended so consumers can
  // resolve relative artifact URIs. We default to the contract's parent
  // directory.
  originalUriBaseIds?: Record<string, { uri: string }>;
}

export interface SarifToolDriver {
  name: string;
  version: string;
  informationUri: string;
  rules: SarifRule[];
}

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription?: { text: string };
  defaultConfiguration?: { level: SarifLevel };
  helpUri?: string;
  help?: { text: string };
}

export interface SarifResult {
  ruleId: string;
  level: SarifLevel;
  message: { text: string };
  locations: SarifLocation[];
  partialFingerprints?: Record<string, string>;
  properties?: Record<string, unknown>;
  suppressions?: { kind: 'inSource' | 'external'; justification?: string }[];
}

export interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string; uriBaseId?: string };
    region?: { startLine: number; endLine?: number };
  };
}

const TOOL_INFO_URI = 'https://github.com/verifiably-human/compact';

/** Severity → SARIF level. critical/high → error; medium → warning; low/info → note. */
function levelFromSeverity(sev: SecuritySeverity | undefined): SarifLevel {
  switch (sev) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'info':
      return 'note';
    default:
      return 'none';
  }
}

/**
 * All rules the analyzer can emit. Listed in full so the GitHub Code
 * Scanning UI has help text for any finding the user clicks, even on
 * runs where that particular rule didn't fire. Adding a new rule
 * requires extending this list.
 */
function allRules(): SarifRule[] {
  return [
    {
      id: 'access-control:missing',
      name: 'MissingAuthorizationCheck',
      shortDescription: { text: 'Circuit lacks an authorization check' },
      fullDescription: {
        text: 'An exported circuit mutates ledger state with no recognised auth guard. Anyone holding a wallet can call it. Either add a guard (require/assert), gate via witness, or add the @access-control annotation to document intent.',
      },
      defaultConfiguration: { level: 'error' },
      helpUri: 'https://github.com/verifiably-human/compact/blob/main/tools/security-analyzer/SECURITY_ANALYSIS.md#access-control',
    },
    {
      id: 'access-control:disabled',
      name: 'DisabledAuthorizationCheck',
      shortDescription: { text: 'Authorization check is commented out' },
      fullDescription: {
        text: 'A guard call is present in the source but commented out (e.g. `// requireOwner();`). The circuit runs without the guard at runtime. Restore the call or delete the commented line.',
      },
      defaultConfiguration: { level: 'error' },
    },
    {
      id: 'access-control:other',
      name: 'AccessControlOther',
      shortDescription: { text: 'Access-control anomaly' },
      defaultConfiguration: { level: 'warning' },
    },
    {
      id: 'privacy-leak',
      name: 'PrivacyLeak',
      shortDescription: { text: 'Witness data is disclosed publicly' },
      fullDescription: {
        text: 'Compiler data-flow tracking found a witness value reaching a public sink (disclose, hash inputs, ledger fields) without a per-event blinder. Verify the disclosure is intentional or add a blinder.',
      },
      defaultConfiguration: { level: 'error' },
    },
    {
      id: 'state-mutation',
      name: 'StateMutation',
      shortDescription: { text: 'Suspicious state mutation pattern' },
      defaultConfiguration: { level: 'warning' },
    },
    {
      id: 'nullifier',
      name: 'NullifierIssue',
      shortDescription: { text: 'Nullifier hygiene issue' },
      defaultConfiguration: { level: 'error' },
    },
    {
      id: 'nonce:constant-return-witness',
      name: 'ConstantReturnWitness',
      shortDescription: { text: 'Witness returns a constant where a nonce is expected' },
      fullDescription: {
        text: 'Witness implementation returns `new Uint8Array(N)` or similar. A constant nonce defeats privacy: two events using the same witness produce identical commitments/nullifiers. Use crypto.randomBytes / crypto.getRandomValues and persist alongside the receipt the holder needs.',
      },
      defaultConfiguration: { level: 'error' },
    },
    {
      id: 'nonce:missing-counter-increment',
      name: 'MissingCounterIncrement',
      shortDescription: { text: 'Ledger counter used in hash without increment' },
      defaultConfiguration: { level: 'error' },
    },
    {
      id: 'nonce:multi-call-binding',
      name: 'MultiCallBinding',
      shortDescription: { text: 'Witness called multiple times without binding' },
      defaultConfiguration: { level: 'warning' },
    },
    {
      id: 'nonce:hash-without-blinder',
      name: 'HashWithoutBlinder',
      shortDescription: { text: 'persistentHash of a stable identifier without a nonce' },
      defaultConfiguration: { level: 'note' },
    },
    {
      id: 'correlator:cross-circuit',
      name: 'CrossCircuitCorrelator',
      shortDescription: { text: 'Witness flows to multiple circuits without a per-event blinder' },
      fullDescription: {
        text: 'Same witness origin reaches disclose sites in multiple circuits with the same exposure shape and no blinder. An observer can link events across circuits. Verify intentional or add @disclose-intent to document.',
      },
      defaultConfiguration: { level: 'warning' },
    },
  ];
}

function locationFor(uri: string, startLine?: number, endLine?: number): SarifLocation {
  return {
    physicalLocation: {
      artifactLocation: { uri, uriBaseId: 'SRC' },
      ...(startLine != null ? { region: { startLine, endLine: endLine ?? startLine } } : {}),
    },
  };
}

function packSuppression(ack: SecurityFinding['ack'] | undefined): SarifResult['suppressions'] | undefined {
  if (!ack) return undefined;
  return [{
    kind: ack.source === 'inline-annotation' ? 'inSource' : 'external',
    justification: `[${ack.by}] ${ack.reason}`,
  }];
}

function mapSecurityFinding(finding: SecurityFinding, contractUri: string): SarifResult {
  const ruleId = deriveRuleKey(finding);
  return {
    ruleId,
    level: levelFromSeverity(finding.severity),
    message: {
      text: `${finding.title}${finding.description ? '\n' + finding.description : ''}`,
    },
    locations: [locationFor(contractUri, finding.location?.line)],
    partialFingerprints: finding.id ? { 'stableId/v1': finding.id } : undefined,
    properties: {
      severity: finding.severity,
      category: finding.type,
      recommendation: finding.recommendation,
    },
    suppressions: packSuppression(finding.ack),
  };
}

function mapNonceFinding(finding: NonceFinding, contractUri: string): SarifResult {
  const ruleId = `nonce:${finding.kind}`;
  const site = finding.sites[0];
  const fileUri = site?.file && !site.file.endsWith('.compact') ? site.file : contractUri;
  return {
    ruleId,
    level: levelFromSeverity(finding.severity),
    message: {
      text: `${finding.kind}: ${finding.witnessFunction ?? finding.ledgerField ?? 'unknown'}\n${finding.recommendation}`,
    },
    locations: [locationFor(fileUri, site?.line)],
    partialFingerprints: { 'stableId/v1': finding.id },
    properties: {
      severity: finding.severity,
      kind: finding.kind,
      autoDismissible: finding.autoDismissible,
      sites: finding.sites.length,
    },
    suppressions: packSuppression(
      (finding as NonceFinding & { ack?: SecurityFinding['ack'] }).ack,
    ),
  };
}

function mapCorrelatorFinding(finding: Correlator, contractUri: string): SarifResult {
  const firstSite = finding.linkedDisclosureSites[0];
  return {
    ruleId: 'correlator:cross-circuit',
    level: levelFromSeverity(finding.severity),
    message: {
      text: `${finding.linkabilitySummary}\n${finding.recommendation}`,
    },
    locations: [locationFor(contractUri, firstSite?.location.line)],
    partialFingerprints: { 'stableId/v1': finding.id },
    properties: {
      severity: finding.severity,
      siteCount: finding.linkedDisclosureSites.length,
      blinderPresent: finding.exposureStructure.blinderPresent,
      annotationPresent: finding.intentCheck.annotationPresent,
    },
    suppressions: packSuppression(
      (finding as Correlator & { ack?: SecurityFinding['ack'] }).ack,
    ),
  };
}

/**
 * Produce a SARIF 2.1.0 log document for the AnalysisResult.
 *
 * `toolVersion` is the analyzer's release tag; pass package version
 * from caller so it's available for the GH UI's tool metadata.
 *
 * `contractUri` is the relative path to the analyzed .compact file,
 * used as the artifactLocation for security findings.
 */
export function buildSarifLog(input: {
  result: AnalysisResult;
  toolVersion: string;
  contractUri: string;
  contractSrcDir?: string;
}): SarifLog {
  const results: SarifResult[] = [];
  const r = input.result;

  for (const f of r.security?.findings ?? []) {
    results.push(mapSecurityFinding(f, input.contractUri));
  }
  for (const n of r.nonceAnalysis?.findings ?? []) {
    results.push(mapNonceFinding(n, input.contractUri));
  }
  for (const c of r.correlatorAnalysis?.findings ?? []) {
    results.push(mapCorrelatorFinding(c, input.contractUri));
  }

  const log: SarifLog = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'security-analyzer',
            version: input.toolVersion,
            informationUri: TOOL_INFO_URI,
            rules: allRules(),
          },
        },
        results,
        ...(input.contractSrcDir
          ? { originalUriBaseIds: { SRC: { uri: input.contractSrcDir } } }
          : {}),
      },
    ],
  };

  return log;
}

/** Convenience: serialise the log to a JSON string. */
export function serialiseSarifLog(log: SarifLog): string {
  return JSON.stringify(log, null, 2) + '\n';
}
