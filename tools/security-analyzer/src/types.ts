/**
 * Types for Compact Circuit Analyzer CLI
 */

export interface CircuitMetrics {
  name: string;
  constraints: number;
  kValue: number;
  proofSize: number; // bytes
  zkirSize: number; // bytes
  provingTimeEstimate: number; // seconds
  memoryEstimate: number; // MB
  dependencies?: string[]; // Names of circuits this circuit calls
}

export interface ComplexityMetrics {
  cyclomaticComplexity: number;
  callDepth: number;
  branchCount: number;
  loopCount: number;
  assertionCount: number;
}

export interface CircuitComplexity {
  circuit: string;
  metrics: ComplexityMetrics;
  rating: 'low' | 'medium' | 'high' | 'very-high';
}

export interface CoverageAnalysis {
  exportedCircuits: string[];
  internalCircuits: string[];
  calledCircuits: string[];
  uncalledCircuits: string[];
  callGraph: Record<string, string[]>; // circuit -> circuits it calls
  callerGraph: Record<string, string[]>; // circuit -> circuits that call it
}

export interface DeadCodeFindings {
  unusedWitnesses: string[];
  unusedCircuits: string[];
  unreachableCode: Array<{
    circuit: string;
    description: string;
    location: string;
  }>;
}

export interface AnalysisResult {
  contractFile: string;
  circuits: CircuitMetrics[];
  totalConstraints: number;
  compilationTime: number; // ms
  timestamp: string;
  compilerVersion?: string;
  security?: import('./security-analyzer.js').SecurityAnalysisResult;
  complexity?: CircuitComplexity[];
  coverage?: CoverageAnalysis;
  deadCode?: DeadCodeFindings;
  profile?: ContractProfile;
  valueInventory?: ValueInventory;
  nonceAnalysis?: NonceAnalysis;
  correlatorAnalysis?: CorrelatorAnalysis;
  policyAssessment?: PolicyAssessment;
}

// ---------------------------------------------------------------------------
// Contract Profile & Value Inventory
// ---------------------------------------------------------------------------
//
// These shapes are the "lens" findings are read through. The profile
// answers "what kind of contract is this?" in machine-readable form.
// The value inventory enumerates the concrete value-handling surface.
// Both are derived from the .compact source, stdlib symbol invocations,
// ledger field shapes, and access-control patterns. Neither requires
// witness implementations or runtime data.
//
// Stable across runs: a non-semantic edit to the source (reordering,
// whitespace, comments) should not change any field. A semantic edit
// (adding a circuit, changing a stdlib call) should.
// ---------------------------------------------------------------------------

export type ValuePosture =
  | 'none'      // no token primitives, no balance-like state
  | 'receives'  // can receive but not send/mint
  | 'holds'     // tracks balances, can transfer, cannot mint
  | 'mints'     // can create new tokens
  | 'bridges';  // mints + sends + references off-chain custody

export type PrivacyPosture =
  | 'open'                     // no witnesses; all state public
  | 'selective'                // witnesses + multiple intentional disclose() per circuit
  | 'strong-with-disclosures'  // witnesses + disclose() only for protocol-required exposure
  | 'strong';                  // witnesses + minimal/no disclose

export type AuthorityModel =
  | 'permissionless'
  | 'single-owner'
  | 'multi-key'
  | 'membership-proof'
  | 'unclear';

export type ContractClass =
  | 'custodial-token'
  | 'shielded-token'
  | 'unshielded-token'
  | 'nft'
  | 'escrow'
  | 'voting'
  | 'auction'
  | 'registry'
  | 'amm'
  | 'bridge'
  | 'compute-only'
  | 'unknown';

export interface SourceLocation {
  file: string;
  line?: number;
  column?: number;
}

export interface TokenPrimitiveInvocation {
  primitive: string; // e.g., "mintShieldedToken"
  circuit: string;
  location: SourceLocation;
}

export interface LedgerSurface {
  fieldsTotal: number;
  fieldsSealed: number;
  balanceLike: string[];      // Counter/Uint fields whose names match balance/supply/total*
  commitmentLike: string[];   // Bytes<32> fields named *Commitment
  nullifierLike: string[];    // Bytes<32> fields named *Nullifier or nullifier*
  counterLike: string[];      // Counter fields not classified as balance
  keyLike: string[];          // Bytes<32> fields named *Key / owner* / authority
}

export interface ContractProfile {
  schemaVersion: '1.0.0';
  valuePosture: ValuePosture;
  privacyPosture: PrivacyPosture;
  authorityModel: AuthorityModel;
  tokenPrimitives: TokenPrimitiveInvocation[];
  ledgerSurface: LedgerSurface;
  externalCustodyHints: string[]; // identifier matches for {vault, reserve, custodian, escrow, treasury}
  circuitCount: number;
  exportedCircuitCount: number;
  witnessFunctionCount: number;
}

export interface MintOperation {
  primitive: string;
  circuit: string;
  location: SourceLocation;
  // Filled in by cross-referencing the access-control analyzer.
  authorizedBy: 'owner-check' | 'membership-proof' | 'missing' | 'unclear';
}

export interface ValueOperation {
  primitive: string;
  circuit: string;
  location: SourceLocation;
}

export interface BalanceField {
  field: string;
  type: string;
  trackedByCircuits: string[];
  overflowAssertionPresent: boolean;
}

export interface CommitmentNullifierPair {
  commitmentField: string;
  nullifierField: string;
}

export interface ValueAtRiskSummary {
  estimatedClass: ContractClass;
  isUnboundedMint: boolean;
  isValueHolding: boolean;
}

export interface ValueInventory {
  schemaVersion: '1.0.0';
  mintOperations: MintOperation[];
  sendOperations: ValueOperation[];
  receiveOperations: ValueOperation[];
  balanceFields: BalanceField[];
  commitmentNullifierPairs: CommitmentNullifierPair[];
  maintenanceAuthorityRefs: SourceLocation[];
  maxSupplyConstraints: SourceLocation[];
  offChainCustodySignals: string[]; // identifier matches
  valueAtRiskSummary: ValueAtRiskSummary;
}

// ---------------------------------------------------------------------------
// Nonce Hygiene
// ---------------------------------------------------------------------------
//
// Nonces / blinders / per-event randomness underpin most privacy claims
// in shielded protocols. A constant or deterministic-from-public-state
// nonce defeats unlinkability without breaking the proof system; the
// compiler accepts it. These findings flag the well-known nonce-failure
// patterns. The compiler can never see the witness implementation; only
// this analyzer does.
// ---------------------------------------------------------------------------

export type NonceFindingKind =
  | 'constant-return-witness'    // The witness JS/TS impl returns a literal
  | 'missing-counter-increment'  // ledger Counter used in a hash, no .increment()
  | 'multi-call-binding'         // witness called >1x without an equality assert (deferred)
  | 'hash-without-blinder';      // hash of stable identifier with no per-event nonce arg (deferred)

export interface NonceSite {
  kind: 'witness-impl' | 'circuit-call' | 'ledger-field' | 'circuit-body';
  file: string;
  line?: number;
  snippet?: string;
  circuit?: string;
}

export interface NonceFinding {
  id: string;                     // sha256-prefix-12 of (kind, witness/field, sorted-sites)
  kind: NonceFindingKind;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  witnessFunction?: string;
  ledgerField?: string;
  sites: NonceSite[];
  evidence?: {
    claimFromSource?: string;
    compilerDiscloseIndex?: number;
  };
  recommendation: string;
  autoDismissible: boolean;
}

export interface NonceAnalysis {
  schemaVersion: '1.0.0';
  witnessFile: string | null;     // resolved path, or null if not found
  witnessFileSkipped: boolean;    // true => constant-return check could not run
  findings: NonceFinding[];
}

// ---------------------------------------------------------------------------
// Correlator analysis (phase 3)
// ---------------------------------------------------------------------------
//
// A correlator is any on-chain artifact that links two otherwise-
// unlinkable events to the same off-chain entity. The analyzer finds
// candidates by joining over the compiler's witness disclosure
// records: when the same witness origin (e.g., the same witness
// function or circuit argument) flows to disclose sites in MULTIPLE
// circuits with structurally similar exposure (same final_exposure,
// no per-call blinder visible in the path), an observer can
// correlate those events.
//
// The detector is a prompt for review, not an automatic bug — many
// contracts deliberately publish a correlator (regulator anchors,
// dedupe keys, identity proofs). A `// @disclose-intent: <tag>`
// annotation above the affected circuit downgrades the finding to
// info severity.
// ---------------------------------------------------------------------------

export type DiscloseIntentTag =
  | 'intentional-correlator'
  | 'nullifier-emission'
  | 'commitment-output'
  | 'public-by-design'
  | 'protocol-required';

export const DISCLOSE_INTENT_TAGS: ReadonlySet<string> = new Set([
  'intentional-correlator',
  'nullifier-emission',
  'commitment-output',
  'public-by-design',
  'protocol-required',
]);

export interface LinkedDisclosureSite {
  circuit: string;
  location: SourceLocation;
  finalExposure: string;
  compilerDiscloseIndex: number;
}

export interface CorrelatorOrigin {
  kind: 'witness-return-value' | 'constructor-argument' | 'circuit-argument';
  function?: string;
  argument?: string;
  location: SourceLocation;
}

export interface ExposureStructure {
  sameFinalExposure: boolean;
  blinderPresent: boolean;       // any path includes a nonce/salt/blinder argument
  stableIdentifierPresent: boolean;
  exposureLabel: string;
}

export interface IntentCheck {
  docstringSaysCorrelatable: boolean | null;
  annotationPresent: boolean;
  annotationTag?: string;
  annotationReason?: string;
}

export interface Correlator {
  id: string;                    // corr-<sha256-prefix-12>
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  witnessOrigin: CorrelatorOrigin;
  linkedDisclosureSites: LinkedDisclosureSite[];
  exposureStructure: ExposureStructure;
  linkabilitySummary: string;
  intentCheck: IntentCheck;
  recommendation: string;
  autoDismissible: boolean;
}

export interface CorrelatorAnalysis {
  schemaVersion: '1.0.0';
  findings: Correlator[];
}

// ---------------------------------------------------------------------------
// Policy assessment (phase 4)
// ---------------------------------------------------------------------------
//
// Synthesises a deploy_recommendation from the lens (ContractProfile,
// ValueInventory) and the findings (security, nonce, correlator). The
// recommendation is computed from explicit rules so a reviewer can
// follow the reasoning, and the rules are designed to be overridable
// in a future config file. Finding severities are NOT silently
// upgraded by the profile — the policy block is separate and visible.
// ---------------------------------------------------------------------------

export type DeployRecommendation = 'block' | 'warn' | 'ok';

export interface PolicyReason {
  rule: string;            // stable rule identifier (e.g., 'mints-with-missing-auth')
  severity: DeployRecommendation;
  message: string;
}

export interface PolicyAssessment {
  schemaVersion: '1.0.0';
  deployRecommendation: DeployRecommendation;
  reasons: PolicyReason[];
}

export interface ReportOptions {
  format: 'console' | 'markdown' | 'json';
  outputFile?: string;
  verbose: boolean;
  warnings: boolean;
}

export interface VisualizationOptions {
  outputDir: string;
  format: 'png' | 'svg' | 'pdf' | 'dot';
  theme: 'default' | 'dark' | 'light' | 'colorful';
  types: Array<'dependency' | 'state-flow' | 'performance' | 'all'>;
  includeDetails: boolean;
  includeLegend: boolean;
  includePerformance: boolean;
}

export interface CompilerOptions {
  skipZk?: boolean;
  verbose?: boolean;
  timeout?: number; // ms
  // Optional explicit path to the witness implementation file (.ts/.js).
  // Used by the nonce analyzer to detect constant-return witnesses.
  // When omitted, the analyzer searches conventional locations.
  witnessFile?: string;
  // Optional path to an existing compactc output directory. When set,
  // the analyzer SKIPS compilation and reads the compiler/, zkir/, and
  // (optionally) keys/ subdirectories from this path. Useful for CI
  // pipelines that already compiled separately, or for re-running the
  // analyzer without paying the compile cost again.
  fromBuildDir?: string;
}

export interface ZkirFileInfo {
  name: string;
  size: number;
  path: string;
}
