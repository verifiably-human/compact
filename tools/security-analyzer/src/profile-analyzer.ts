/**
 * Contract Profile + Value Inventory analyzer.
 *
 * Phase 1 of the value-and-privacy-at-risk detection suite.
 * Reads:
 *   - the raw .compact source
 *   - the circuits already parsed by SecurityAnalyzer
 *   - the ledger/witness state variables already parsed by SecurityAnalyzer
 *   - the SecurityAnalyzer's findings (for authorizedBy on mint operations)
 *
 * Emits:
 *   - ContractProfile: value posture, privacy posture, authority model,
 *     token primitives, ledger surface classification.
 *   - ValueInventory: per-operation enumeration of mint/send/receive,
 *     balance fields, commitment+nullifier pairings, custody signals.
 *
 * No EVM concepts. No reentrancy. No msg.sender. Only Midnight semantics.
 */

import {
  AuthorityModel,
  BalanceField,
  CommitmentNullifierPair,
  ContractClass,
  ContractProfile,
  LedgerSurface,
  MintOperation,
  PrivacyPosture,
  SourceLocation,
  TokenPrimitiveInvocation,
  ValueAtRiskSummary,
  ValueInventory,
  ValueOperation,
  ValuePosture,
} from './types.js';
import { SecurityFinding } from './security-analyzer.js';

// ---------------------------------------------------------------------------
// Stdlib symbols. These are the unambiguous token-handling primitives.
// Detected via word-boundary regex on circuit bodies; future-proofing
// against syntactic variation is intentional (we want to catch the call
// even if the prefix differs).
// ---------------------------------------------------------------------------

const MINT_PRIMITIVES = [
  'mintShieldedToken',
  'mintUnshieldedToken',
] as const;

const SEND_PRIMITIVES = [
  'sendShielded',
  'sendUnshielded',
  'sendImmediate',
] as const;

const RECEIVE_PRIMITIVES = [
  'receiveShielded',
  'receiveUnshielded',
] as const;

const BALANCE_PRIMITIVES = [
  'unshieldedBalance',
  'shieldedBalance',
] as const;

const MAINTENANCE_AUTHORITY_PATTERNS = [
  /ContractMaintenanceAuthority/,
  /maintenanceAuthority/,
];

// Field-name classifiers. Compact identifiers are typically camelCase
// (e.g. vaultBalance, totalDistributed). The patterns below use plain
// case-insensitive substring or anchored match — the previous
// `\bbalance\b` form did NOT match camelCase like `vaultBalance`.
const BALANCE_FIELD_PATTERNS = [
  /balance/i,
  /supply/i,
  /^total[A-Z]/,                 // totalSupply, totalDistributed
  /^reserves?$/i,
  /vault[A-Z]?[a-z]*$/i,         // vault, vaultBalance
];

const COMMITMENT_FIELD_PATTERNS = [
  /Commitment$/,
  /^commitment[A-Z]?/,
  /^commit[A-Z]/,
];

const NULLIFIER_FIELD_PATTERNS = [
  /Nullifier$/,
  /^nullifier[A-Z]?/,
];

const KEY_FIELD_PATTERNS = [
  /Key$/,
  /^owner/i,
  /^authority/i,
  /^admin/i,
];

const CUSTODY_HINT_PATTERNS = [
  /vault/i,
  /reserve/i,
  /custodian/i,
  /escrow/i,
  /treasury/i,
  /solven/i,
];

const MAX_SUPPLY_ASSERT_PATTERN = /assert\s*\([^;]*(?:max[_A-Z][A-Za-z0-9_]*supply|MAX_SUPPLY|maxSupply)\b/i;

// ---------------------------------------------------------------------------
// Inputs the analyzer needs from SecurityAnalyzer.
// ---------------------------------------------------------------------------

export interface CircuitForProfile {
  name: string;
  body: string;
  isExported: boolean;
  returnType: string;
}

export interface StateVarForProfile {
  name: string;
  type: string;
  kind: 'ledger' | 'witness';
  sealed?: boolean;
}

export interface ProfileAnalyzerInput {
  contractSource: string;
  contractPath: string;
  circuits: CircuitForProfile[];
  stateVars: StateVarForProfile[];
  findings: SecurityFinding[];
}

// ---------------------------------------------------------------------------
// Analyzer.
// ---------------------------------------------------------------------------

export class ProfileAnalyzer {
  private input: ProfileAnalyzerInput;

  constructor(input: ProfileAnalyzerInput) {
    this.input = input;
  }

  analyze(): { profile: ContractProfile; valueInventory: ValueInventory } {
    const tokenPrimitives = this.detectTokenPrimitives();
    const ledgerSurface = this.classifyLedgerSurface();
    const externalCustodyHints = this.detectCustodyHints();

    const valueInventory = this.buildValueInventory(tokenPrimitives, ledgerSurface);

    const profile: ContractProfile = {
      schemaVersion: '1.0.0',
      valuePosture: this.deriveValuePosture(tokenPrimitives, ledgerSurface, externalCustodyHints),
      privacyPosture: this.derivePrivacyPosture(),
      authorityModel: this.deriveAuthorityModel(),
      tokenPrimitives,
      ledgerSurface,
      externalCustodyHints,
      circuitCount: this.input.circuits.length,
      exportedCircuitCount: this.input.circuits.filter(c => c.isExported).length,
      witnessFunctionCount: this.input.stateVars.filter(v => v.kind === 'witness').length,
    };

    return { profile, valueInventory };
  }

  // -------------------------------------------------------------------------
  // Token primitive detection.
  // -------------------------------------------------------------------------

  private detectTokenPrimitives(): TokenPrimitiveInvocation[] {
    const invocations: TokenPrimitiveInvocation[] = [];
    const allPrimitives = [
      ...MINT_PRIMITIVES,
      ...SEND_PRIMITIVES,
      ...RECEIVE_PRIMITIVES,
      ...BALANCE_PRIMITIVES,
    ];

    for (const circuit of this.input.circuits) {
      for (const primitive of allPrimitives) {
        const pattern = new RegExp(`\\b${primitive}\\s*[<(]`, 'g');
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(circuit.body)) !== null) {
          invocations.push({
            primitive,
            circuit: circuit.name,
            location: this.locateInSource(match.index, circuit),
          });
        }
      }
    }

    return invocations;
  }

  // -------------------------------------------------------------------------
  // Ledger surface classification.
  // -------------------------------------------------------------------------

  private classifyLedgerSurface(): LedgerSurface {
    const ledgerFields = this.input.stateVars.filter(v => v.kind === 'ledger');
    const balanceLike: string[] = [];
    const commitmentLike: string[] = [];
    const nullifierLike: string[] = [];
    const counterLike: string[] = [];
    const keyLike: string[] = [];

    for (const field of ledgerFields) {
      // Order matters: most specific patterns first.
      if (NULLIFIER_FIELD_PATTERNS.some(p => p.test(field.name))) {
        nullifierLike.push(field.name);
        continue;
      }
      if (COMMITMENT_FIELD_PATTERNS.some(p => p.test(field.name))) {
        commitmentLike.push(field.name);
        continue;
      }
      if (BALANCE_FIELD_PATTERNS.some(p => p.test(field.name))) {
        balanceLike.push(field.name);
        continue;
      }
      if (KEY_FIELD_PATTERNS.some(p => p.test(field.name))) {
        keyLike.push(field.name);
        continue;
      }
      if (/^Counter$/i.test(field.type) || /\bCounter\b/.test(field.type)) {
        counterLike.push(field.name);
        continue;
      }
    }

    return {
      fieldsTotal: ledgerFields.length,
      fieldsSealed: ledgerFields.filter(f => f.sealed).length,
      balanceLike,
      commitmentLike,
      nullifierLike,
      counterLike,
      keyLike,
    };
  }

  // -------------------------------------------------------------------------
  // Custody hint detection. Scans identifiers (field names + circuit names)
  // for off-chain-custody-suggestive words.
  // -------------------------------------------------------------------------

  private detectCustodyHints(): string[] {
    const hints = new Set<string>();

    for (const field of this.input.stateVars) {
      if (CUSTODY_HINT_PATTERNS.some(p => p.test(field.name))) {
        hints.add(field.name);
      }
    }
    for (const circuit of this.input.circuits) {
      if (CUSTODY_HINT_PATTERNS.some(p => p.test(circuit.name))) {
        hints.add(circuit.name);
      }
    }

    return [...hints].sort();
  }

  // -------------------------------------------------------------------------
  // Posture derivation.
  // -------------------------------------------------------------------------

  private deriveValuePosture(
    tokenPrimitives: TokenPrimitiveInvocation[],
    ledgerSurface: LedgerSurface,
    custodyHints: string[],
  ): ValuePosture {
    const hasMint = tokenPrimitives.some(t =>
      MINT_PRIMITIVES.some(m => m === t.primitive));
    const hasSend = tokenPrimitives.some(t =>
      SEND_PRIMITIVES.some(s => s === t.primitive));
    const hasReceive = tokenPrimitives.some(t =>
      RECEIVE_PRIMITIVES.some(r => r === t.primitive));
    const hasBalanceTracking = ledgerSurface.balanceLike.length > 0;

    // Bridges: mint + send + off-chain custody signals.
    if (hasMint && hasSend && custodyHints.length > 0) {
      return 'bridges';
    }
    if (hasMint) {
      return 'mints';
    }
    if (hasSend || hasBalanceTracking) {
      return 'holds';
    }
    if (hasReceive) {
      return 'receives';
    }
    return 'none';
  }

  private derivePrivacyPosture(): PrivacyPosture {
    const witnessCount = this.input.stateVars.filter(v => v.kind === 'witness').length;
    if (witnessCount === 0) {
      return 'open';
    }

    // Count disclose() calls across all circuit bodies.
    let totalDisclosures = 0;
    let protocolRequiredOnly = true;
    const protocolRequiredPrimitives = [
      ...MINT_PRIMITIVES,
      ...SEND_PRIMITIVES,
      ...RECEIVE_PRIMITIVES,
    ];

    for (const circuit of this.input.circuits) {
      const matches = circuit.body.match(/\bdisclose\s*\(/g);
      if (!matches) continue;
      totalDisclosures += matches.length;

      // A disclose is "protocol-required" if it appears within an
      // argument to a token primitive call. We approximate by checking
      // whether the same line contains both `disclose(` and a token
      // primitive name. Coarse but conservative for the posture call.
      const lines = circuit.body.split('\n');
      for (const line of lines) {
        if (!line.includes('disclose(')) continue;
        const protocolRequired = protocolRequiredPrimitives.some(p =>
          new RegExp(`\\b${p}\\b`).test(line));
        if (!protocolRequired) {
          protocolRequiredOnly = false;
        }
      }
    }

    if (totalDisclosures === 0) return 'strong';
    if (protocolRequiredOnly) return 'strong-with-disclosures';
    // 'selective' = many disclosures, some outside protocol-required paths.
    // We don't try to refine further at this phase.
    return 'selective';
  }

  private deriveAuthorityModel(): AuthorityModel {
    // Pull signal from the access-control findings the SecurityAnalyzer
    // already emitted. If every exported state-mutating circuit has a
    // matching "Disabled authorization" or "Missing authorization", the
    // contract is effectively permissionless. Otherwise we infer from
    // the keyLike ledger surface.
    // Findings have a `[Heuristic]` prefix added by the merge layer in
    // compiler-security-reader.ts. Match by substring rather than
    // prefix.
    const accessControlFindings = this.input.findings.filter(f => f.type === 'access-control');
    const missingOrDisabled = accessControlFindings.filter(f =>
      f.title.includes('Missing authorization') ||
      f.title.includes('Disabled authorization'));
    const exportedCount = this.input.circuits.filter(c => c.isExported).length;

    if (exportedCount > 0 && missingOrDisabled.length === exportedCount) {
      return 'permissionless';
    }

    const ledgerFields = this.input.stateVars.filter(v => v.kind === 'ledger');
    const ownerLike = ledgerFields.filter(f =>
      /^owner\b/i.test(f.name) ||
      /^authority\b/i.test(f.name) ||
      /^admin\b/i.test(f.name));
    const merkleRootLike = ledgerFields.filter(f =>
      /MerkleRoot/i.test(f.name) || /membership/i.test(f.name));

    if (merkleRootLike.length > 0) return 'membership-proof';
    if (ownerLike.length === 1) return 'single-owner';
    if (ownerLike.length > 1) return 'multi-key';

    return 'unclear';
  }

  // -------------------------------------------------------------------------
  // Value inventory.
  // -------------------------------------------------------------------------

  private buildValueInventory(
    tokenPrimitives: TokenPrimitiveInvocation[],
    ledgerSurface: LedgerSurface,
  ): ValueInventory {
    const mintOperations: MintOperation[] = tokenPrimitives
      .filter(t => MINT_PRIMITIVES.some(m => m === t.primitive))
      .map(t => ({
        ...t,
        authorizedBy: this.authorizedByFor(t.circuit),
      }));

    const sendOperations: ValueOperation[] = tokenPrimitives
      .filter(t => SEND_PRIMITIVES.some(s => s === t.primitive));

    const receiveOperations: ValueOperation[] = tokenPrimitives
      .filter(t => RECEIVE_PRIMITIVES.some(r => r === t.primitive));

    const balanceFields = this.detectBalanceFields(ledgerSurface);
    const commitmentNullifierPairs = this.pairCommitmentsAndNullifiers(ledgerSurface);
    const maintenanceAuthorityRefs = this.detectMaintenanceAuthorityRefs();
    const maxSupplyConstraints = this.detectMaxSupplyConstraints();
    const offChainCustodySignals = this.detectCustodyHints();

    const valueAtRiskSummary = this.summarizeValueAtRisk(
      mintOperations,
      sendOperations,
      receiveOperations,
      balanceFields,
      commitmentNullifierPairs,
      maxSupplyConstraints,
      offChainCustodySignals,
    );

    return {
      schemaVersion: '1.0.0',
      mintOperations,
      sendOperations,
      receiveOperations,
      balanceFields,
      commitmentNullifierPairs,
      maintenanceAuthorityRefs,
      maxSupplyConstraints,
      offChainCustodySignals,
      valueAtRiskSummary,
    };
  }

  private authorizedByFor(circuitName: string):
    'owner-check' | 'membership-proof' | 'missing' | 'unclear' {
    const findingsForCircuit = this.input.findings.filter(f =>
      f.location?.circuit === circuitName && f.type === 'access-control');
    const hasMissingOrDisabled = findingsForCircuit.some(f =>
      f.title.includes('Missing authorization') ||
      f.title.includes('Disabled authorization'));
    if (hasMissingOrDisabled) return 'missing';

    const circuit = this.input.circuits.find(c => c.name === circuitName);
    if (!circuit) return 'unclear';
    if (/\bmembership\b/i.test(circuit.body) || /MerkleRoot/.test(circuit.body)) {
      return 'membership-proof';
    }
    if (/\bowner\b/i.test(circuit.body) || /requireOwner|onlyOwner/.test(circuit.body)) {
      return 'owner-check';
    }
    return 'unclear';
  }

  private detectBalanceFields(ledgerSurface: LedgerSurface): BalanceField[] {
    return ledgerSurface.balanceLike.map(fieldName => {
      const stateVar = this.input.stateVars.find(v => v.name === fieldName);
      const trackedByCircuits = this.input.circuits
        .filter(c => new RegExp(`\\b${fieldName}\\b`).test(c.body))
        .map(c => c.name);
      // Heuristic: do any circuits that write this field also assert an
      // upper bound on it? We approximate by looking for an `assert` on
      // the same field within the writing circuit. Doesn't prove the
      // bound is correct, just that one exists.
      const overflowAssertionPresent = this.input.circuits.some(c => {
        if (!new RegExp(`\\b${fieldName}\\s*=`).test(c.body)) return false;
        const assertPattern = new RegExp(
          `assert\\s*\\([^;]*\\b${fieldName}\\b[^;]*[<>]=?[^;]*\\)`);
        return assertPattern.test(c.body);
      });
      return {
        field: fieldName,
        type: stateVar?.type ?? 'unknown',
        trackedByCircuits,
        overflowAssertionPresent,
      };
    });
  }

  private pairCommitmentsAndNullifiers(ledgerSurface: LedgerSurface): CommitmentNullifierPair[] {
    const pairs: CommitmentNullifierPair[] = [];
    // Pair by stem: foo_Commitment with foo_Nullifier.
    for (const commitment of ledgerSurface.commitmentLike) {
      const stem = commitment.replace(/Commitment$/i, '').toLowerCase();
      const match = ledgerSurface.nullifierLike.find(n =>
        n.replace(/Nullifier$/i, '').toLowerCase() === stem);
      if (match) {
        pairs.push({ commitmentField: commitment, nullifierField: match });
      }
    }
    return pairs;
  }

  private detectMaintenanceAuthorityRefs(): SourceLocation[] {
    const refs: SourceLocation[] = [];
    const lines = this.input.contractSource.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (MAINTENANCE_AUTHORITY_PATTERNS.some(p => p.test(lines[i]))) {
        refs.push({
          file: this.input.contractPath,
          line: i + 1,
        });
      }
    }
    return refs;
  }

  private detectMaxSupplyConstraints(): SourceLocation[] {
    const refs: SourceLocation[] = [];
    const lines = this.input.contractSource.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (MAX_SUPPLY_ASSERT_PATTERN.test(lines[i])) {
        refs.push({
          file: this.input.contractPath,
          line: i + 1,
        });
      }
    }
    return refs;
  }

  private summarizeValueAtRisk(
    mintOperations: MintOperation[],
    sendOperations: ValueOperation[],
    receiveOperations: ValueOperation[],
    balanceFields: BalanceField[],
    commitmentNullifierPairs: CommitmentNullifierPair[],
    maxSupplyConstraints: SourceLocation[],
    offChainCustodySignals: string[],
  ): ValueAtRiskSummary {
    const isUnboundedMint = mintOperations.length > 0 &&
      mintOperations.some(m => m.authorizedBy === 'missing') &&
      maxSupplyConstraints.length === 0;
    const isValueHolding = balanceFields.length > 0 ||
      receiveOperations.length > 0 ||
      commitmentNullifierPairs.length > 0;

    return {
      estimatedClass: this.classifyContract(
        mintOperations,
        sendOperations,
        receiveOperations,
        balanceFields,
        commitmentNullifierPairs,
        offChainCustodySignals,
      ),
      isUnboundedMint,
      isValueHolding,
    };
  }

  private classifyContract(
    mintOperations: MintOperation[],
    sendOperations: ValueOperation[],
    receiveOperations: ValueOperation[],
    balanceFields: BalanceField[],
    commitmentNullifierPairs: CommitmentNullifierPair[],
    offChainCustodySignals: string[],
  ): ContractClass {
    const hasShielded = [...mintOperations, ...sendOperations, ...receiveOperations]
      .some(o => /Shielded\b/.test(o.primitive));
    const hasUnshielded = [...mintOperations, ...sendOperations, ...receiveOperations]
      .some(o => /Unshielded\b/.test(o.primitive));

    if (offChainCustodySignals.length > 0 && (hasShielded || hasUnshielded)) {
      return 'custodial-token';
    }
    if (commitmentNullifierPairs.length > 0 && hasShielded) {
      return 'shielded-token';
    }
    if (hasUnshielded && !hasShielded) {
      return 'unshielded-token';
    }
    if (hasShielded) {
      return 'shielded-token';
    }
    // No token primitives at all from here on.
    const ledgerFields = this.input.stateVars.filter(v => v.kind === 'ledger');
    const hasVotingFields = ledgerFields.some(f =>
      /\bvote/i.test(f.name) || /\bballot/i.test(f.name) || /\btally/i.test(f.name));
    if (hasVotingFields) return 'voting';
    const hasAuctionFields = ledgerFields.some(f =>
      /\bbid/i.test(f.name) || /\bauction/i.test(f.name));
    if (hasAuctionFields) return 'auction';
    const hasRegistryFields = ledgerFields.some(f =>
      /\bregistry\b/i.test(f.name) || /\bregistered/i.test(f.name));
    if (hasRegistryFields) return 'registry';
    if (this.input.stateVars.filter(v => v.kind === 'witness').length === 0
        && ledgerFields.length > 0) {
      return 'compute-only';
    }
    return 'unknown';
  }

  // -------------------------------------------------------------------------
  // Helpers.
  // -------------------------------------------------------------------------

  /**
   * Convert a character offset inside a circuit body to a line/column in
   * the original source file. Approximate: we use the position of the
   * circuit declaration in the source and add the body offset.
   */
  private locateInSource(bodyOffset: number, circuit: CircuitForProfile): SourceLocation {
    const circuitDeclPattern = new RegExp(`circuit\\s+${circuit.name}\\b`);
    const sourceMatch = circuitDeclPattern.exec(this.input.contractSource);
    if (!sourceMatch) {
      return { file: this.input.contractPath };
    }
    const upToOffset = this.input.contractSource.slice(0, sourceMatch.index + bodyOffset);
    const lines = upToOffset.split('\n');
    return {
      file: this.input.contractPath,
      line: lines.length,
      column: lines[lines.length - 1].length + 1,
    };
  }
}
