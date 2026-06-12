/**
 * Security Analyzer for Compact Contracts
 *
 * Performs static analysis to detect:
 * - Privacy leaks (improper disclosure of private data)
 * - Access control issues
 * - State mutation risks
 * - Nullifier misuse
 * - Taint propagation
 * - Side-channel vulnerabilities
 * - Information flow issues
 */

import { readFileSync, existsSync } from 'fs';
import {
  CircuitAnnotationMap,
  findAnnotation,
  parseAnnotations,
} from './annotation-parser.js';

export type SecuritySeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface SecurityFinding {
  type: 'privacy-leak' | 'access-control' | 'state-mutation' | 'nullifier' | 'taint' | 'side-channel' | 'info-flow';
  severity: SecuritySeverity;
  title: string;
  description: string;
  location?: {
    circuit: string;
    line?: number;
    code?: string;
  };
  recommendation: string;
  impact: string;
}

export interface SecurityAnalysisResult {
  findings: SecurityFinding[];
  riskScore: number; // 0-100
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

interface CircuitInfo {
  name: string;
  body: string;
  params: Array<{ name: string; type: string }>;
  returnType: string;
  isExported: boolean;
}

interface StateVariable {
  name: string;
  type: string;
  kind: 'ledger' | 'witness';
  sealed?: boolean;
}

export class SecurityAnalyzer {
  private contractSource: string;
  private contractPath: string;
  private circuits: CircuitInfo[] = [];
  private stateVars: StateVariable[] = [];
  private findings: SecurityFinding[] = [];
  private annotations: CircuitAnnotationMap = new Map();

  constructor(contractPath: string) {
    this.contractPath = contractPath;

    if (!existsSync(contractPath)) {
      throw new Error(`Contract file not found: ${contractPath}`);
    }

    this.contractSource = readFileSync(contractPath, 'utf8');
  }

  /**
   * Run all security analyses
   */
  public analyze(): SecurityAnalysisResult {
    this.findings = [];

    // Parse contract structure
    this.parseStateVariables();
    this.parseCircuits();
    // Parse in-source audit annotations (// @access-control: ..., etc.)
    // and bind them to circuit declarations. Per-check methods consult
    // this map to downgrade findings the contract author has marked as
    // intentional design choices.
    this.annotations = parseAnnotations(
      this.contractSource,
      this.circuits.map(c => ({
        name: c.name,
        body: c.body,
        isExported: c.isExported,
        returnType: c.returnType,
      })),
    );

    // Run security analyses
    this.analyzePrivacyLeaks();
    this.analyzeAccessControl();
    this.analyzeStateMutations();
    this.analyzeNullifiers();
    this.analyzeTaint();
    this.analyzeSideChannels();
    this.analyzeInformationFlow();

    // Calculate risk score and summary
    const summary = {
      critical: this.findings.filter(f => f.severity === 'critical').length,
      high: this.findings.filter(f => f.severity === 'high').length,
      medium: this.findings.filter(f => f.severity === 'medium').length,
      low: this.findings.filter(f => f.severity === 'low').length,
      info: this.findings.filter(f => f.severity === 'info').length
    };

    const riskScore = this.calculateRiskScore(summary);

    return {
      findings: this.findings,
      riskScore,
      summary
    };
  }

  /**
   * Parse state variables (ledger and witness)
   */
  private parseStateVariables(): void {
    // Parse ledger variables (public state). Compact admits these forms:
    //   `ledger X: T;`
    //   `sealed ledger X: T;`            — no maintenance authority can change it
    //   `export ledger X: T;`            — visible in generated TypeScript
    //   `export sealed ledger X: T;`
    // Allow `export` and `sealed` in either order; both are optional.
    const ledgerRegex = /^(?:(export)\s+)?(?:(sealed)\s+)?(?:(export)\s+)?ledger\s+(\w+)\s*:\s*([^;]+);/gm;
    let match;

    while ((match = ledgerRegex.exec(this.contractSource)) !== null) {
      this.stateVars.push({
        name: match[4],
        type: match[5].trim(),
        kind: 'ledger',
        sealed: !!match[2],
      });
    }

    // Parse witness variables (private inputs). Witnesses can also be
    // declared with the `export` prefix in some contract styles.
    const witnessRegex = /^(?:export\s+)?witness\s+([\w$]+)\s*\(([^)]*)\)\s*:\s*([^;]+);/gm;

    while ((match = witnessRegex.exec(this.contractSource)) !== null) {
      this.stateVars.push({
        name: match[1],
        type: match[3].trim(),
        kind: 'witness'
      });
    }
  }

  /**
   * Expose parsed circuits/state vars to downstream analyzers (Profile,
   * Correlator, Nonce). The profile analyzer doesn't need to re-parse.
   */
  public getCircuits(): CircuitInfo[] {
    return this.circuits;
  }

  public getStateVars(): StateVariable[] {
    return this.stateVars;
  }

  public getContractSource(): string {
    return this.contractSource;
  }

  public getContractPath(): string {
    return this.contractPath;
  }

  public getAnnotations(): CircuitAnnotationMap {
    return this.annotations;
  }

  /**
   * Parse circuit definitions
   */
  private parseCircuits(): void {
    // Match: [export] circuit name(params): ReturnType { body }
    // The optional `export` prefix is captured so we can mark the
    // circuit as exported via the inline-export form. The export-block
    // form (`export { foo, bar }`) is checked separately below.
    const circuitRegex = /(export\s+)?circuit\s+(\w+)\s*\(([^)]*)\)\s*:\s*([^{]+)\s*\{([^]*?)\n\}/gm;

    let match;
    while ((match = circuitRegex.exec(this.contractSource)) !== null) {
      const inlineExport = !!match[1];
      const name = match[2];
      const paramsStr = match[3];
      const returnType = match[4].trim();
      const body = match[5];

      // Parse parameters
      const params: Array<{ name: string; type: string }> = [];
      if (paramsStr.trim()) {
        const paramParts = paramsStr.split(',');
        for (const part of paramParts) {
          const paramMatch = part.trim().match(/(\w+)\s*:\s*(.+)/);
          if (paramMatch) {
            params.push({
              name: paramMatch[1],
              type: paramMatch[2].trim()
            });
          }
        }
      }

      // Two export forms in Compact:
      //   1. Inline:  `export circuit foo(...) ...`
      //   2. Block:   `export { foo, bar }` declared elsewhere
      const exportBlockRegex = new RegExp(`export\\s*\\{[^}]*\\b${name}\\b[^}]*\\}`);
      const isExported = inlineExport || exportBlockRegex.test(this.contractSource);

      this.circuits.push({
        name,
        body,
        params,
        returnType,
        isExported
      });
    }
  }

  /**
   * 1. Privacy Leak Detection
   * Detects inappropriate disclosure of private (witness) data
   */
  private analyzePrivacyLeaks(): void {
    const witnessVars = this.stateVars.filter(v => v.kind === 'witness');

    for (const circuit of this.circuits) {
      // Collect disclose() sites once per circuit and dedupe findings
      // by (witness name, kind). Without this, a circuit with N disclose
      // calls produced N identical findings — the same fan-out failure
      // mode that produced the old 6× reentrancy noise.
      const discloseRegex = /disclose\s*\(\s*([^)]+)\s*\)/g;
      const discloseMatches: Array<{ expr: string; code: string }> = [];
      let match;
      while ((match = discloseRegex.exec(circuit.body)) !== null) {
        discloseMatches.push({ expr: match[1].trim(), code: match[0] });
      }

      if (discloseMatches.length === 0) {
        continue;
      }

      // Per-witness direct disclosure: dedupe so each witness is
      // reported once per circuit, with all matching disclose sites
      // listed in the finding code field.
      for (const witness of witnessVars) {
        const witnessCallPattern = new RegExp(`\\b${witness.name}\\s*\\(`);
        const matching = discloseMatches.filter(m => witnessCallPattern.test(m.expr));
        if (matching.length === 0) continue;

        const sites = matching.map(m => m.code).join('; ');
        this.findings.push({
          type: 'privacy-leak',
          severity: 'critical',
          title: `Direct disclosure of private witness: ${witness.name}`,
          description: `Circuit "${circuit.name}" directly discloses the private witness "${witness.name}" at ${matching.length} site(s). This raw-witness exposure is what the compiler's witness-protection analysis is designed to catch; on a clean compile, every such disclosure carries explicit programmer intent. Verify intent for each site.`,
          location: {
            circuit: circuit.name,
            code: sites
          },
          recommendation: `For each disclose() of "${witness.name}", confirm the disclosed value is what the contract's privacy claim says it should expose. If the value was meant to be hidden, replace the raw disclose with a commitment or a hash that binds the witness without revealing it.`,
          impact: 'Raw witness data becomes publicly visible on the blockchain. If the contract claims this value is private, the claim is violated.'
        });
      }

      // Exported circuit with non-void return that contains any
      // disclose(): one finding per circuit, listing all sites.
      if (circuit.isExported && circuit.returnType !== '[]') {
        this.findings.push({
          type: 'privacy-leak',
          severity: 'medium',
          title: `Exported circuit returns disclosed data: ${circuit.name}`,
          description: `Circuit "${circuit.name}" is exported, returns ${circuit.returnType}, and contains ${discloseMatches.length} disclose() call(s). The compiler's witness-protection analysis (compiler/security-analysis.json) is authoritative for what reaches the return value; this heuristic only flags the cooccurrence and is a prompt for manual review of the disclose intent on each site.`,
          location: {
            circuit: circuit.name,
            code: discloseMatches.map(m => m.code).join('; ')
          },
          recommendation: `Cross-check the compiler's security-analysis.json disclosures for this circuit. Each disclosure entry there carries the full data-flow path from witness origin to disclose site; confirm each is intentional.`,
          impact: 'Potential information leak if disclosed data can be correlated with private inputs.'
        });
      }

      // Witness data in assert conditions: dedupe per witness per
      // circuit. Multiple asserts on the same witness produce one
      // finding, not N.
      for (const witness of witnessVars) {
        const assertWithWitnessRegex = new RegExp(`assert\\s*\\([^;]*\\b${witness.name}\\s*\\(`, 'g');
        const assertMatches = circuit.body.match(assertWithWitnessRegex);
        if (assertMatches && assertMatches.length > 0) {
          this.findings.push({
            type: 'privacy-leak',
            severity: 'low',
            title: `Witness data used in assertion: ${witness.name}`,
            description: `Circuit "${circuit.name}" uses witness "${witness.name}" in ${assertMatches.length} assertion(s). Variable-time constraint paths over witness values can leak information through proving-time side channels observable to the prover host.`,
            location: {
              circuit: circuit.name
            },
            recommendation: `Where the path through the assertion depends on the witness value, consider restructuring so that the assertion outcome does not vary in constraint shape based on the witness.`,
            impact: 'Potential side-channel leakage through constraint count variations observable to the prover host (not the verifier).'
          });
        }
      }
    }
  }

  /**
   * 2. Access Control Analysis
   * Identifies circuits without proper authorization checks
   */
  private analyzeAccessControl(): void {
    for (const circuit of this.circuits) {
      if (!circuit.isExported) continue; // Internal circuits don't need auth checks

      // If the contract author added `// @access-control: <tag>` above
      // this circuit, they're acknowledging the access-control posture
      // is intentional. Emit a single "acknowledged" finding at info
      // severity and skip the rest of the checks for this circuit.
      const acAnnotation = findAnnotation(this.annotations, circuit.name, 'access-control');
      if (acAnnotation) {
        const tagSuffix = acAnnotation.tagKnown
          ? acAnnotation.tag
          : `${acAnnotation.tag} (unknown tag — review)`;
        this.findings.push({
          type: 'access-control',
          severity: acAnnotation.tagKnown ? 'info' : 'low',
          title: `Access-control acknowledged: ${circuit.name} (${tagSuffix})`,
          description: `Exported circuit "${circuit.name}" carries a \`// @access-control: ${acAnnotation.tag}\` annotation at ${this.contractPath}:${acAnnotation.line}. The contract author has marked this circuit's access-control posture as intentional. ${acAnnotation.reason ? `Reason: ${acAnnotation.reason}` : 'No reason provided.'}`,
          location: { circuit: circuit.name },
          recommendation: acAnnotation.tagKnown
            ? `Reviewer: confirm the annotation tag (${acAnnotation.tag}) matches the contract's stated threat model. If it does, no action needed.`
            : `The annotation tag "${acAnnotation.tag}" is not in the known enum (intentional-permissionless, witness-gated, compliance-gated, read-only, documented). Either correct the tag or extend the enum.`,
          impact: acAnnotation.tagKnown
            ? 'Intentional design. No security impact assuming the annotation is accurate.'
            : 'Unknown impact — annotation cannot be verified by the analyzer.',
        });
        continue;
      }

      // Check for COMMENTED-OUT authorization calls first. This catches
      // the common pattern of `// requireOwner()` or
      // `// requireOwner(); // Removed for demo` — a disabled guard is
      // worse than a missing one because it documents the intent that
      // an access check was supposed to be there.
      const disabledAuth = this.findCommentedOutAuthCall(circuit);
      if (disabledAuth) {
        this.findings.push({
          type: 'access-control',
          severity: 'critical',
          title: `Disabled authorization check: ${circuit.name}`,
          description: `Exported circuit "${circuit.name}" contains a commented-out authorization call (${disabledAuth}). The contract appears to be intentionally permissionless in its current state. If this is a production build this is a critical bug; if this is a demo, the demo cannot be used for any deployment that handles value.`,
          location: {
            circuit: circuit.name,
            code: disabledAuth
          },
          recommendation: `Restore the authorization call as the first statement of the circuit. If the demo intentionally has no access control, add a \`// @access-control: intentional-permissionless\` annotation above the circuit declaration to acknowledge the design.`,
          impact: 'Any caller can invoke this circuit, including paths the original design restricted to an owner or authority.'
        });
      }

      const hasAuthCheck = this.checkAuthorizationPattern(circuit);

      if (!hasAuthCheck.hasCheck) {
        // State-mutating circuits should have auth checks
        if (this.isStateMutating(circuit)) {
          this.findings.push({
            type: 'access-control',
            severity: 'high',
            title: `Missing authorization check: ${circuit.name}`,
            description: `Exported circuit "${circuit.name}" mutates ledger state but has no authorization assertion. Any caller can submit a transaction invoking this circuit.`,
            location: {
              circuit: circuit.name
            },
            recommendation: `Add an authorization assertion at the top of the circuit body. Typical Midnight pattern:\n  const sk = ownerSecret();\n  const provided = persistentHash<Vector<2, Bytes<32>>>([pad(32, "domain:owner:"), sk]);\n  assert(provided == ownerKey, "not owner");\nDo NOT wrap the equality in disclose() — that exposes the boolean to the ledger but does not gate the circuit any differently.\n\nIf the circuit is intentionally permissionless (demo, public utility, compliance-gated), add a \`// @access-control: <tag>\` annotation above the circuit declaration to acknowledge the design.`,
            impact: 'Any caller can mutate the affected ledger fields.'
          });
        } else {
          // Read-only circuits might be intentionally public
          this.findings.push({
            type: 'access-control',
            severity: 'info',
            title: `No authorization check: ${circuit.name}`,
            description: `Exported circuit "${circuit.name}" has no authorization check. Verify this is intentionally public.`,
            location: {
              circuit: circuit.name
            },
            recommendation: `If this circuit should be restricted, add an authorization check. Otherwise, add a \`// @access-control: read-only\` (or \`intentional-permissionless\`) annotation to acknowledge.`,
            impact: 'Circuit is publicly callable by any user.'
          });
        }
      } else if (hasAuthCheck.hasWeakCheck) {
        this.findings.push({
          type: 'access-control',
          severity: 'medium',
          title: `Weak authorization pattern: ${circuit.name}`,
          description: `Circuit "${circuit.name}" has an authorization check that might be bypassable.`,
          location: {
            circuit: circuit.name,
            code: hasAuthCheck.checkCode
          },
          recommendation: `Review authorization logic. Ensure it properly validates caller identity and cannot be bypassed.`,
          impact: 'Authorization might be insufficient to prevent unauthorized access.'
        });
      }
    }
  }

  /**
   * Check if circuit has an authorization pattern. Compact ledger
   * fields are read by naming them directly (no `.read()`); the
   * canonical guard is:
   *
   *   const sk = ownerSecret();
   *   assert(persistentHash<...>([prefix, sk]) == ownerKey, "...");
   *
   * or via an internal circuit that does the same.
   */
  private checkAuthorizationPattern(circuit: CircuitInfo): { hasCheck: boolean; hasWeakCheck: boolean; checkCode?: string } {
    const body = circuit.body;

    // Strong pattern: assert that hashes a witness-derived value and
    // compares to a ledger key/owner field.
    const strongAuthPattern = /assert\s*\([^;]*(persistentHash|transientHash|public_key)\s*[<(][^;]*==[^;]*\b(owner|authority|admin|signer|publicKey)[A-Za-z_]*[^;]*,/i;
    if (strongAuthPattern.test(body)) {
      return { hasCheck: true, hasWeakCheck: false };
    }

    // Medium pattern: assert that compares an identity-like name to
    // something, but we can't tell whether the comparison is bound to
    // a witness-derived value or just to a circuit argument the caller
    // supplied. Flag for review.
    const mediumAuthPattern = /assert\s*\([^;]*\b(caller|sender|owner|authority|admin)\b[^;]*==/i;
    const match = body.match(mediumAuthPattern);
    if (match) {
      return { hasCheck: true, hasWeakCheck: true, checkCode: match[0] };
    }

    // Internal circuit dispatch: `requireOwner()`, `onlyOwner()`, etc.
    // Treat presence as a strong check — the inner circuit is audited
    // separately.
    const dispatchPattern = /\b(require[A-Z][A-Za-z0-9]*|only[A-Z][A-Za-z0-9]*)\s*\(\s*\)/;
    if (dispatchPattern.test(body)) {
      return { hasCheck: true, hasWeakCheck: false };
    }

    return { hasCheck: false, hasWeakCheck: false };
  }

  /**
   * Check if circuit mutates state. Covers two Compact write patterns:
   *  - ADT methods on ledger fields: counter.increment(...), map.insert(...).
   *  - Direct ledger-field assignment: vaultBalance = ...; owner = ....
   * Direct assignment is the more common Compact form; the old check
   * missed it entirely.
   */
  private isStateMutating(circuit: CircuitInfo): boolean {
    const body = circuit.body;

    // ADT method calls on ledger fields.
    const adtWritePatterns = [
      /\.write\s*\(/,
      /\.insert\s*\(/,
      /\.increment\s*\(/,
      /\.decrement\s*\(/,
      /\.update\s*\(/,
      /\.remove\s*\(/
    ];
    if (adtWritePatterns.some(pattern => pattern.test(body))) {
      return true;
    }

    // Direct ledger-field assignment. We look for top-of-line
    // identifier = expression; patterns that aren't `const ...` /
    // `let ...` (those are local bindings, not ledger writes).
    const assignmentPattern = /(?<![A-Za-z0-9_$])(?!const\b|let\b|return\b)[A-Za-z_$][A-Za-z0-9_$]*\s*=\s*[^=]/m;
    return assignmentPattern.test(body);
  }

  /**
   * Look for commented-out function calls whose name suggests an
   * authorization guard. Catches:
   *   - "// requireOwner();"  (line comment)
   *   - "// requireOwner(); // Removed for demo"
   *   - Block-comment form "(slash-star) requireOwner(); (star-slash)"
   * Names matched: requireOwner, requireAuth, requireAdmin, onlyOwner,
   * checkAuth, assertAuth, assertOwner. False-positive rate is low
   * because the name itself signals authorization intent.
   */
  private findCommentedOutAuthCall(circuit: CircuitInfo): string | null {
    const body = circuit.body;
    const authNames = '(?:require[A-Z][A-Za-z0-9]*|only[A-Z][A-Za-z0-9]*|check(?:Auth|Owner|Admin|Role)|assert(?:Auth|Owner|Admin|Role))';

    // Line comments: `// callName(...)` possibly with trailing text.
    const lineCommentPattern = new RegExp(`//\\s*${authNames}\\s*\\(`, 'g');
    const lineMatch = body.match(lineCommentPattern);
    if (lineMatch && lineMatch.length > 0) {
      return lineMatch[0].replace(/\s+/g, ' ').trim();
    }

    // Block comments: `/* requireOwner(); */` on a single line.
    const blockCommentPattern = new RegExp(`/\\*[^*]*${authNames}\\s*\\([^*]*\\*/`, 'g');
    const blockMatch = body.match(blockCommentPattern);
    if (blockMatch && blockMatch.length > 0) {
      return blockMatch[0].replace(/\s+/g, ' ').trim();
    }

    return null;
  }

  /**
   * 3. State Mutation Audit
   * Tracks state transitions and flags risky patterns
   */
  private analyzeStateMutations(): void {
    const ledgerVars = this.stateVars.filter(v => v.kind === 'ledger');

    for (const circuit of this.circuits) {
      const mutations = this.findStateMutations(circuit);

      // Flag circuits that modify multiple state variables
      if (mutations.length > 3) {
        this.findings.push({
          type: 'state-mutation',
          severity: 'medium',
          title: `Complex state mutation: ${circuit.name}`,
          description: `Circuit "${circuit.name}" modifies ${mutations.length} state variables in a single transaction. This increases complexity and gas costs.`,
          location: {
            circuit: circuit.name
          },
          recommendation: `Consider splitting into multiple circuits or ensure all state changes are necessary and atomic.`,
          impact: 'Complex state mutations increase gas costs and make the contract harder to audit.'
        });
      }

      // Flag mutations without precondition checks
      for (const mutation of mutations) {
        const hasPreCondition = this.hasPreConditionCheck(circuit, mutation.variable);

        if (!hasPreCondition && ledgerVars.some(v => v.name === mutation.variable)) {
          this.findings.push({
            type: 'state-mutation',
            severity: 'medium',
            title: `Unchecked state mutation: ${mutation.variable}`,
            description: `Circuit "${circuit.name}" modifies "${mutation.variable}" without apparent precondition checks.`,
            location: {
              circuit: circuit.name,
              code: mutation.code
            },
            recommendation: `Add assertion to verify state preconditions before mutation. Example: assert(state.read() == ExpectedState, "Invalid state");`,
            impact: 'State could be corrupted if preconditions are not met.'
          });
        }
      }

      // NOTE: An earlier version of this heuristic emitted a
      // "Potential reentrancy risk" finding when a circuit performed any
      // state write while the body mentioned "external" or "call".
      // That heuristic was removed: Midnight has no synchronous external
      // call primitive. Circuits compile to ZK statements; the resulting
      // state delta is applied atomically by the ledger on inclusion.
      // There is no callback model and no reentrancy class (SWC-107
      // does not apply). The closest legitimate analog is stale-state
      // / ordering divergence — handled by ledger transcript checks,
      // not by checks-effects-interactions patterns.
    }
  }

  /**
   * Find all state mutations in a circuit
   */
  private findStateMutations(circuit: CircuitInfo): Array<{ variable: string; operation: string; code: string }> {
    const mutations: Array<{ variable: string; operation: string; code: string }> = [];
    const body = circuit.body;

    const mutationOps = ['write', 'insert', 'increment', 'decrement', 'update'];

    for (const op of mutationOps) {
      const regex = new RegExp(`(\\w+)\\.${op}\\s*\\(([^)]*)\\)`, 'g');
      let match;

      while ((match = regex.exec(body)) !== null) {
        mutations.push({
          variable: match[1],
          operation: op,
          code: match[0]
        });
      }
    }

    return mutations;
  }

  /**
   * Check if circuit has precondition checks for a variable
   */
  private hasPreConditionCheck(circuit: CircuitInfo, variable: string): boolean {
    // Look for assertions that read the variable before any writes
    const body = circuit.body;
    const lines = body.split('\n');

    let foundAssertion = false;
    let foundMutation = false;

    for (const line of lines) {
      // Check for assertion reading the variable
      if (line.includes('assert') && line.includes(`${variable}.read()`)) {
        foundAssertion = true;
      }

      // Check for mutation of the variable
      if (line.includes(`${variable}.write(`) ||
          line.includes(`${variable}.insert(`) ||
          line.includes(`${variable}.increment(`)) {
        foundMutation = true;
        break;
      }
    }

    return foundAssertion || !foundMutation;
  }

  /**
   * 4. Nullifier Analysis
   * Verifies nullifiers are used correctly to prevent double-spending
   */
  private analyzeNullifiers(): void {
    // Detect nullifier patterns
    const nullifierCreationRegex = /(\w+)\s*=\s*(?:disclose\s*\()?\s*persistentHash\s*<[^>]+>\s*\(\s*\[[^\]]*nullifier[^\]]*\]\s*\)/gi;
    const nullifierVars: string[] = [];

    let match;
    while ((match = nullifierCreationRegex.exec(this.contractSource)) !== null) {
      nullifierVars.push(match[1]);
    }

    if (nullifierVars.length === 0) {
      // No nullifiers found - might be okay for some contracts
      return;
    }

    for (const circuit of this.circuits) {
      // Check each nullifier variable
      for (const nullifierVar of nullifierVars) {
        const hasNullifier = circuit.body.includes(nullifierVar);

        if (hasNullifier) {
          // Check if nullifier is checked before use
          const hasDoubleSpendCheck = this.hasNullifierCheck(circuit, nullifierVar);

          if (!hasDoubleSpendCheck.hasCheck) {
            this.findings.push({
              type: 'nullifier',
              severity: 'critical',
              title: `Missing nullifier double-spend check: ${nullifierVar}`,
              description: `Circuit "${circuit.name}" creates nullifier "${nullifierVar}" but doesn't check if it was already used.`,
              location: {
                circuit: circuit.name
              },
              recommendation: `Add double-spend check: assert(!nullifierSet.member(${nullifierVar}), "Nullifier already used");`,
              impact: 'Users can double-spend by reusing the same nullifier multiple times.'
            });
          }

          // Check if nullifier is stored after use
          const hasStorage = this.hasNullifierStorage(circuit, nullifierVar);

          if (!hasStorage && hasDoubleSpendCheck.hasCheck) {
            this.findings.push({
              type: 'nullifier',
              severity: 'critical',
              title: `Nullifier not stored: ${nullifierVar}`,
              description: `Circuit "${circuit.name}" checks nullifier "${nullifierVar}" but doesn't store it, allowing reuse.`,
              location: {
                circuit: circuit.name
              },
              recommendation: `Store nullifier after checking: nullifierSet.insert(${nullifierVar});`,
              impact: 'Nullifier check is ineffective - users can still double-spend.'
            });
          }
        }
      }
    }
  }

  /**
   * Check if circuit properly checks nullifier for double-spend
   */
  private hasNullifierCheck(circuit: CircuitInfo, nullifierVar: string): { hasCheck: boolean } {
    const body = circuit.body;

    // Look for patterns like:
    // - assert(!set.member(nullifier), ...)
    // - assert(!nullifierSet.member(nullifier), ...)
    const checkPattern = new RegExp(`assert\\s*\\(\\s*!\\s*\\w+\\.member\\s*\\(\\s*${nullifierVar}\\s*\\)`, 'i');

    return { hasCheck: checkPattern.test(body) };
  }

  /**
   * Check if circuit stores nullifier after use
   */
  private hasNullifierStorage(circuit: CircuitInfo, nullifierVar: string): boolean {
    const body = circuit.body;

    // Look for patterns like:
    // - set.insert(nullifier)
    // - nullifierSet.insert(nullifier)
    const storagePattern = new RegExp(`\\w+\\.insert\\s*\\(\\s*${nullifierVar}\\s*\\)`, 'i');

    return storagePattern.test(body);
  }

  /**
   * 5. Taint Analysis
   * Tracks how user inputs flow through circuits to outputs
   */
  private analyzeTaint(): void {
    for (const circuit of this.circuits) {
      if (!circuit.isExported) continue;

      // Track tainted (user-controlled) inputs
      const taintedVars = new Set<string>();

      // All circuit parameters are tainted
      for (const param of circuit.params) {
        taintedVars.add(param.name);
      }

      // All witness calls are tainted
      const witnessVars = this.stateVars.filter(v => v.kind === 'witness');
      for (const witness of witnessVars) {
        const witnessUsageRegex = new RegExp(`(\\w+)\\s*=\\s*${witness.name}\\s*\\(`, 'g');
        let match;

        while ((match = witnessUsageRegex.exec(circuit.body)) !== null) {
          taintedVars.add(match[1]);
        }
      }

      // Check if tainted data reaches sensitive operations without validation
      this.checkTaintedStateMutations(circuit, taintedVars);
      this.checkTaintedControlFlow(circuit, taintedVars);
    }
  }

  /**
   * Check if tainted data is used in state mutations without validation
   */
  private checkTaintedStateMutations(circuit: CircuitInfo, taintedVars: Set<string>): void {
    const mutations = this.findStateMutations(circuit);

    for (const mutation of mutations) {
      // Check if mutation uses tainted data
      for (const taintedVar of taintedVars) {
        if (mutation.code.includes(taintedVar)) {
          // Check if there's validation before this mutation
          const hasValidation = this.hasValidationBefore(circuit.body, mutation.code, taintedVar);

          if (!hasValidation) {
            this.findings.push({
              type: 'taint',
              severity: 'high',
              title: `Unvalidated user input in state mutation: ${taintedVar}`,
              description: `Circuit "${circuit.name}" uses user-controlled input "${taintedVar}" in state mutation without validation.`,
              location: {
                circuit: circuit.name,
                code: mutation.code
              },
              recommendation: `Add validation assertion before using user input: assert(${taintedVar} < MAX_VALUE, "Invalid input");`,
              impact: 'User could manipulate state with malicious inputs, potentially corrupting contract state.'
            });
          }
        }
      }
    }
  }

  /**
   * Check if tainted data is used in control flow
   */
  private checkTaintedControlFlow(circuit: CircuitInfo, taintedVars: Set<string>): void {
    const body = circuit.body;

    // Look for conditional statements using tainted data
    for (const taintedVar of taintedVars) {
      const conditionalPattern = new RegExp(`if\\s*\\([^)]*\\b${taintedVar}\\b[^)]*\\)`, 'g');

      if (conditionalPattern.test(body)) {
        this.findings.push({
          type: 'taint',
          severity: 'medium',
          title: `User input in conditional: ${taintedVar}`,
          description: `Circuit "${circuit.name}" uses user-controlled "${taintedVar}" in conditional statement, potentially creating side-channels.`,
          location: {
            circuit: circuit.name
          },
          recommendation: `Validate input bounds and consider constant-time operations to prevent timing side-channels.`,
          impact: 'Conditional branches on user input may create observable timing or constraint count variations.'
        });
      }
    }
  }

  /**
   * Check if there's validation for a variable before a certain point in code
   */
  private hasValidationBefore(code: string, targetCode: string, variable: string): boolean {
    const targetIndex = code.indexOf(targetCode);
    if (targetIndex === -1) return false;

    const beforeTarget = code.substring(0, targetIndex);

    // Look for assert statements involving the variable
    const assertPattern = new RegExp(`assert\\s*\\([^;]*\\b${variable}\\b[^;]*,\\s*["']`, 'i');

    return assertPattern.test(beforeTarget);
  }

  /**
   * 6. Side-Channel Detection
   * Identifies potential timing or constraint count side-channels
   */
  private analyzeSideChannels(): void {
    for (const circuit of this.circuits) {
      // Check for variable-time operations
      this.checkVariableTimeOperations(circuit);

      // Check for data-dependent branches
      this.checkDataDependentBranches(circuit);
    }
  }

  /**
   * Check for variable-time operations that could leak info
   */
  private checkVariableTimeOperations(circuit: CircuitInfo): void {
    const witnessVars = this.stateVars.filter(v => v.kind === 'witness');

    // Check for loops with witness-dependent bounds
    for (const witness of witnessVars) {
      const loopPattern = new RegExp(`for\\s*\\([^;]*\\s*<\\s*[^;]*\\b${witness.name}\\b`, 'g');

      if (loopPattern.test(circuit.body)) {
        this.findings.push({
          type: 'side-channel',
          severity: 'high',
          title: `Variable-length loop based on private data: ${witness.name}`,
          description: `Circuit "${circuit.name}" has loop with bounds determined by private witness "${witness.name}".`,
          location: {
            circuit: circuit.name
          },
          recommendation: `Use fixed-size loops or pad to constant length to prevent constraint count leakage.`,
          impact: 'Loop iteration count reveals information about private input.'
        });
      }
    }
  }

  /**
   * Check for data-dependent conditional branches
   */
  private checkDataDependentBranches(circuit: CircuitInfo): void {
    const witnessVars = this.stateVars.filter(v => v.kind === 'witness');

    for (const witness of witnessVars) {
      // Check for if statements on witness data
      const ifPattern = new RegExp(`if\\s*\\([^)]*\\b${witness.name}\\b[^)]*\\)\\s*\\{`, 'g');
      let match;

      while ((match = ifPattern.exec(circuit.body)) !== null) {
        // Check if both branches have same complexity
        const branchesMatch = this.analyzeBranchComplexity(circuit.body, match.index);

        if (!branchesMatch) {
          this.findings.push({
            type: 'side-channel',
            severity: 'medium',
            title: `Unbalanced branches on private data: ${witness.name}`,
            description: `Circuit "${circuit.name}" has conditional branches on "${witness.name}" with different complexities.`,
            location: {
              circuit: circuit.name,
              code: match[0]
            },
            recommendation: `Ensure both branches have equal constraint counts by padding operations or using select() instead of if/else.`,
            impact: 'Constraint count differences between branches leak information about private input.'
          });
        }
      }
    }
  }

  /**
   * Analyze if conditional branches have similar complexity
   */
  private analyzeBranchComplexity(code: string, ifIndex: number): boolean {
    // Simple heuristic: check if then/else blocks have similar number of operations
    const afterIf = code.substring(ifIndex);

    const thenMatch = afterIf.match(/\{([^}]*)\}/);
    const elseMatch = afterIf.match(/\}\s*else\s*\{([^}]*)\}/);

    if (!thenMatch || !elseMatch) {
      return true; // Can't analyze, assume ok
    }

    const thenOps = (thenMatch[1].match(/[.;]/g) || []).length;
    const elseOps = (elseMatch[1].match(/[.;]/g) || []).length;

    // If operations differ by more than 20%, flag it
    return Math.abs(thenOps - elseOps) / Math.max(thenOps, elseOps) < 0.2;
  }

  /**
   * 7. Information Flow Analysis
   * Analyzes what private information can be inferred from public outputs
   */
  private analyzeInformationFlow(): void {
    const witnessVars = this.stateVars.filter(v => v.kind === 'witness');

    for (const circuit of this.circuits) {
      if (!circuit.isExported || circuit.returnType === '[]') {
        continue; // No public outputs
      }

      // Check if return value depends on witness data
      for (const witness of witnessVars) {
        const returnPattern = /return\s+([^;]+);/g;
        let match;

        while ((match = returnPattern.exec(circuit.body)) !== null) {
          const returnExpr = match[1];

          if (returnExpr.includes(witness.name)) {
            // Check if witness is disclosed or hashed
            const isHashed = /hash|Hash|commit|Commit/.test(returnExpr);
            const isDisclosed = returnExpr.includes('disclose');

            if (isDisclosed && !isHashed) {
              this.findings.push({
                type: 'info-flow',
                severity: 'high',
                title: `Private data disclosed in return value: ${witness.name}`,
                description: `Circuit "${circuit.name}" returns value derived from private witness "${witness.name}" via disclose().`,
                location: {
                  circuit: circuit.name,
                  code: match[0]
                },
                recommendation: `Use commitment or hash instead of direct disclosure. Only disclose if absolutely necessary (e.g., for nullifiers).`,
                impact: 'Private information becomes publicly visible, potentially compromising user privacy.'
              });
            } else if (!isHashed && !isDisclosed) {
              this.findings.push({
                type: 'info-flow',
                severity: 'info',
                title: `Witness data in return value: ${witness.name}`,
                description: `Circuit "${circuit.name}" derives return value from witness "${witness.name}".`,
                location: {
                  circuit: circuit.name
                },
                recommendation: `Verify that this doesn't leak information. Use zero-knowledge proofs to hide witness while proving properties.`,
                impact: 'Return value might leak information about private input.'
              });
            }
          }
        }
      }
    }
  }

  /**
   * Calculate overall risk score (0-100)
   */
  private calculateRiskScore(summary: { critical: number; high: number; medium: number; low: number; info: number }): number {
    const score =
      summary.critical * 20 +
      summary.high * 10 +
      summary.medium * 5 +
      summary.low * 2 +
      summary.info * 0.5;

    return Math.min(100, score);
  }
}
