/**
 * Attack Scenario Modeler
 *
 * Generates detailed attack scenarios based on security analysis findings
 * Models potential exploit paths, impacts, and mitigations
 */

import { writeFileSync } from 'fs';
import { basename } from 'path';
import type { AnalysisResult } from './types.js';
import type { SecurityFinding } from './security-analyzer.js';

interface AttackScenario {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  description: string;
  preconditions: string[];
  attackSteps: string[];
  impact: {
    confidentiality: 'high' | 'medium' | 'low' | 'none';
    integrity: 'high' | 'medium' | 'low' | 'none';
    availability: 'high' | 'medium' | 'low' | 'none';
    financial: string;
  };
  exploitComplexity: 'low' | 'medium' | 'high';
  detectionDifficulty: 'easy' | 'medium' | 'hard';
  mitigation: {
    shortTerm: string[];
    longTerm: string[];
    codeExample?: string;
  };
  affectedCircuits: string[];
  relatedCVEs: string[];
  references: string[];
}

export class AttackScenarioModeler {
  private result: AnalysisResult;
  private contractPath: string;
  private contractName: string;

  constructor(contractPath: string, result: AnalysisResult) {
    this.contractPath = contractPath;
    this.result = result;
    this.contractName = basename(contractPath, '.compact');
  }

  /**
   * Generate attack scenarios and save to file
   */
  public generate(outputPath: string): void {
    const scenarios = this.modelScenarios();
    const html = this.generateHTML(scenarios);
    writeFileSync(outputPath, html, 'utf8');
  }

  /**
   * Model attack scenarios from security findings
   */
  private modelScenarios(): AttackScenario[] {
    const scenarios: AttackScenario[] = [];

    if (!this.result.security) {
      return scenarios;
    }

    // Model scenarios from each finding type
    const findings = this.result.security.findings;

    // Group findings by type
    const groupedFindings: Record<string, SecurityFinding[]> = {};
    for (const finding of findings) {
      if (!groupedFindings[finding.type]) {
        groupedFindings[finding.type] = [];
      }
      groupedFindings[finding.type].push(finding);
    }

    // Model scenarios for each type
    if (groupedFindings['privacy-leak']) {
      scenarios.push(...this.modelPrivacyLeakScenarios(groupedFindings['privacy-leak']));
    }
    if (groupedFindings['access-control']) {
      scenarios.push(...this.modelAccessControlScenarios(groupedFindings['access-control']));
    }
    if (groupedFindings['state-mutation']) {
      scenarios.push(...this.modelStateMutationScenarios(groupedFindings['state-mutation']));
    }
    if (groupedFindings['nullifier']) {
      scenarios.push(...this.modelNullifierScenarios(groupedFindings['nullifier']));
    }
    if (groupedFindings['taint']) {
      scenarios.push(...this.modelTaintScenarios(groupedFindings['taint']));
    }
    if (groupedFindings['side-channel']) {
      scenarios.push(...this.modelSideChannelScenarios(groupedFindings['side-channel']));
    }
    if (groupedFindings['info-flow']) {
      scenarios.push(...this.modelInfoFlowScenarios(groupedFindings['info-flow']));
    }

    // Add generic attack scenarios
    scenarios.push(...this.modelGenericScenarios());

    return scenarios;
  }

  /**
   * Model privacy leak attack scenarios
   */
  private modelPrivacyLeakScenarios(findings: SecurityFinding[]): AttackScenario[] {
    const scenarios: AttackScenario[] = [];

    for (const finding of findings) {
      if (finding.severity === 'critical' || finding.severity === 'high') {
        scenarios.push({
          id: `PRIV-${scenarios.length + 1}`,
          title: 'Private Data Extraction Attack',
          severity: finding.severity,
          category: 'Privacy Breach',
          description: `An attacker can extract private user data by analyzing the disclosed information from the ${finding.location?.circuit} circuit. This violates the privacy guarantees of the zero-knowledge proof system.`,
          preconditions: [
            'Attacker can observe blockchain transactions',
            'Attacker has knowledge of contract structure',
            `Circuit ${finding.location?.circuit} discloses private witness data`
          ],
          attackSteps: [
            `1. Attacker deploys monitoring tool to watch ${this.contractName} transactions`,
            `2. Attacker calls ${finding.location?.circuit}() circuit with known inputs`,
            '3. Attacker observes disclosed private data in transaction output',
            '4. Attacker correlates disclosed data with other on-chain information',
            '5. Attacker builds database of private user information',
            '6. Attacker uses information for targeted attacks or sells on dark web'
          ],
          impact: {
            confidentiality: 'high',
            integrity: 'none',
            availability: 'none',
            financial: 'Users lose privacy; potential regulatory penalties; reputational damage'
          },
          exploitComplexity: 'low',
          detectionDifficulty: 'hard',
          mitigation: {
            shortTerm: [
              'Add access control to restrict who can call the circuit',
              'Implement rate limiting on circuit calls',
              'Add monitoring for suspicious patterns'
            ],
            longTerm: [
              'Remove direct disclosure of witness data',
              'Use commitment schemes instead of disclosure',
              'Implement zero-knowledge range proofs',
              'Redesign circuit to eliminate privacy leaks'
            ],
            codeExample: `// Instead of:
disclose(private$secret_data())

// Use:
persistentHash<"commitment", Bytes<32>>([private$secret_data(), private$nonce()])`
          },
          affectedCircuits: finding.location?.circuit ? [finding.location.circuit] : [],
          relatedCVEs: ['CVE-2021-XXXXX (ZK privacy leak)'],
          references: [
            'https://eprint.iacr.org/2021/1234.pdf',
            'OWASP Top 10 Privacy Risks'
          ]
        });
      }
    }

    return scenarios;
  }

  /**
   * Model access control attack scenarios
   */
  private modelAccessControlScenarios(findings: SecurityFinding[]): AttackScenario[] {
    const scenarios: AttackScenario[] = [];

    const highSeverityFindings = findings.filter(f => f.severity === 'high');
    if (highSeverityFindings.length > 0) {
      const affectedCircuits = highSeverityFindings.map(f => f.location?.circuit || '').filter(Boolean);

      scenarios.push({
        id: `AC-1`,
        title: 'Unauthorized State Manipulation',
        severity: 'high',
        category: 'Access Control',
        description: `Multiple circuits lack authorization checks, allowing any user to modify contract state. An attacker can call ${affectedCircuits.join(', ')} to manipulate contract behavior.`,
        preconditions: [
          'Contract is deployed on network',
          'Attacker has DUST for transaction fees',
          'No authorization checks on state-mutating circuits'
        ],
        attackSteps: [
          '1. Attacker reads the deployed contract\'s ledger state and contract-info.json to identify exported circuits and their guards.',
          `2. Attacker submits a valid transaction calling ${affectedCircuits[0]}() with chosen circuit arguments.`,
          '3. Because the circuit body lacks an `assert` tying the caller\'s witness-known key to the on-chain authority field, the proof verifies without proving authorization.',
          '4. The ledger applies the state delta atomically.',
          '5. Attacker repeats for other unguarded circuits.'
        ],
        impact: {
          confidentiality: 'low',
          integrity: 'high',
          availability: 'medium',
          financial: 'Operator-controlled state can be mutated by any caller; tokens and compliance fields are at risk depending on contract domain.'
        },
        exploitComplexity: 'low',
        detectionDifficulty: 'easy',
        mitigation: {
          shortTerm: [
            'Add an authorization assertion at the top of every exported state-mutating circuit.',
            'If a guard exists but is commented out, restore it.',
            'Have the contract maintenance authority (where present) freeze further state changes pending a fixed deployment.'
          ],
          longTerm: [
            'Choose an identity model explicitly: single owner key in a sealed ledger field, Merkle-root group membership, or ZK signature over an allow-list.',
            'For multi-operator contracts, implement an M-of-N membership proof inside the circuit; do not rely on off-chain coordination.',
            'Audit every exported circuit\'s first statement before deployment.'
          ],
          codeExample: `// Real Compact authorization pattern.
//
// Owner identity is the persistentHash of a witness-known secret key,
// stored once in a sealed ledger field.

witness ownerSecret(): Bytes<32>;
sealed ledger ownerKey: Bytes<32>;

circuit requireOwner(): [] {
  const sk = ownerSecret();
  const provided = persistentHash<Vector<2, Bytes<32>>>(
    [pad(32, "domain:owner:"), sk]
  );
  // Critical: assert against the ledger value directly. Do NOT wrap
  // the equality in disclose() — that exposes the boolean to the
  // ledger but the assert is what gates the circuit.
  assert(provided == ownerKey, "not owner");
}

export circuit protectedOperation(...): [] {
  requireOwner();
  // ... rest of circuit logic
}`
        },
        affectedCircuits,
        relatedCVEs: [],
        references: [
          'midnight-ledger contract maintenance authority (ledger/src/structure.rs)',
          'compact-core:compact-patterns — access control patterns for Midnight'
        ]
      });
    }

    return scenarios;
  }

  /**
   * Model state mutation attack scenarios
   */
  private modelStateMutationScenarios(findings: SecurityFinding[]): AttackScenario[] {
    const scenarios: AttackScenario[] = [];

    // The previous SM-1 "Reentrancy Attack on State Mutations" scenario
    // was removed: Midnight has no synchronous external call primitive
    // and no callback model, so SWC-107 reentrancy is not expressible.
    // Cross-contract calls compose at the ledger transcript level and
    // do not re-enter the caller's circuit.
    //
    // The closest legitimate analog on Midnight is stale-state /
    // ordering divergence — an actor reads ledger state at time T,
    // proves against it, transaction lands at T+k with diverged state.
    // The ledger's transcript verification rejects this when the
    // touched fields diverge, so reporting it as a generic scenario
    // here would be inaccurate. Future work: a contract-specific
    // ordering check on circuits whose outcome depends on a read of
    // a field that another circuit can mutate between prepare and
    // execute.

    return scenarios;
  }

  /**
   * Model nullifier attack scenarios
   */
  private modelNullifierScenarios(findings: SecurityFinding[]): AttackScenario[] {
    const scenarios: AttackScenario[] = [];

    for (const finding of findings.filter(f => f.severity === 'critical')) {
      scenarios.push({
        id: `NULL-1`,
        title: 'Double-Spend Attack via Missing Nullifier Check',
        severity: 'critical',
        category: 'Double Spending',
        description: `Circuit ${finding.location?.circuit} creates nullifiers but doesn't check if they've been used before, enabling double-spend attacks.`,
        preconditions: [
          'Circuit accepts nullifiers without verification',
          'Attacker has valid witness data',
          'No nullifier registry check implemented'
        ],
        attackSteps: [
          '1. Attacker obtains valid witness data (e.g., through legitimate transaction)',
          `2. Attacker calls ${finding.location?.circuit}() with witness data`,
          '3. Transaction succeeds, nullifier is created but not checked',
          '4. Attacker immediately calls circuit again with same witness',
          '5. Second transaction succeeds (no double-spend check)',
          '6. Attacker repeats indefinitely, draining resources'
        ],
        impact: {
          confidentiality: 'none',
          integrity: 'high',
          availability: 'high',
          financial: 'Unlimited token minting; complete fund drainage; contract insolvency'
        },
        exploitComplexity: 'low',
        detectionDifficulty: 'easy',
        mitigation: {
          shortTerm: [
            'Immediately pause contract',
            'Deploy hotfix with nullifier checks',
            'Identify and freeze affected accounts'
          ],
          longTerm: [
            'Implement nullifier registry',
            'Check nullifiers before accepting transactions',
            'Add comprehensive double-spend testing',
            'Implement nullifier expiry if appropriate'
          ],
          codeExample: `// Proper nullifier handling:
circuit spend(nullifier: Bytes<32>): [] {
  // CHECK: Ensure nullifier hasn't been used
  assert(
    !spent_nullifiers.member(nullifier),
    "Double-spend: nullifier already used"
  );

  // EFFECT: Mark nullifier as spent
  spent_nullifiers.insert(nullifier);

  // ... rest of logic
}`
        },
        affectedCircuits: [finding.location?.circuit || ''],
        relatedCVEs: ['CVE-2019-XXXXX (ZK double-spend)'],
        references: [
          'Zcash Security - Nullifier Design',
          'Privacy-Preserving Cryptocurrencies'
        ]
      });
    }

    return scenarios;
  }

  /**
   * Model taint attack scenarios
   */
  private modelTaintScenarios(findings: SecurityFinding[]): AttackScenario[] {
    const scenarios: AttackScenario[] = [];

    for (const finding of findings.filter(f => f.severity === 'high')) {
      scenarios.push({
        id: `TAINT-1`,
        title: 'State Corruption via Unvalidated Input',
        severity: 'high',
        category: 'Input Validation',
        description: `Circuit ${finding.location?.circuit} uses user-controlled input in state mutations without validation, enabling state corruption attacks.`,
        preconditions: [
          'Circuit accepts user input',
          'No input validation or sanitization',
          'User input flows to state mutations'
        ],
        attackSteps: [
          '1. Attacker analyzes circuit to identify input parameters',
          '2. Attacker crafts malicious input (overflow, underflow, invalid states)',
          `3. Attacker calls ${finding.location?.circuit}() with malicious input`,
          '4. Circuit processes input without validation',
          '5. Malicious input corrupts contract state',
          '6. Contract enters invalid state, breaking invariants'
        ],
        impact: {
          confidentiality: 'low',
          integrity: 'high',
          availability: 'medium',
          financial: 'State corruption; broken contract logic; potential fund loss'
        },
        exploitComplexity: 'medium',
        detectionDifficulty: 'medium',
        mitigation: {
          shortTerm: [
            'Add input validation to all user parameters',
            'Implement bounds checking',
            'Add invariant checks after state updates'
          ],
          longTerm: [
            'Use strong typing to prevent invalid inputs',
            'Implement formal verification of state invariants',
            'Add comprehensive input fuzzing tests',
            'Use allowlists instead of blocklists'
          ],
          codeExample: `// Real Compact input validation.
//
// Note: Compact's Uint<n> types are range-constrained at the type
// level. Passing a value outside the declared range causes the proof
// to fail verification — there is no silent wrap-around (SWC-101 does
// NOT apply). The real risk is unasserted invariants on Field-typed
// values, where the field arithmetic is unbounded.

ledger state: STATE;
ledger value: Field;
enum STATE { unset, set }

export circuit setValue(userInput: Field): [] {
  // Field-typed input has no implicit bound. If you need one,
  // assert it explicitly:
  assert(userInput < 1000, "Input out of range");

  // State precondition is read directly from the ledger field.
  assert(state == STATE.unset, "Invalid state");

  // Ledger writes are field assignments wrapped in disclose() for any
  // value that originated from a witness.
  value = disclose(userInput);
  state = STATE.set;
}`
        },
        affectedCircuits: [finding.location?.circuit || ''],
        relatedCVEs: [],
        references: [
          'Compact Uint<n> types — range-constrained at the type level',
          'compact-core:compact-language-ref — type semantics'
        ]
      });
    }

    return scenarios;
  }

  /**
   * Model side-channel attack scenarios
   */
  private modelSideChannelScenarios(findings: SecurityFinding[]): AttackScenario[] {
    const scenarios: AttackScenario[] = [];

    if (findings.length > 0) {
      scenarios.push({
        id: `SC-1`,
        title: 'Timing Side-Channel Information Leak',
        severity: 'medium',
        category: 'Side Channel',
        description: 'Variable-time operations and unbalanced branches leak information about private inputs through timing analysis.',
        preconditions: [
          'Circuit has data-dependent branches',
          'Attacker can measure proof generation time',
          'Attacker has statistical analysis tools'
        ],
        attackSteps: [
          '1. Attacker submits many transactions with varying inputs',
          '2. Attacker measures proof generation time for each',
          '3. Attacker identifies timing variations based on private data',
          '4. Attacker uses statistical analysis to extract patterns',
          '5. Attacker infers private information from timing differences',
          '6. Attacker builds profile of private user data'
        ],
        impact: {
          confidentiality: 'medium',
          integrity: 'none',
          availability: 'none',
          financial: 'Privacy leak; partial information disclosure'
        },
        exploitComplexity: 'high',
        detectionDifficulty: 'hard',
        mitigation: {
          shortTerm: [
            'Add random delays to proof generation',
            'Implement constant-time operations',
            'Monitor for timing analysis attempts'
          ],
          longTerm: [
            'Use constant-time circuit implementations',
            'Balance all conditional branches',
            'Implement zero-knowledge proofs for all decisions',
            'Conduct side-channel security audit'
          ],
          codeExample: `// Use select() instead of if/else for constant-time:

// BAD: Variable-time branch
if (private_value > threshold) {
  result = expensive_computation();
} else {
  result = cheap_computation();
}

// GOOD: Constant-time selection
let expensive = expensive_computation();
let cheap = cheap_computation();
result = select(private_value > threshold, expensive, cheap);`
        },
        affectedCircuits: findings.map(f => f.location?.circuit || '').filter(Boolean),
        relatedCVEs: ['CVE-2017-XXXXX (Timing attack)'],
        references: [
          'Timing Attacks on Implementations of Diffie-Hellman',
          'ZK Side-Channel Security'
        ]
      });
    }

    return scenarios;
  }

  /**
   * Model information flow attack scenarios
   */
  private modelInfoFlowScenarios(findings: SecurityFinding[]): AttackScenario[] {
    const scenarios: AttackScenario[] = [];

    for (const finding of findings.filter(f => f.severity === 'high')) {
      scenarios.push({
        id: `IF-1`,
        title: 'Private Data Inference from Public Outputs',
        severity: 'high',
        category: 'Information Flow',
        description: `Circuit ${finding.location?.circuit} returns values derived from private witnesses, enabling inference attacks.`,
        preconditions: [
          'Circuit returns data derived from private inputs',
          'Attacker can observe return values',
          'Attacker has background knowledge'
        ],
        attackSteps: [
          '1. Attacker observes public outputs over multiple transactions',
          '2. Attacker correlates outputs with known information',
          '3. Attacker uses statistical inference to deduce private inputs',
          '4. Attacker builds probabilistic model of private data',
          '5. Attacker refines model with additional observations',
          '6. Attacker achieves high-confidence inference of private data'
        ],
        impact: {
          confidentiality: 'high',
          integrity: 'none',
          availability: 'none',
          financial: 'Privacy breach; potential regulatory violations'
        },
        exploitComplexity: 'medium',
        detectionDifficulty: 'hard',
        mitigation: {
          shortTerm: [
            'Reduce information in return values',
            'Add noise to outputs',
            'Rate-limit circuit calls'
          ],
          longTerm: [
            'Use zero-knowledge proofs for all outputs',
            'Implement differential privacy',
            'Return only commitments, not raw values',
            'Conduct information flow analysis'
          ],
          codeExample: `// Return commitment instead of derived value:

// BAD: Returns derived value
return disclose(hash(private_data));

// GOOD: Returns commitment only
let commitment = persistentHash<"commit", Bytes<32>>([
  private_data,
  private_nonce
]);
return commitment;`
        },
        affectedCircuits: [finding.location?.circuit || ''],
        relatedCVEs: [],
        references: [
          'Information Flow in Zero-Knowledge Proofs',
          'Differential Privacy in Blockchain'
        ]
      });
    }

    return scenarios;
  }

  /**
   * Model generic attack scenarios applicable to all contracts.
   *
   * Both prior entries here (GEN-1 Front-Running, GEN-2 DoS via
   * Resource Exhaustion) were removed: they were generic blockchain
   * scenarios that fired on every contract regardless of structure
   * and didn't model Midnight semantics.
   *
   * GEN-1 (Front-Running): the analyzer cannot tell, without
   * semantic analysis of value-bearing public state changes, whether
   * a contract is front-runnable. Most Midnight contracts use
   * shielded transfers or commitment-reveal patterns that defeat
   * naive front-running. A generic finding on every contract is
   * pure noise; an actually-useful version requires per-circuit
   * semantic analysis of (a) what's observable on chain after the
   * call and (b) whether an attacker can submit a competing call
   * before inclusion. Out of scope for this analyzer until a
   * stale-state / ordering-divergence detector is built.
   *
   * GEN-2 (DoS via Resource Exhaustion): conflated three things —
   * EVM-style consensus DoS (doesn't apply: Midnight has DUST fees),
   * prover-host resource pressure (operator concern, not contract
   * concern), and circuit complexity (a UX / cost concern surfaced
   * in the Performance section). None of these are contract-level
   * security findings. The Performance Insights section already
   * flags large circuits like `prepareWithdrawal` (>30s); duplicating
   * the warning in attack-scenarios mis-framed it as an attack.
   *
   * If a real ordering-class attack ever becomes detectable from
   * source (e.g., an exported circuit reads a publicly-readable
   * ledger field and uses the read in a value-bearing write without
   * binding to the read in the proof), a Midnight-native scenario
   * can be added here.
   */
  private modelGenericScenarios(): AttackScenario[] {
    return [];
  }

  /**
   * Generate HTML report
   */
  private generateHTML(scenarios: AttackScenario[]): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${this.contractName} - Attack Scenario Analysis</title>
  <style>
    ${this.getStyles()}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>🛡️ Attack Scenario Analysis</h1>
      <p class="subtitle">${this.contractName} Contract</p>
      <div class="metadata">
        <span>Generated: ${new Date(this.result.timestamp).toLocaleString()}</span>
        <span>${scenarios.length} scenarios identified</span>
        <span>Risk Score: ${this.result.security?.riskScore || 0}/100</span>
      </div>
    </header>

    <section class="summary">
      <h2>Executive Summary</h2>
      <div class="summary-grid">
        <div class="summary-card critical">
          <div class="card-value">${scenarios.filter(s => s.severity === 'critical').length}</div>
          <div class="card-label">Critical Threats</div>
        </div>
        <div class="summary-card high">
          <div class="card-value">${scenarios.filter(s => s.severity === 'high').length}</div>
          <div class="card-label">High Threats</div>
        </div>
        <div class="summary-card medium">
          <div class="card-value">${scenarios.filter(s => s.severity === 'medium').length}</div>
          <div class="card-label">Medium Threats</div>
        </div>
        <div class="summary-card low">
          <div class="card-value">${scenarios.filter(s => s.severity === 'low').length}</div>
          <div class="card-label">Low Threats</div>
        </div>
      </div>

      <div class="threat-categories">
        <h3>Threat Categories</h3>
        ${this.generateCategoryBreakdown(scenarios)}
      </div>
    </section>

    <section class="scenarios">
      <h2>Attack Scenarios</h2>
      ${scenarios.map(s => this.generateScenarioHTML(s)).join('\n')}
    </section>

    <footer>
      <p><strong>Disclaimer:</strong> This analysis is generated automatically and should be reviewed by security professionals.</p>
      <p>Generated by Compact Circuit Analyzer • ${new Date().getFullYear()}</p>
    </footer>
  </div>
</body>
</html>`;
  }

  /**
   * Generate category breakdown
   */
  private generateCategoryBreakdown(scenarios: AttackScenario[]): string {
    const categories = new Map<string, number>();
    for (const scenario of scenarios) {
      categories.set(scenario.category, (categories.get(scenario.category) || 0) + 1);
    }

    return `<div class="category-list">
${Array.from(categories.entries()).map(([cat, count]) =>
  `<div class="category-item"><span class="category-name">${cat}</span><span class="category-count">${count}</span></div>`
).join('\n')}
    </div>`;
  }

  /**
   * Generate HTML for a single scenario
   */
  private generateScenarioHTML(scenario: AttackScenario): string {
    return `
    <div class="scenario ${scenario.severity}">
      <div class="scenario-header">
        <h3><span class="scenario-id">${scenario.id}</span> ${scenario.title}</h3>
        <div class="scenario-badges">
          <span class="badge severity-${scenario.severity}">${scenario.severity.toUpperCase()}</span>
          <span class="badge category">${scenario.category}</span>
          <span class="badge complexity-${scenario.exploitComplexity}">${scenario.exploitComplexity.toUpperCase()} complexity</span>
        </div>
      </div>

      <div class="scenario-description">
        ${scenario.description}
      </div>

      <div class="scenario-section">
        <h4>💡 Preconditions</h4>
        <ul>
          ${scenario.preconditions.map(p => `<li>${p}</li>`).join('')}
        </ul>
      </div>

      <div class="scenario-section">
        <h4>⚔️ Attack Steps</h4>
        <ol class="attack-steps">
          ${scenario.attackSteps.map(step => `<li>${step}</li>`).join('')}
        </ol>
      </div>

      <div class="scenario-section">
        <h4>💥 Impact Assessment</h4>
        <div class="impact-grid">
          <div class="impact-item">
            <span class="impact-label">Confidentiality:</span>
            <span class="impact-value ${scenario.impact.confidentiality}">${scenario.impact.confidentiality}</span>
          </div>
          <div class="impact-item">
            <span class="impact-label">Integrity:</span>
            <span class="impact-value ${scenario.impact.integrity}">${scenario.impact.integrity}</span>
          </div>
          <div class="impact-item">
            <span class="impact-label">Availability:</span>
            <span class="impact-value ${scenario.impact.availability}">${scenario.impact.availability}</span>
          </div>
          <div class="impact-item full-width">
            <span class="impact-label">Financial Impact:</span>
            <span class="impact-description">${scenario.impact.financial}</span>
          </div>
        </div>
        <div class="exploit-info">
          <span><strong>Exploit Complexity:</strong> ${scenario.exploitComplexity}</span>
          <span><strong>Detection Difficulty:</strong> ${scenario.detectionDifficulty}</span>
        </div>
      </div>

      <div class="scenario-section">
        <h4>🛡️ Mitigation Strategies</h4>
        <div class="mitigation">
          <div class="mitigation-section">
            <h5>Short-term (Immediate)</h5>
            <ul>
              ${scenario.mitigation.shortTerm.map(m => `<li>${m}</li>`).join('')}
            </ul>
          </div>
          <div class="mitigation-section">
            <h5>Long-term (Strategic)</h5>
            <ul>
              ${scenario.mitigation.longTerm.map(m => `<li>${m}</li>`).join('')}
            </ul>
          </div>
        </div>
        ${scenario.mitigation.codeExample ? `
        <div class="code-example">
          <h5>Code Example</h5>
          <pre><code>${this.escapeHtml(scenario.mitigation.codeExample)}</code></pre>
        </div>` : ''}
      </div>

      ${scenario.affectedCircuits.length > 0 ? `
      <div class="scenario-section">
        <h4>🎯 Affected Circuits</h4>
        <div class="affected-circuits">
          ${scenario.affectedCircuits.map(c => `<span class="circuit-tag">${c}</span>`).join(' ')}
        </div>
      </div>` : ''}

      ${scenario.references.length > 0 ? `
      <div class="scenario-section">
        <h4>📚 References</h4>
        <ul class="references">
          ${scenario.references.map(r => `<li>${r}</li>`).join('')}
        </ul>
      </div>` : ''}
    </div>`;
  }

  private escapeHtml(text: string): string {
    return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  private getStyles(): string {
    return `
      * { margin: 0; padding: 0; box-sizing: border-box; }
      body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        line-height: 1.6;
        color: #333;
        background: #f5f5f5;
        padding: 20px;
      }
      .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
      header { text-align: center; margin-bottom: 40px; padding-bottom: 30px; border-bottom: 3px solid #dc3545; }
      h1 { font-size: 2.5rem; color: #dc3545; margin-bottom: 10px; }
      .subtitle { font-size: 1.2rem; color: #666; margin-bottom: 20px; }
      .metadata { display: flex; justify-content: center; gap: 20px; flex-wrap: wrap; }
      .metadata span { padding: 6px 12px; background: #f8f9fa; border-radius: 4px; font-size: 0.9rem; }
      h2 { font-size: 2rem; margin: 40px 0 20px; color: #333; border-bottom: 2px solid #ddd; padding-bottom: 10px; }
      h3 { font-size: 1.5rem; margin: 20px 0 10px; color: #333; }
      h4 { font-size: 1.2rem; margin: 20px 0 10px; color: #555; }
      h5 { font-size: 1rem; margin: 15px 0 8px; color: #666; }
      .summary { margin-bottom: 40px; }
      .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
      .summary-card { padding: 30px; border-radius: 8px; text-align: center; color: white; }
      .summary-card.critical { background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); }
      .summary-card.high { background: linear-gradient(135deg, #fd7e14 0%, #e96d00 100%); }
      .summary-card.medium { background: linear-gradient(135deg, #ffc107 0%, #e0a800 100%); }
      .summary-card.low { background: linear-gradient(135deg, #17a2b8 0%, #138496 100%); }
      .card-value { font-size: 3rem; font-weight: 700; }
      .card-label { font-size: 1rem; text-transform: uppercase; letter-spacing: 1px; margin-top: 5px; }
      .threat-categories { background: #f8f9fa; padding: 20px; border-radius: 8px; }
      .category-list { display: flex; flex-direction: column; gap: 10px; }
      .category-item { display: flex; justify-content: space-between; padding: 10px; background: white; border-radius: 4px; }
      .category-name { font-weight: 600; }
      .category-count { background: #4169E1; color: white; padding: 2px 10px; border-radius: 12px; font-size: 0.85rem; }
      .scenario { background: #fff; border: 2px solid #ddd; border-radius: 8px; padding: 30px; margin-bottom: 30px; }
      .scenario.critical { border-left: 6px solid #dc3545; }
      .scenario.high { border-left: 6px solid #fd7e14; }
      .scenario.medium { border-left: 6px solid #ffc107; }
      .scenario.low { border-left: 6px solid #17a2b8; }
      .scenario-header { margin-bottom: 20px; }
      .scenario-id { background: #333; color: white; padding: 4px 10px; border-radius: 4px; font-size: 0.9rem; margin-right: 10px; }
      .scenario-badges { display: flex; gap: 10px; margin-top: 10px; flex-wrap: wrap; }
      .badge { padding: 4px 12px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
      .severity-critical { background: #dc3545; color: white; }
      .severity-high { background: #fd7e14; color: white; }
      .severity-medium { background: #ffc107; color: #333; }
      .severity-low { background: #17a2b8; color: white; }
      .badge.category { background: #6c757d; color: white; }
      .badge.complexity-low { background: #28a745; color: white; }
      .badge.complexity-medium { background: #ffc107; color: #333; }
      .badge.complexity-high { background: #dc3545; color: white; }
      .scenario-description { font-size: 1.1rem; line-height: 1.8; margin-bottom: 20px; padding: 15px; background: #f8f9fa; border-left: 4px solid #4169E1; }
      .scenario-section { margin: 25px 0; }
      ul, ol { margin-left: 20px; }
      li { margin: 8px 0; }
      .attack-steps { background: #fff3cd; padding: 20px; border-radius: 8px; }
      .attack-steps li { font-weight: 500; }
      .impact-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin: 15px 0; }
      .impact-item { padding: 15px; background: #f8f9fa; border-radius: 8px; }
      .impact-item.full-width { grid-column: 1 / -1; }
      .impact-label { display: block; font-size: 0.85rem; color: #666; margin-bottom: 5px; }
      .impact-value { font-weight: 700; text-transform: uppercase; }
      .impact-value.high { color: #dc3545; }
      .impact-value.medium { color: #fd7e14; }
      .impact-value.low { color: #ffc107; }
      .impact-value.none { color: #28a745; }
      .impact-description { font-style: italic; color: #555; }
      .exploit-info { display: flex; gap: 30px; margin-top: 15px; padding: 15px; background: #e9ecef; border-radius: 8px; }
      .mitigation { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 15px 0; }
      .mitigation-section { background: #f8f9fa; padding: 15px; border-radius: 8px; }
      .code-example { margin-top: 15px; }
      pre { background: #1e1e1e; color: #e0e0e0; padding: 20px; border-radius: 8px; overflow-x: auto; }
      code { font-family: 'Courier New', monospace; font-size: 0.9rem; }
      .affected-circuits { display: flex; gap: 10px; flex-wrap: wrap; }
      .circuit-tag { background: #4169E1; color: white; padding: 6px 12px; border-radius: 20px; font-size: 0.85rem; }
      .references { list-style-type: none; margin-left: 0; }
      .references li { padding: 8px; background: #f8f9fa; margin: 5px 0; border-radius: 4px; }
      footer { margin-top: 60px; padding-top: 30px; border-top: 2px solid #ddd; text-align: center; color: #888; }
      @media (max-width: 768px) {
        .summary-grid, .impact-grid, .mitigation { grid-template-columns: 1fr; }
        h1 { font-size: 2rem; }
      }
    `;
  }
}
