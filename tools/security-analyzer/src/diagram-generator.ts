/**
 * Diagram Generators
 *
 * Generates:
 * - Sequence Diagrams (transaction flows)
 * - State Machine Diagrams (contract lifecycle)
 */

import { readFileSync, existsSync } from 'fs';
import type { AnalysisResult, CoverageAnalysis } from './types.js';

interface CircuitInfo {
  name: string;
  body: string;
  isExported: boolean;
}

interface StateTransition {
  from: string;
  to: string;
  circuit: string;
  condition?: string;
}

export class DiagramGenerator {
  private contractSource: string;
  private result: AnalysisResult;
  private circuits: CircuitInfo[] = [];
  private stateVars: string[] = [];

  constructor(contractPath: string, result: AnalysisResult) {
    if (!existsSync(contractPath)) {
      throw new Error(`Contract file not found: ${contractPath}`);
    }

    this.contractSource = readFileSync(contractPath, 'utf8');
    this.result = result;
    this.parseContract();
  }

  /**
   * Parse contract structure
   */
  private parseContract(): void {
    // Parse circuits
    const circuitRegex = /(export\s+)?circuit\s+(\w+)\s*\([^)]*\)\s*:[^{]+\{([^}]*(?:\{[^}]*\}[^}]*)*)\}/gs;
    let match;

    while ((match = circuitRegex.exec(this.contractSource)) !== null) {
      this.circuits.push({
        name: match[2],
        body: match[3],
        isExported: !!match[1]
      });
    }

    // Parse state variables (ledger only for state machine)
    const ledgerRegex = /ledger\s+(\w+)\s*:/g;
    while ((match = ledgerRegex.exec(this.contractSource)) !== null) {
      this.stateVars.push(match[1]);
    }
  }

  /**
   * Generate sequence diagram showing transaction flows
   */
  public generateSequenceDiagram(): string {
    const exportedCircuits = this.circuits.filter(c => c.isExported);

    if (exportedCircuits.length === 0) {
      return `sequenceDiagram
    participant User
    Note over User: No exported circuits found`;
    }

    let diagram = `sequenceDiagram
    participant User
    participant Contract
    participant Ledger
    participant Prover

    Note over User,Prover: Typical Transaction Sequences

`;

    // Generate sequence for each exported circuit
    for (const circuit of exportedCircuits) {
      diagram += this.generateCircuitSequence(circuit);
    }

    return diagram;
  }

  /**
   * Generate sequence for a single circuit
   */
  private generateCircuitSequence(circuit: CircuitInfo): string {
    const callGraph = this.result.coverage?.callGraph || {};
    const calledCircuits = callGraph[circuit.name] || [];

    let sequence = `    rect rgb(230, 240, 255)
    Note over User: ${circuit.name}()
    User->>+Contract: Call ${circuit.name}()
    Contract->>+Prover: Generate ZK proof

`;

    // Check for state reads
    const stateReads = this.findStateReads(circuit);
    if (stateReads.length > 0) {
      sequence += `    Contract->>Ledger: Read state (${stateReads.join(', ')})\n    Ledger-->>Contract: Current values\n    \n`;
    }

    // Check for witness calls
    const witnessCalls = this.findWitnessCalls(circuit);
    if (witnessCalls.length > 0) {
      sequence += `    Note over Contract: Verify private witnesses\n    \n`;
    }

    // Check for assertions
    const assertionCount = (circuit.body.match(/\bassert\s*\(/g) || []).length;
    if (assertionCount > 0) {
      sequence += `    Note over Contract: Check ${assertionCount} assertion(s)\n    \n`;
    }

    // Show called circuits
    if (calledCircuits.length > 0) {
      for (const called of calledCircuits.slice(0, 3)) { // Limit to 3 for readability
        sequence += `    Contract->>Contract: Call ${called}()\n`;
      }
      if (calledCircuits.length > 3) {
        sequence += `    Note over Contract: ... and ${calledCircuits.length - 3} more\n`;
      }
      sequence += `    \n`;
    }

    // Check for state writes
    const stateWrites = this.findStateWrites(circuit);
    if (stateWrites.length > 0) {
      sequence += `    Contract->>Ledger: Update state (${stateWrites.join(', ')})\n    Ledger-->>Contract: Confirmed\n    \n`;
    }

    sequence += `    Prover-->>-Contract: ZK proof generated
    Contract-->>-User: Transaction complete
    end

`;

    return sequence;
  }

  /**
   * Find state variables read in circuit
   */
  private findStateReads(circuit: CircuitInfo): string[] {
    const reads: string[] = [];
    for (const stateVar of this.stateVars) {
      if (new RegExp(`\\b${stateVar}\\.read\\s*\\(`).test(circuit.body)) {
        reads.push(stateVar);
      }
    }
    return reads;
  }

  /**
   * Find state variables written in circuit
   */
  private findStateWrites(circuit: CircuitInfo): string[] {
    const writes: string[] = [];
    const writeOps = ['write', 'insert', 'increment', 'decrement'];

    for (const stateVar of this.stateVars) {
      for (const op of writeOps) {
        if (new RegExp(`\\b${stateVar}\\.${op}\\s*\\(`).test(circuit.body)) {
          if (!writes.includes(stateVar)) {
            writes.push(stateVar);
          }
        }
      }
    }
    return writes;
  }

  /**
   * Find witness calls in circuit
   */
  private findWitnessCalls(circuit: CircuitInfo): string[] {
    const witnesses: string[] = [];
    const witnessRegex = /witness\s+(\w+)\s*\(/g;
    let match;

    // Find all witness definitions
    while ((match = witnessRegex.exec(this.contractSource)) !== null) {
      const witnessName = match[1];
      if (new RegExp(`\\b${witnessName}\\s*\\(`).test(circuit.body)) {
        witnesses.push(witnessName);
      }
    }

    return witnesses;
  }

  /**
   * Generate state machine diagram
   */
  public generateStateMachineDiagram(): string {
    // Look for state enumeration or state variable
    const stateEnumMatch = this.contractSource.match(/type\s+(\w*State\w*)\s*=\s*\{([^}]+)\}/i);

    if (!stateEnumMatch) {
      // Try to infer states from state variable usage
      return this.generateInferredStateMachine();
    }

    const stateTypeName = stateEnumMatch[1];
    const stateOptions = stateEnumMatch[2].split('|').map(s => s.trim());

    let diagram = `stateDiagram-v2
    [*] --> ${stateOptions[0]}

`;

    // Find state transitions
    const transitions = this.findStateTransitions(stateTypeName, stateOptions);

    // Generate transitions
    for (const transition of transitions) {
      const label = transition.circuit + (transition.condition ? ` [${transition.condition}]` : '');
      diagram += `    ${transition.from} --> ${transition.to}: ${label}\n`;
    }

    // Add end state if applicable
    const lastState = stateOptions[stateOptions.length - 1];
    diagram += `    ${lastState} --> [*]\n`;

    // Add notes for each state
    diagram += `\n    note right of ${stateOptions[0]}\n        Initial state\n    end note\n`;

    return diagram;
  }

  /**
   * Find state transitions by analyzing state writes
   */
  private findStateTransitions(stateTypeName: string, stateOptions: string[]): StateTransition[] {
    const transitions: StateTransition[] = [];

    for (const circuit of this.circuits.filter(c => c.isExported)) {
      // Find state writes in this circuit
      const stateWriteRegex = new RegExp(`state\\.write\\s*\\(\\s*([^)]+)\\)`, 'g');
      let match;

      while ((match = stateWriteRegex.exec(circuit.body)) !== null) {
        const writeExpr = match[1];

        // Try to determine which state it's writing to
        for (const toState of stateOptions) {
          if (writeExpr.includes(toState)) {
            // Try to infer from state
            const fromStateRegex = /state\.read\(\)\s*==\s*(\w+)/;
            const fromMatch = circuit.body.match(fromStateRegex);

            if (fromMatch) {
              transitions.push({
                from: fromMatch[1],
                to: toState,
                circuit: circuit.name
              });
            } else {
              // Generic transition
              transitions.push({
                from: 'Any',
                to: toState,
                circuit: circuit.name
              });
            }
          }
        }
      }
    }

    return transitions;
  }

  /**
   * Generate inferred state machine when no explicit state enum found
   */
  private generateInferredStateMachine(): string {
    let diagram = `stateDiagram-v2
    [*] --> Initialized

`;

    // Find circuits that modify state
    const stateModifyingCircuits = this.circuits.filter(c =>
      c.isExported && this.findStateWrites(c).length > 0
    );

    if (stateModifyingCircuits.length === 0) {
      diagram += `    Initialized --> [*]

    note right of Initialized
        No state transitions found
    end note`;
      return diagram;
    }

    // Create simple lifecycle based on circuit calls
    let currentState = 'Initialized';
    for (let i = 0; i < Math.min(stateModifyingCircuits.length, 5); i++) {
      const circuit = stateModifyingCircuits[i];
      const nextState = i === stateModifyingCircuits.length - 1 ? 'Finalized' : `State${i + 1}`;

      diagram += `    ${currentState} --> ${nextState}: ${circuit.name}()\n`;
      currentState = nextState;
    }

    if (stateModifyingCircuits.length > 5) {
      diagram += `    ${currentState} --> Finalized: ... (${stateModifyingCircuits.length - 5} more)\n`;
    }

    diagram += `    Finalized --> [*]\n`;

    return diagram;
  }

  /**
   * Generate deployment sequence diagram
   */
  public generateDeploymentSequence(): string {
    return `sequenceDiagram
    participant Developer
    participant Compiler
    participant Node
    participant Ledger

    Developer->>+Compiler: Compile contract
    Compiler->>Compiler: Generate ZKIR circuits
    Compiler->>Compiler: Generate proving/verifying keys
    Compiler-->>-Developer: Contract artifacts

    Developer->>+Node: Deploy contract
    Node->>Ledger: Initialize contract state
    Ledger-->>Node: State initialized
    Node-->>-Developer: Contract deployed

    Note over Developer,Ledger: Contract ready for transactions`;
  }
}
