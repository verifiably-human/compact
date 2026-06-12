/**
 * Advanced Static Analysis for Compact Contracts
 *
 * Performs:
 * - Complexity Metrics (cyclomatic complexity, call depth)
 * - Code Coverage Analysis (circuit usage, call graphs)
 * - Dead Code Detection (unused witnesses, circuits, unreachable code)
 */

import { readFileSync, existsSync } from 'fs';
import type { ComplexityMetrics, CircuitComplexity, CoverageAnalysis, DeadCodeFindings } from './types.js';

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
}

export class AdvancedAnalyzer {
  private contractSource: string;
  private contractPath: string;
  private circuits: CircuitInfo[] = [];
  private stateVars: StateVariable[] = [];

  constructor(contractPath: string) {
    this.contractPath = contractPath;

    if (!existsSync(contractPath)) {
      throw new Error(`Contract file not found: ${contractPath}`);
    }

    this.contractSource = readFileSync(contractPath, 'utf8');
  }

  /**
   * Run all advanced analyses
   */
  public analyze(): {
    complexity: CircuitComplexity[];
    coverage: CoverageAnalysis;
    deadCode: DeadCodeFindings;
  } {
    // Parse contract structure
    this.parseStateVariables();
    this.parseCircuits();

    // Perform analyses
    const complexity = this.analyzeComplexity();
    const coverage = this.analyzeCoverage();
    const deadCode = this.analyzeDeadCode();

    return { complexity, coverage, deadCode };
  }

  /**
   * Parse state variables (ledger and witness)
   */
  private parseStateVariables(): void {
    // Parse ledger variables
    const ledgerRegex = /ledger\s+(\w+)\s*:\s*([^;=]+)/g;
    let match;

    while ((match = ledgerRegex.exec(this.contractSource)) !== null) {
      this.stateVars.push({
        name: match[1],
        type: match[2].trim(),
        kind: 'ledger'
      });
    }

    // Parse witness variables
    const witnessRegex = /witness\s+(\w+)\s*\([^)]*\)\s*:\s*([^{;]+)/g;
    while ((match = witnessRegex.exec(this.contractSource)) !== null) {
      this.stateVars.push({
        name: match[1],
        type: match[2].trim(),
        kind: 'witness'
      });
    }
  }

  /**
   * Parse circuit definitions
   */
  private parseCircuits(): void {
    // Match circuit definitions with export keyword optional
    const circuitRegex = /(export\s+)?circuit\s+(\w+)\s*\(([^)]*)\)\s*:\s*([^{]+)\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}/gs;
    let match;

    while ((match = circuitRegex.exec(this.contractSource)) !== null) {
      const isExported = !!match[1];
      const name = match[2];
      const paramsStr = match[3];
      const returnType = match[4].trim();
      const body = match[5];

      // Parse parameters
      const params: Array<{ name: string; type: string }> = [];
      if (paramsStr.trim()) {
        const paramPairs = paramsStr.split(',');
        for (const pair of paramPairs) {
          const colonIndex = pair.indexOf(':');
          if (colonIndex !== -1) {
            params.push({
              name: pair.substring(0, colonIndex).trim(),
              type: pair.substring(colonIndex + 1).trim()
            });
          }
        }
      }

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
   * 10. Complexity Metrics
   * Calculate cyclomatic complexity and call depth
   */
  private analyzeComplexity(): CircuitComplexity[] {
    const results: CircuitComplexity[] = [];

    for (const circuit of this.circuits) {
      const metrics = this.calculateComplexityMetrics(circuit);
      const rating = this.rateComplexity(metrics);

      results.push({
        circuit: circuit.name,
        metrics,
        rating
      });
    }

    return results;
  }

  /**
   * Calculate complexity metrics for a circuit
   */
  private calculateComplexityMetrics(circuit: CircuitInfo): ComplexityMetrics {
    const body = circuit.body;

    // Count branches (if, else, match)
    const ifCount = (body.match(/\bif\s*\(/g) || []).length;
    const elseIfCount = (body.match(/\belse\s+if\s*\(/g) || []).length;
    const matchCount = (body.match(/\bmatch\s+/g) || []).length;
    const matchArms = (body.match(/=>/g) || []).length;
    const branchCount = ifCount + elseIfCount + matchCount;

    // Count loops (for, while)
    const forLoopCount = (body.match(/\bfor\s*\(/g) || []).length;
    const whileLoopCount = (body.match(/\bwhile\s*\(/g) || []).length;
    const loopCount = forLoopCount + whileLoopCount;

    // Count assertions
    const assertionCount = (body.match(/\bassert\s*\(/g) || []).length;

    // Calculate cyclomatic complexity
    // McCabe's formula: M = E - N + 2P
    // Simplified: M = decision_points + 1
    // Decision points: if, else if, match arms, loops, &&, ||
    const andOrCount = (body.match(/(\&\&|\|\|)/g) || []).length;
    const cyclomaticComplexity = 1 + branchCount + loopCount + matchArms + andOrCount;

    // Calculate call depth
    const callDepth = this.calculateCallDepth(circuit.name, new Set());

    return {
      cyclomaticComplexity,
      callDepth,
      branchCount,
      loopCount,
      assertionCount
    };
  }

  /**
   * Calculate maximum call depth from a circuit
   */
  private calculateCallDepth(circuitName: string, visited: Set<string>): number {
    if (visited.has(circuitName)) {
      return 0; // Circular reference, stop recursion
    }

    visited.add(circuitName);

    const circuit = this.circuits.find(c => c.name === circuitName);
    if (!circuit) return 0;

    // Find all circuit calls in this circuit
    const calledCircuits = this.findCircuitCalls(circuit);

    if (calledCircuits.length === 0) {
      return 1; // Leaf circuit
    }

    // Find maximum depth among all called circuits
    let maxDepth = 0;
    for (const called of calledCircuits) {
      const depth = this.calculateCallDepth(called, new Set(visited));
      maxDepth = Math.max(maxDepth, depth);
    }

    return 1 + maxDepth;
  }

  /**
   * Find all circuits called by a given circuit
   */
  private findCircuitCalls(circuit: CircuitInfo): string[] {
    const called: string[] = [];
    const body = circuit.body;

    // Find all circuit calls (circuitName(...))
    for (const otherCircuit of this.circuits) {
      if (otherCircuit.name === circuit.name) continue;

      // Look for calls to this circuit
      const callPattern = new RegExp(`\\b${otherCircuit.name}\\s*\\(`, 'g');
      if (callPattern.test(body)) {
        called.push(otherCircuit.name);
      }
    }

    return called;
  }

  /**
   * Rate complexity level
   */
  private rateComplexity(metrics: ComplexityMetrics): 'low' | 'medium' | 'high' | 'very-high' {
    const { cyclomaticComplexity } = metrics;

    if (cyclomaticComplexity <= 5) return 'low';
    if (cyclomaticComplexity <= 10) return 'medium';
    if (cyclomaticComplexity <= 20) return 'high';
    return 'very-high';
  }

  /**
   * 11. Code Coverage Analysis
   * Analyze which circuits are used and build call graphs
   */
  private analyzeCoverage(): CoverageAnalysis {
    const exportedCircuits = this.circuits.filter(c => c.isExported).map(c => c.name);
    const internalCircuits = this.circuits.filter(c => !c.isExported).map(c => c.name);

    // Build call graph
    const callGraph: Record<string, string[]> = {};
    const callerGraph: Record<string, string[]> = {};

    for (const circuit of this.circuits) {
      const called = this.findCircuitCalls(circuit);
      callGraph[circuit.name] = called;

      // Build reverse call graph
      for (const calledCircuit of called) {
        if (!callerGraph[calledCircuit]) {
          callerGraph[calledCircuit] = [];
        }
        callerGraph[calledCircuit].push(circuit.name);
      }
    }

    // Determine which circuits are actually called
    const calledCircuits = new Set<string>();
    const uncalledCircuits: string[] = [];

    // Start from exported circuits (entry points)
    const toVisit = [...exportedCircuits];
    const visited = new Set<string>();

    while (toVisit.length > 0) {
      const current = toVisit.pop()!;
      if (visited.has(current)) continue;
      visited.add(current);
      calledCircuits.add(current);

      const called = callGraph[current] || [];
      for (const calledCircuit of called) {
        if (!visited.has(calledCircuit)) {
          toVisit.push(calledCircuit);
        }
      }
    }

    // Find uncalled circuits
    for (const circuit of this.circuits) {
      if (!calledCircuits.has(circuit.name)) {
        uncalledCircuits.push(circuit.name);
      }
    }

    return {
      exportedCircuits,
      internalCircuits,
      calledCircuits: Array.from(calledCircuits),
      uncalledCircuits,
      callGraph,
      callerGraph
    };
  }

  /**
   * 12. Dead Code Detection
   * Find unused witnesses, circuits, and unreachable code
   */
  private analyzeDeadCode(): DeadCodeFindings {
    const unusedWitnesses: string[] = [];
    const unusedCircuits: string[] = [];
    const unreachableCode: Array<{ circuit: string; description: string; location: string }> = [];

    // Find unused witnesses
    for (const witness of this.stateVars.filter(v => v.kind === 'witness')) {
      let isUsed = false;

      // Check if witness is called in any circuit
      const witnessCallPattern = new RegExp(`\\b${witness.name}\\s*\\(`, 'g');
      for (const circuit of this.circuits) {
        if (witnessCallPattern.test(circuit.body)) {
          isUsed = true;
          break;
        }
      }

      if (!isUsed) {
        unusedWitnesses.push(witness.name);
      }
    }

    // Find unused circuits (already computed in coverage analysis)
    const coverage = this.analyzeCoverage();
    unusedCircuits.push(...coverage.uncalledCircuits);

    // Find unreachable code (code after return statements)
    for (const circuit of this.circuits) {
      const lines = circuit.body.split('\n');
      let foundReturn = false;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();

        if (line.startsWith('return ') || line === 'return;') {
          foundReturn = true;
          continue;
        }

        if (foundReturn && line.length > 0 && !line.startsWith('//') && !line.startsWith('}')) {
          unreachableCode.push({
            circuit: circuit.name,
            description: 'Code after return statement',
            location: `Line ${i + 1}: ${line.substring(0, 50)}...`
          });
          break; // Only report first instance
        }
      }
    }

    return {
      unusedWitnesses,
      unusedCircuits,
      unreachableCode
    };
  }
}
