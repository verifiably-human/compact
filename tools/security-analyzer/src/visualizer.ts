/**
 * Circuit Visualizer
 *
 * Generates visual diagrams of Compact circuits including:
 * - Dependency graphs
 * - Constraint flows
 * - Variable relationships
 * - Ledger interactions
 * - Performance heatmaps
 */

import { execSync } from 'child_process';
import { existsSync, mkdirSync, writeFileSync, readFileSync } from 'fs';
import { join, basename } from 'path';
import type { AnalysisResult, CircuitMetrics } from './types.js';

export type VisualizationFormat = 'png' | 'svg' | 'pdf' | 'dot';
export type VisualizationTheme = 'default' | 'dark' | 'light' | 'colorful';
export type VisualizationType =
  | 'dependency'
  | 'state-flow'
  | 'performance'
  | 'all';

export interface VisualizationOptions {
  outputDir: string;
  format: VisualizationFormat;
  theme: VisualizationTheme;
  types: VisualizationType[];
  includeDetails: boolean;
  includeLegend: boolean;
  includePerformance: boolean;
}

interface Theme {
  background: string;
  nodeBorder: string;
  lowComplexity: string;
  mediumComplexity: string;
  highComplexity: string;
  veryHighComplexity: string;
  circuit: string;
  ledger: string;
  variable: string;
  witness: string;
  dependency: string;
  read: string;
  write: string;
  constraint: string;
}

export class CircuitVisualizer {
  private options: VisualizationOptions;
  private result: AnalysisResult;
  private contractSource: string;

  constructor(result: AnalysisResult, options: Partial<VisualizationOptions> = {}) {
    this.result = result;
    this.options = {
      outputDir: './circuit-visualizations',
      format: 'png',
      theme: 'default',
      types: ['all'],
      includeDetails: true,
      includeLegend: true,
      includePerformance: false,
      ...options
    };

    // Try to read the source contract for additional context
    this.contractSource = '';
    try {
      if (existsSync(result.contractFile)) {
        this.contractSource = readFileSync(result.contractFile, 'utf8');
      }
    } catch (error) {
      // Source not available, will use compiled data only
    }
  }

  /**
   * Generate all requested visualizations
   */
  async visualize(): Promise<void> {
    console.log(`🎨 Generating circuit visualizations...`);
    console.log(`   Format: ${this.options.format}`);
    console.log(`   Theme: ${this.options.theme}`);
    console.log(``);

    // Create output directory
    if (!existsSync(this.options.outputDir)) {
      mkdirSync(this.options.outputDir, { recursive: true });
    }

    // Check if Graphviz is available
    const hasGraphviz = this.checkGraphviz();
    if (!hasGraphviz && this.options.format !== 'dot') {
      console.warn(`⚠️  Graphviz not found. Only DOT format will be generated.`);
      console.warn(`   Install Graphviz to generate ${this.options.format} files:`);
      console.warn(`   - macOS: brew install graphviz`);
      console.warn(`   - Ubuntu: sudo apt-get install graphviz`);
      console.warn(`   - Windows: https://graphviz.org/download/\n`);
      this.options.format = 'dot';
    }

    // Generate requested visualizations
    const types = this.options.types.includes('all')
      ? ['dependency', 'state-flow', 'performance'] as VisualizationType[]
      : this.options.types;

    for (const type of types) {
      if (type === 'all') continue;
      await this.generateVisualization(type);
    }

    console.log(`\n✅ Visualizations generated in: ${this.options.outputDir}`);
  }

  /**
   * Check if Graphviz is installed
   */
  private checkGraphviz(): boolean {
    try {
      execSync('dot -V', { stdio: 'pipe' });
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Generate a specific visualization type
   */
  private async generateVisualization(type: VisualizationType): Promise<void> {
    let dotContent: string;
    let filename: string;

    switch (type) {
      case 'dependency':
        console.log(`   📊 Generating dependency graph...`);
        dotContent = this.generateDependencyDot();
        filename = 'dependency-graph';
        break;
      case 'state-flow':
        console.log(`   🔄 Generating state flow diagram...`);
        dotContent = this.generateStateFlowDot();
        filename = 'state-flow';
        break;
      case 'performance':
        console.log(`   ⚡ Generating performance heatmap...`);
        dotContent = this.generatePerformanceDot();
        filename = 'performance-heatmap';
        break;
      default:
        return;
    }

    // Write DOT file
    const dotPath = join(this.options.outputDir, `${filename}.dot`);
    writeFileSync(dotPath, dotContent);

    // Convert to requested format if not DOT
    if (this.options.format !== 'dot') {
      const outputPath = join(this.options.outputDir, `${filename}.${this.options.format}`);
      try {
        execSync(`dot -T${this.options.format} "${dotPath}" -o "${outputPath}"`, {
          timeout: 30000,
          stdio: 'pipe'
        });
        console.log(`      ✅ ${filename}.${this.options.format}`);
      } catch (error) {
        console.warn(`      ⚠️  Failed to generate ${this.options.format}: ${(error as Error).message}`);
      }
    } else {
      console.log(`      ✅ ${filename}.dot`);
    }
  }

  /**
   * Get text color for current theme
   */
  private getTextColor(): string {
    return this.options.theme === 'dark' ? '#e0e0e0' : '#000000';
  }

  /**
   * Get theme colors
   */
  private getTheme(): Theme {
    const themes: Record<VisualizationTheme, Theme> = {
      default: {
        background: '#FFFFFF',
        nodeBorder: '#333333',
        lowComplexity: '#90EE90',
        mediumComplexity: '#FFD700',
        highComplexity: '#FFA500',
        veryHighComplexity: '#FF6347',
        circuit: '#B0C4DE',
        ledger: '#87CEEB',
        variable: '#DDA0DD',
        witness: '#F0E68C',
        dependency: '#4169E1',
        read: '#32CD32',
        write: '#FF4500',
        constraint: '#8B4513'
      },
      dark: {
        background: '#1E1E1E',
        nodeBorder: '#CCCCCC',
        lowComplexity: '#2E7D32',
        mediumComplexity: '#F57C00',
        highComplexity: '#D32F2F',
        veryHighComplexity: '#B71C1C',
        circuit: '#546E7A',
        ledger: '#1976D2',
        variable: '#7B1FA2',
        witness: '#F57F17',
        dependency: '#1565C0',
        read: '#388E3C',
        write: '#D32F2F',
        constraint: '#5D4037'
      },
      light: {
        background: '#FAFAFA',
        nodeBorder: '#666666',
        lowComplexity: '#C8E6C9',
        mediumComplexity: '#FFE082',
        highComplexity: '#FFAB91',
        veryHighComplexity: '#EF9A9A',
        circuit: '#CFD8DC',
        ledger: '#BBDEFB',
        variable: '#E1BEE7',
        witness: '#FFF9C4',
        dependency: '#64B5F6',
        read: '#81C784',
        write: '#E57373',
        constraint: '#A1887F'
      },
      colorful: {
        background: '#FFFFFF',
        nodeBorder: '#000000',
        lowComplexity: '#00FF00',
        mediumComplexity: '#FFFF00',
        highComplexity: '#FF8C00',
        veryHighComplexity: '#FF0000',
        circuit: '#00CED1',
        ledger: '#00BFFF',
        variable: '#FF00FF',
        witness: '#FFD700',
        dependency: '#0000FF',
        read: '#00FF00',
        write: '#FF0000',
        constraint: '#8B4513'
      }
    };

    return themes[this.options.theme];
  }

  /**
   * Get complexity color based on constraint count
   */
  private getComplexityColor(constraints: number): string {
    const theme = this.getTheme();
    if (constraints < 1000) return theme.lowComplexity;
    if (constraints < 10000) return theme.mediumComplexity;
    if (constraints < 100000) return theme.highComplexity;
    return theme.veryHighComplexity;
  }

  /**
   * Generate dependency graph DOT
   */
  private generateDependencyDot(): string {
    const theme = this.getTheme();
    const textColor = this.getTextColor();
    let dot = `digraph CircuitDependencies {\n`;
    dot += `  rankdir=TB;\n`;
    dot += `  bgcolor="${theme.background}";\n`;
    dot += `  fontcolor="${textColor}";\n`;
    dot += `  node [shape=box, style=filled, fontname="Arial", fontsize=10, fontcolor="${textColor}"];\n`;
    dot += `  edge [fontname="Arial", fontsize=8, fontcolor="${textColor}"];\n\n`;

    // Add title
    dot += `  label="Circuit Dependency Graph\\n`;
    dot += `Contract: ${basename(this.result.contractFile)}\\n`;
    dot += `Circuits: ${this.result.circuits.length} | `;
    dot += `Total Constraints: ${this.result.totalConstraints.toLocaleString()}";\n`;
    dot += `  labelloc="t";\n`;
    dot += `  fontsize=14;\n\n`;

    // Extract dependencies from source code
    const dependencies = this.extractCircuitDependencies();

    // Add circuits
    for (const circuit of this.result.circuits) {
      const color = this.getComplexityColor(circuit.constraints);
      const label = this.options.includeDetails
        ? `${circuit.name}\\n${circuit.constraints.toLocaleString()} constraints\\nK=${circuit.kValue}`
        : circuit.name;

      dot += `  "${circuit.name}" [label="${label}", fillcolor="${color}", color="${theme.nodeBorder}"];\n`;
    }

    dot += '\n';

    // Add edges for dependencies
    let edgeCount = 0;
    for (const [caller, callees] of Object.entries(dependencies)) {
      for (const callee of callees) {
        // Only add edge if both circuits exist in results
        const callerExists = this.result.circuits.some(c => c.name === caller);
        const calleeExists = this.result.circuits.some(c => c.name === callee);

        if (callerExists && calleeExists) {
          dot += `  "${caller}" -> "${callee}";\n`;
          edgeCount++;
        }
      }
    }

    // If no inter-circuit dependencies found, add a note
    if (edgeCount === 0 && this.result.circuits.length > 1) {
      dot += `\n  note [shape=note, fillcolor="${theme.background}", color="${theme.nodeBorder}", fontcolor="${textColor}",\n`;
      dot += `        label="No inter-circuit dependencies detected.\\nCircuits are independent or call external library functions."];\n`;
    }

    // Add legend
    if (this.options.includeLegend) {
      dot += this.generateDependencyLegend(theme);
    }

    dot += `}\n`;
    return dot;
  }

  /**
   * Generate dependency legend
   */
  private generateDependencyLegend(theme: Theme): string {
    let legend = `\n  subgraph cluster_legend {\n`;
    legend += `    label="Legend";\n`;
    legend += `    style=filled;\n`;
    legend += `    color="${theme.nodeBorder}";\n`;
    legend += `    fillcolor="${theme.background}";\n\n`;

    legend += `    legend_low [label="Low Complexity\\n(<1K constraints)", fillcolor="${theme.lowComplexity}", shape=box];\n`;
    legend += `    legend_med [label="Medium Complexity\\n(1K-10K constraints)", fillcolor="${theme.mediumComplexity}", shape=box];\n`;
    legend += `    legend_high [label="High Complexity\\n(10K-100K constraints)", fillcolor="${theme.highComplexity}", shape=box];\n`;
    legend += `    legend_vhigh [label="Very High Complexity\\n(>100K constraints)", fillcolor="${theme.veryHighComplexity}", shape=box];\n`;

    legend += `  }\n`;
    return legend;
  }

  /**
   * Generate state flow DOT - shows how circuits interact with ledger state
   */
  private generateStateFlowDot(): string {
    const theme = this.getTheme();
    const textColor = this.getTextColor();
    let dot = `digraph StateFlow {\n`;
    dot += `  rankdir=LR;\n`;
    dot += `  bgcolor="${theme.background}";\n`;
    dot += `  fontcolor="${textColor}";\n`;
    dot += `  node [fontname="Arial", fontsize=10, fontcolor="${textColor}"];\n`;
    dot += `  edge [fontname="Arial", fontsize=8, fontcolor="${textColor}"];\n\n`;

    // Add title
    dot += `  label="State Flow Diagram\\n`;
    dot += `Contract: ${basename(this.result.contractFile)}";\n`;
    dot += `  labelloc="t";\n`;
    dot += `  fontsize=14;\n\n`;

    // Extract state variables from source
    const ledgers = this.contractSource ? this.extractLedgers(this.contractSource) : [];
    const witnesses = this.contractSource ? this.extractWitnesses(this.contractSource) : [];

    const hasState = ledgers.length > 0 || witnesses.length > 0;

    if (!hasState) {
      // No state found - add informational note
      dot += `  note [shape=note, fillcolor="${theme.background}", color="${theme.nodeBorder}", fontcolor="${textColor}",\n`;
      dot += `        label="No state variables found.\\nContract may use external state or be stateless."];\n`;

      // Still show circuits
      for (const circuit of this.result.circuits) {
        dot += `  "${circuit.name}" [label="${circuit.name}", fillcolor="${theme.circuit}", shape=box, style=filled, color="${theme.nodeBorder}"];\n`;
      }
    } else {
      // Add public state (ledger) nodes
      if (ledgers.length > 0) {
        dot += `  // Public State (Ledger Variables - on-chain)\n`;
        for (const ledger of ledgers) {
          const escapedType = ledger.type.replace(/"/g, '\\"');
          dot += `  "${ledger.name}" [label="${ledger.name}\\n(${escapedType})\\n[PUBLIC]", fillcolor="${theme.ledger}", shape=cylinder, style=filled, color="${theme.nodeBorder}"];\n`;
        }
      }

      // Add private inputs (witness) nodes
      if (witnesses.length > 0) {
        dot += `\n  // Private Inputs (Witness Variables - off-chain)\n`;
        for (const witness of witnesses) {
          const escapedType = witness.type.replace(/"/g, '\\"');
          dot += `  "${witness.name}" [label="${witness.name}\\n(${escapedType})\\n[PRIVATE]", fillcolor="${theme.witness}", shape=diamond, style=filled, color="${theme.nodeBorder}"];\n`;
        }
      }

      dot += `\n  // Circuits\n`;
      // Add circuit nodes
      for (const circuit of this.result.circuits) {
        dot += `  "${circuit.name}" [label="${circuit.name}", fillcolor="${theme.circuit}", shape=box, style=filled, color="${theme.nodeBorder}"];\n`;
      }

      dot += `\n  // State Interactions\n`;
      // Parse source code for actual read/write operations
      const interactions = this.extractStateInteractions(ledgers);

      let edgeCount = 0;
      for (const [circuitName, ops] of Object.entries(interactions)) {
        for (const op of ops) {
          if (op.type === 'read') {
            dot += `  "${op.ledger}" -> "${circuitName}" [label="read", color="${theme.read}", style=solid];\n`;
            edgeCount++;
          } else {
            dot += `  "${circuitName}" -> "${op.ledger}" [label="${op.operation}", color="${theme.write}", style=solid];\n`;
            edgeCount++;
          }
        }
      }

      if (edgeCount === 0) {
        dot += `  info [shape=note, fillcolor="${theme.background}", color="${theme.nodeBorder}", fontcolor="${textColor}",\n`;
        dot += `        label="No state interactions detected in circuit bodies.\\nMay use external library functions."];\n`;
      }
    }

    dot += `}\n`;
    return dot;
  }

  /**
   * OLD METHOD - Remove after refactoring
   * Generate constraint flow DOT
   */
  private generateConstraintFlowDot_OLD(): string {
    const theme = this.getTheme();
    const textColor = this.getTextColor();
    let dot = `digraph ConstraintFlow {\n`;
    dot += `  rankdir=LR;\n`;
    dot += `  bgcolor="${theme.background}";\n`;
    dot += `  fontcolor="${textColor}";\n`;
    dot += `  node [shape=box, style=rounded, fontname="Arial", fontsize=10, fontcolor="${textColor}"];\n`;
    dot += `  edge [fontname="Arial", fontsize=8, fontcolor="${textColor}"];\n\n`;

    // Add title
    dot += `  label="Constraint Flow Diagram\\n`;
    dot += `Contract: ${basename(this.result.contractFile)}";\n`;
    dot += `  labelloc="t";\n`;
    dot += `  fontsize=14;\n\n`;

    // Add circuits with constraint counts
    for (let i = 0; i < this.result.circuits.length; i++) {
      const circuit = this.result.circuits[i];
      const color = this.getComplexityColor(circuit.constraints);
      const label = `${circuit.name}\\n${circuit.constraints.toLocaleString()} constraints`;

      dot += `  "circuit_${i}" [label="${label}", fillcolor="${color}", color="${theme.nodeBorder}"];\n`;

      // Add flow between circuits (sequential)
      if (i > 0) {
        dot += `  "circuit_${i-1}" -> "circuit_${i}" [color="${theme.constraint}"];\n`;
      }
    }

    dot += `}\n`;
    return dot;
  }

  /**
   * Generate variable map DOT
   */
  private generateVariableMapDot(): string {
    const theme = this.getTheme();
    const textColor = this.getTextColor();
    let dot = `digraph VariableMap {\n`;
    dot += `  rankdir=TB;\n`;
    dot += `  bgcolor="${theme.background}";\n`;
    dot += `  fontcolor="${textColor}";\n`;
    dot += `  node [shape=ellipse, style=filled, fontname="Arial", fontsize=10, fontcolor="${textColor}"];\n`;
    dot += `  edge [fontname="Arial", fontsize=8, fontcolor="${textColor}"];\n\n`;

    // Add title
    dot += `  label="Variable Relationship Map\\n`;
    dot += `Contract: ${basename(this.result.contractFile)}";\n`;
    dot += `  labelloc="t";\n`;
    dot += `  fontsize=14;\n\n`;

    // Parse source code for variable information if available
    if (this.contractSource) {
      const ledgers = this.extractLedgers(this.contractSource);

      for (const ledger of ledgers) {
        dot += `  "${ledger.name}" [label="${ledger.name}\\n(Ledger: ${ledger.type})", fillcolor="${theme.ledger}", color="${theme.nodeBorder}"];\n`;
      }
    }

    // Add circuits as variable sources
    for (const circuit of this.result.circuits) {
      dot += `  "${circuit.name}" [label="${circuit.name}", fillcolor="${theme.variable}", color="${theme.nodeBorder}"];\n`;
    }

    dot += `}\n`;
    return dot;
  }

  /**
   * Generate ledger interaction DOT
   */
  private generateLedgerDot(): string {
    const theme = this.getTheme();
    const textColor = this.getTextColor();
    let dot = `digraph LedgerInteractions {\n`;
    dot += `  rankdir=LR;\n`;
    dot += `  bgcolor="${theme.background}";\n`;
    dot += `  fontcolor="${textColor}";\n`;
    dot += `  node [shape=cylinder, style=filled, fontname="Arial", fontsize=10, fontcolor="${textColor}"];\n`;
    dot += `  edge [fontname="Arial", fontsize=8, fontcolor="${textColor}"];\n\n`;

    // Add title
    dot += `  label="Ledger Interaction Diagram\\n`;
    dot += `Contract: ${basename(this.result.contractFile)}";\n`;
    dot += `  labelloc="t";\n`;
    dot += `  fontsize=14;\n\n`;

    // Extract ledgers from source if available
    if (this.contractSource) {
      const ledgers = this.extractLedgers(this.contractSource);

      for (const ledger of ledgers) {
        dot += `  "${ledger.name}" [label="${ledger.name}\\n(${ledger.type})", fillcolor="${theme.ledger}", color="${theme.nodeBorder}"];\n`;
      }

      // Add circuits that interact with ledgers
      for (const circuit of this.result.circuits) {
        dot += `  "${circuit.name}" [label="${circuit.name}", fillcolor="${theme.variable}", shape=box, color="${theme.nodeBorder}"];\n`;

        // Check for ledger interactions in circuit name (heuristic)
        for (const ledger of ledgers) {
          if (circuit.name.toLowerCase().includes(ledger.name.toLowerCase()) ||
              circuit.name.toLowerCase().includes('read') ||
              circuit.name.toLowerCase().includes('write') ||
              circuit.name.toLowerCase().includes('update')) {
            dot += `  "${circuit.name}" -> "${ledger.name}" [color="${theme.write}", style=solid, label="modifies"];\n`;
          }
        }
      }
    } else {
      // Fallback: just show circuits
      for (const circuit of this.result.circuits) {
        dot += `  "${circuit.name}" [label="${circuit.name}", fillcolor="${theme.variable}", shape=box, color="${theme.nodeBorder}"];\n`;
      }
    }

    dot += `}\n`;
    return dot;
  }

  /**
   * Generate performance heatmap DOT
   */
  private generatePerformanceDot(): string {
    const theme = this.getTheme();
    const textColor = this.getTextColor();
    let dot = `digraph PerformanceHeatmap {\n`;
    dot += `  rankdir=TB;\n`;
    dot += `  bgcolor="${theme.background}";\n`;
    dot += `  fontcolor="${textColor}";\n`;
    dot += `  node [shape=box, style=filled, fontname="Arial", fontsize=10, fontcolor="${textColor}"];\n`;
    dot += `  edge [fontname="Arial", fontsize=8, fontcolor="${textColor}"];\n\n`;

    // Add title
    dot += `  label="Performance Heatmap\\n`;
    dot += `Contract: ${basename(this.result.contractFile)}\\n`;
    dot += `Total Proving Time: ${this.result.circuits.reduce((sum, c) => sum + c.provingTimeEstimate, 0).toFixed(1)}s";\n`;
    dot += `  labelloc="t";\n`;
    dot += `  fontsize=14;\n\n`;

    // Sort circuits by proving time
    const sortedCircuits = [...this.result.circuits].sort((a, b) =>
      b.provingTimeEstimate - a.provingTimeEstimate
    );

    // Add circuits with performance info
    for (const circuit of sortedCircuits) {
      const color = this.getComplexityColor(circuit.constraints);
      const label = this.options.includeDetails
        ? `${circuit.name}\\n${circuit.constraints.toLocaleString()} constraints\\n` +
          `Proving Time: ${circuit.provingTimeEstimate.toFixed(1)}s\\n` +
          `Memory: ${circuit.memoryEstimate.toFixed(0)}MB`
        : `${circuit.name}\\n${circuit.provingTimeEstimate.toFixed(1)}s`;

      dot += `  "${circuit.name}" [label="${label}", fillcolor="${color}", color="${theme.nodeBorder}"];\n`;
    }

    // Add legend
    if (this.options.includeLegend) {
      dot += this.generatePerformanceLegend(theme);
    }

    dot += `}\n`;
    return dot;
  }

  /**
   * Generate performance legend
   */
  private generatePerformanceLegend(theme: Theme): string {
    let legend = `\n  subgraph cluster_legend {\n`;
    legend += `    label="Performance Impact";\n`;
    legend += `    style=filled;\n`;
    legend += `    color="${theme.nodeBorder}";\n`;
    legend += `    fillcolor="${theme.background}";\n\n`;

    legend += `    perf_low [label="Fast\\n(<5s)", fillcolor="${theme.lowComplexity}", shape=box];\n`;
    legend += `    perf_med [label="Moderate\\n(5-30s)", fillcolor="${theme.mediumComplexity}", shape=box];\n`;
    legend += `    perf_high [label="Slow\\n(30-120s)", fillcolor="${theme.highComplexity}", shape=box];\n`;
    legend += `    perf_vhigh [label="Very Slow\\n(>120s)", fillcolor="${theme.veryHighComplexity}", shape=box];\n`;

    legend += `  }\n`;
    return legend;
  }

  /**
   * Extract ledgers (public state) from source code
   */
  private extractLedgers(source: string): Array<{ name: string; type: string }> {
    const ledgers: Array<{ name: string; type: string }> = [];
    // Match: ledger name: Type;
    // Need to handle generics like Maybe<X>, Bytes<32>, etc.
    const ledgerRegex = /^ledger\s+(\w+)\s*:\s*([^;]+);/gm;

    let match;
    while ((match = ledgerRegex.exec(source)) !== null) {
      ledgers.push({
        name: match[1],
        type: match[2].trim()
      });
    }

    return ledgers;
  }

  /**
   * Extract witnesses (private inputs) from source code
   */
  private extractWitnesses(source: string): Array<{ name: string; type: string }> {
    const witnesses: Array<{ name: string; type: string }> = [];
    // Match: witness name(params): ReturnType;
    // Witnesses are functions that provide private inputs
    const witnessRegex = /^witness\s+([\w$]+)\s*\([^)]*\)\s*:\s*([^;]+);/gm;

    let match;
    while ((match = witnessRegex.exec(source)) !== null) {
      witnesses.push({
        name: match[1],
        type: match[2].trim()
      });
    }

    return witnesses;
  }

  /**
   * Extract state interactions from source code
   * Returns map of circuit name -> array of state operations
   */
  private extractStateInteractions(ledgers: Array<{ name: string; type: string }>): Record<string, Array<{ type: 'read' | 'write'; ledger: string; operation: string }>> {
    const interactions: Record<string, Array<{ type: 'read' | 'write'; ledger: string; operation: string }>> = {};

    if (!this.contractSource) {
      return interactions;
    }

    // Find all circuit definitions
    const circuitRegex = /circuit\s+(\w+)\s*\([^)]*\)\s*:\s*[^{]*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}/g;

    let match;
    while ((match = circuitRegex.exec(this.contractSource)) !== null) {
      const circuitName = match[1];
      const circuitBody = match[2];

      const ops: Array<{ type: 'read' | 'write'; ledger: string; operation: string }> = [];

      // Look for read/write operations on each ledger
      for (const ledger of ledgers) {
        // Match: ledgerName.read()
        const readPattern = new RegExp(`\\b${ledger.name}\\.read\\s*\\(`, 'g');
        if (readPattern.test(circuitBody)) {
          ops.push({ type: 'read', ledger: ledger.name, operation: 'read' });
        }

        // Match: ledgerName.write(...)
        const writePattern = new RegExp(`\\b${ledger.name}\\.write\\s*\\(`, 'g');
        if (writePattern.test(circuitBody)) {
          ops.push({ type: 'write', ledger: ledger.name, operation: 'write' });
        }

        // Match: ledgerName.insert(...)
        const insertPattern = new RegExp(`\\b${ledger.name}\\.insert\\s*\\(`, 'g');
        if (insertPattern.test(circuitBody)) {
          ops.push({ type: 'write', ledger: ledger.name, operation: 'insert' });
        }

        // Match: ledgerName.increment(...)
        const incrementPattern = new RegExp(`\\b${ledger.name}\\.increment\\s*\\(`, 'g');
        if (incrementPattern.test(circuitBody)) {
          ops.push({ type: 'write', ledger: ledger.name, operation: 'increment' });
        }

        // Match: ledgerName.checkRoot(...)
        const checkPattern = new RegExp(`\\b${ledger.name}\\.checkRoot\\s*\\(`, 'g');
        if (checkPattern.test(circuitBody)) {
          ops.push({ type: 'read', ledger: ledger.name, operation: 'check' });
        }

        // Match: ledgerName.member(...)
        const memberPattern = new RegExp(`\\b${ledger.name}\\.member\\s*\\(`, 'g');
        if (memberPattern.test(circuitBody)) {
          ops.push({ type: 'read', ledger: ledger.name, operation: 'member' });
        }
      }

      if (ops.length > 0) {
        interactions[circuitName] = ops;
      }
    }

    return interactions;
  }

  /**
   * Extract circuit dependencies from source code
   * Returns a map of circuit name -> array of circuit names it calls
   */
  private extractCircuitDependencies(): Record<string, string[]> {
    const dependencies: Record<string, string[]> = {};

    if (!this.contractSource) {
      return dependencies;
    }

    // Get list of all circuit names
    const circuitNames = this.result.circuits.map(c => c.name);

    // Find all circuit definitions
    const circuitRegex = /circuit\s+(\w+)\s*\([^)]*\)\s*:\s*[^{]*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}/g;

    let match;
    while ((match = circuitRegex.exec(this.contractSource)) !== null) {
      const circuitName = match[1];
      const circuitBody = match[2];

      // Look for calls to other circuits in the body
      const calls: Set<string> = new Set();

      for (const otherCircuit of circuitNames) {
        // Skip self-references
        if (otherCircuit === circuitName) continue;

        // Look for circuit calls: circuitName(...) or PREFIX_circuitName(...)
        const callPattern = new RegExp(`\\b(\\w+_)?${otherCircuit}\\s*\\(`, 'g');

        if (callPattern.test(circuitBody)) {
          calls.add(otherCircuit);
        }
      }

      if (calls.size > 0) {
        dependencies[circuitName] = Array.from(calls);
      }
    }

    return dependencies;
  }

  /**
   * Get legend HTML for dependency graph
   */
  public getDependencyLegendHTML(theme: 'light' | 'dark'): string {
    const isDark = theme === 'dark';
    const colors = {
      low: isDark ? '#2d5a3d' : '#d4edda',
      medium: isDark ? '#7a6b2d' : '#fff3cd',
      high: isDark ? '#7a4d2d' : '#f8d7da',
      veryHigh: isDark ? '#5a2d2d' : '#f5c6cb'
    };

    return `
      <div class="legend">
        <div class="legend-item">
          <span class="legend-color" style="background-color: ${colors.low};"></span>
          <span class="legend-label">Low Complexity (&lt;1K constraints)</span>
        </div>
        <div class="legend-item">
          <span class="legend-color" style="background-color: ${colors.medium};"></span>
          <span class="legend-label">Medium Complexity (1K-10K constraints)</span>
        </div>
        <div class="legend-item">
          <span class="legend-color" style="background-color: ${colors.high};"></span>
          <span class="legend-label">High Complexity (10K-100K constraints)</span>
        </div>
        <div class="legend-item">
          <span class="legend-color" style="background-color: ${colors.veryHigh};"></span>
          <span class="legend-label">Very High Complexity (&gt;100K constraints)</span>
        </div>
      </div>
    `;
  }

  /**
   * Get legend HTML for performance heatmap
   */
  public getPerformanceLegendHTML(theme: 'light' | 'dark'): string {
    const isDark = theme === 'dark';
    const colors = {
      low: isDark ? '#2d5a3d' : '#d4edda',
      medium: isDark ? '#7a6b2d' : '#fff3cd',
      high: isDark ? '#7a4d2d' : '#f8d7da',
      veryHigh: isDark ? '#5a2d2d' : '#f5c6cb'
    };

    return `
      <div class="legend">
        <div class="legend-item">
          <span class="legend-color" style="background-color: ${colors.low};"></span>
          <span class="legend-label">Fast (&lt;5s)</span>
        </div>
        <div class="legend-item">
          <span class="legend-color" style="background-color: ${colors.medium};"></span>
          <span class="legend-label">Moderate (5-30s)</span>
        </div>
        <div class="legend-item">
          <span class="legend-color" style="background-color: ${colors.high};"></span>
          <span class="legend-label">Slow (30-120s)</span>
        </div>
        <div class="legend-item">
          <span class="legend-color" style="background-color: ${colors.veryHigh};"></span>
          <span class="legend-label">Very Slow (&gt;120s)</span>
        </div>
      </div>
    `;
  }
}
