/**
 * API Documentation Generator
 *
 * Generates comprehensive HTML API documentation from circuit signatures and comments
 */

import { readFileSync, existsSync, writeFileSync } from 'fs';
import { basename } from 'path';
import type { AnalysisResult } from './types.js';

interface CircuitDoc {
  name: string;
  signature: string;
  description: string;
  params: Array<{ name: string; type: string; description: string }>;
  returns: { type: string; description: string };
  isExported: boolean;
  complexity?: string;
  examples: string[];
  seeAlso: string[];
}

interface StateVarDoc {
  name: string;
  type: string;
  kind: 'ledger' | 'witness';
  description: string;
}

export class ApiDocGenerator {
  private contractSource: string;
  private contractPath: string;
  private result: AnalysisResult;

  constructor(contractPath: string, result: AnalysisResult) {
    this.contractPath = contractPath;
    this.result = result;

    if (!existsSync(contractPath)) {
      throw new Error(`Contract file not found: ${contractPath}`);
    }

    this.contractSource = readFileSync(contractPath, 'utf8');
  }

  /**
   * Generate API documentation HTML
   */
  public generate(outputPath: string): void {
    const circuits = this.parseCircuitDocs();
    const stateVars = this.parseStateVarDocs();
    const html = this.generateHTML(circuits, stateVars);

    writeFileSync(outputPath, html, 'utf8');
  }

  /**
   * Parse circuit documentation from source code
   */
  private parseCircuitDocs(): CircuitDoc[] {
    const circuits: CircuitDoc[] = [];

    // Match circuit definitions with preceding comments
    const circuitPattern = /((?:\/\*\*[\s\S]*?\*\/\s*)?)(export\s+)?circuit\s+(\w+)\s*\(([^)]*)\)\s*:\s*([^{]+)\s*\{/g;
    let match;

    while ((match = circuitPattern.exec(this.contractSource)) !== null) {
      const commentBlock = match[1];
      const isExported = !!match[2];
      const name = match[3];
      const paramsStr = match[4];
      const returnType = match[5].trim();

      // Extract documentation from comment block
      const doc = this.parseJSDoc(commentBlock);

      // Parse parameters
      const params: Array<{ name: string; type: string; description: string }> = [];
      if (paramsStr.trim()) {
        const paramPairs = paramsStr.split(',');
        for (const pair of paramPairs) {
          const colonIndex = pair.indexOf(':');
          if (colonIndex !== -1) {
            const paramName = pair.substring(0, colonIndex).trim();
            const paramType = pair.substring(colonIndex + 1).trim();
            const paramDoc = doc.params[paramName] || '';

            params.push({
              name: paramName,
              type: paramType,
              description: paramDoc
            });
          }
        }
      }

      // Get complexity rating if available
      const complexity = this.result.complexity?.find(c => c.circuit === name);

      circuits.push({
        name,
        signature: `${isExported ? 'export ' : ''}circuit ${name}(${paramsStr}): ${returnType}`,
        description: doc.description,
        params,
        returns: {
          type: returnType,
          description: doc.returns
        },
        isExported,
        complexity: complexity?.rating,
        examples: doc.examples,
        seeAlso: doc.seeAlso
      });
    }

    return circuits;
  }

  /**
   * Parse state variable documentation
   */
  private parseStateVarDocs(): StateVarDoc[] {
    const stateVars: StateVarDoc[] = [];

    // Parse ledger variables with comments
    const ledgerPattern = /((?:\/\*\*[\s\S]*?\*\/\s*)?|(?:\/\/[^\n]*\n\s*)*)ledger\s+(\w+)\s*:\s*([^;=]+)/g;
    let match;

    while ((match = ledgerPattern.exec(this.contractSource)) !== null) {
      const commentBlock = match[1];
      const name = match[2];
      const type = match[3].trim();
      const doc = this.parseJSDoc(commentBlock);

      stateVars.push({
        name,
        type,
        kind: 'ledger',
        description: doc.description
      });
    }

    // Parse witness variables with comments
    const witnessPattern = /((?:\/\*\*[\s\S]*?\*\/\s*)?|(?:\/\/[^\n]*\n\s*)*)witness\s+(\w+)\s*\([^)]*\)\s*:\s*([^{;]+)/g;
    while ((match = witnessPattern.exec(this.contractSource)) !== null) {
      const commentBlock = match[1];
      const name = match[2];
      const type = match[3].trim();
      const doc = this.parseJSDoc(commentBlock);

      stateVars.push({
        name,
        type,
        kind: 'witness',
        description: doc.description
      });
    }

    return stateVars;
  }

  /**
   * Parse JSDoc-style comments
   */
  private parseJSDoc(commentBlock: string): {
    description: string;
    params: Record<string, string>;
    returns: string;
    examples: string[];
    seeAlso: string[];
  } {
    const result = {
      description: '',
      params: {} as Record<string, string>,
      returns: '',
      examples: [] as string[],
      seeAlso: [] as string[]
    };

    if (!commentBlock) return result;

    // Remove comment markers
    const cleaned = commentBlock
      .replace(/\/\*\*|\*\/|^\s*\*\s?/gm, '')
      .trim();

    const lines = cleaned.split('\n');
    let currentSection = 'description';
    let descriptionLines: string[] = [];
    let currentExample: string[] = [];

    for (const line of lines) {
      const trimmed = line.trim();

      if (trimmed.startsWith('@param')) {
        currentSection = 'param';
        const match = trimmed.match(/@param\s+(\w+)\s+(.*)/);
        if (match) {
          result.params[match[1]] = match[2];
        }
      } else if (trimmed.startsWith('@returns') || trimmed.startsWith('@return')) {
        currentSection = 'returns';
        const match = trimmed.match(/@returns?\s+(.*)/);
        if (match) {
          result.returns = match[1];
        }
      } else if (trimmed.startsWith('@example')) {
        currentSection = 'example';
        if (currentExample.length > 0) {
          result.examples.push(currentExample.join('\n'));
          currentExample = [];
        }
      } else if (trimmed.startsWith('@see')) {
        currentSection = 'seeAlso';
        const match = trimmed.match(/@see\s+(.*)/);
        if (match) {
          result.seeAlso.push(match[1]);
        }
      } else {
        if (currentSection === 'description') {
          descriptionLines.push(trimmed);
        } else if (currentSection === 'example' && trimmed) {
          currentExample.push(trimmed);
        }
      }
    }

    if (currentExample.length > 0) {
      result.examples.push(currentExample.join('\n'));
    }

    result.description = descriptionLines.join(' ').trim();

    return result;
  }

  /**
   * Generate HTML documentation
   */
  private generateHTML(circuits: CircuitDoc[], stateVars: StateVarDoc[]): string {
    const contractName = basename(this.contractPath, '.compact');
    const date = new Date(this.result.timestamp).toLocaleString();

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${contractName} - API Documentation</title>
  <style>
    ${this.getStyles()}
  </style>
</head>
<body>
  <div class="sidebar">
    <div class="logo">📚 API Docs</div>
    <div class="contract-name">${contractName}</div>

    <div class="nav-section">
      <div class="nav-header">State Variables</div>
      ${stateVars.map(v => `<a href="#state-${v.name}" class="nav-link">${v.name}</a>`).join('')}
    </div>

    <div class="nav-section">
      <div class="nav-header">Exported Circuits</div>
      ${circuits.filter(c => c.isExported).map(c => `<a href="#circuit-${c.name}" class="nav-link">${c.name}</a>`).join('')}
    </div>

    ${circuits.filter(c => !c.isExported).length > 0 ? `
    <div class="nav-section">
      <div class="nav-header">Internal Circuits</div>
      ${circuits.filter(c => !c.isExported).map(c => `<a href="#circuit-${c.name}" class="nav-link">${c.name}</a>`).join('')}
    </div>
    ` : ''}
  </div>

  <div class="content">
    <header>
      <h1>${contractName}</h1>
      <p class="subtitle">Contract API Documentation</p>
      <div class="metadata">
        <span>Generated: ${date}</span>
        <span>Compiler: ${this.result.compilerVersion || 'Unknown'}</span>
        <span>${circuits.length} circuits</span>
        <span>${stateVars.length} state variables</span>
      </div>
    </header>

    <section id="overview">
      <h2>Overview</h2>
      <div class="overview-grid">
        <div class="overview-card">
          <div class="overview-label">Total Constraints</div>
          <div class="overview-value">${this.result.totalConstraints.toLocaleString()}</div>
        </div>
        <div class="overview-card">
          <div class="overview-label">Exported Circuits</div>
          <div class="overview-value">${circuits.filter(c => c.isExported).length}</div>
        </div>
        <div class="overview-card">
          <div class="overview-label">Internal Circuits</div>
          <div class="overview-value">${circuits.filter(c => !c.isExported).length}</div>
        </div>
        <div class="overview-card">
          <div class="overview-label">State Variables</div>
          <div class="overview-value">${stateVars.length}</div>
        </div>
      </div>
    </section>

    <section id="state-variables">
      <h2>State Variables</h2>
      ${stateVars.length === 0 ? '<p class="no-content">No state variables defined.</p>' : stateVars.map(v => this.generateStateVarHTML(v)).join('')}
    </section>

    <section id="circuits">
      <h2>Circuits</h2>
      ${circuits.length === 0 ? '<p class="no-content">No circuits defined.</p>' : circuits.map(c => this.generateCircuitHTML(c)).join('')}
    </section>

    <footer>
      <p>Generated by <strong>Compact Circuit Analyzer</strong></p>
      <p>Midnight Network • ${new Date().getFullYear()}</p>
    </footer>
  </div>
</body>
</html>`;
  }

  /**
   * Generate HTML for a state variable
   */
  private generateStateVarHTML(stateVar: StateVarDoc): string {
    return `
    <div class="state-var" id="state-${stateVar.name}">
      <div class="state-var-header">
        <span class="state-var-name">${stateVar.name}</span>
        <span class="state-var-kind ${stateVar.kind}">${stateVar.kind}</span>
      </div>
      <div class="state-var-type"><strong>Type:</strong> <code>${this.escapeHtml(stateVar.type)}</code></div>
      ${stateVar.description ? `<div class="state-var-description">${this.escapeHtml(stateVar.description)}</div>` : ''}
    </div>`;
  }

  /**
   * Generate HTML for a circuit
   */
  private generateCircuitHTML(circuit: CircuitDoc): string {
    return `
    <div class="circuit" id="circuit-${circuit.name}">
      <div class="circuit-header">
        <h3 class="circuit-name">${circuit.name}</h3>
        ${circuit.isExported ? '<span class="badge exported">exported</span>' : '<span class="badge internal">internal</span>'}
        ${circuit.complexity ? `<span class="badge complexity-${circuit.complexity}">${circuit.complexity} complexity</span>` : ''}
      </div>

      <div class="circuit-signature">
        <code>${this.escapeHtml(circuit.signature)}</code>
      </div>

      ${circuit.description ? `
      <div class="circuit-description">
        ${this.escapeHtml(circuit.description)}
      </div>` : ''}

      ${circuit.params.length > 0 ? `
      <div class="circuit-section">
        <h4>Parameters</h4>
        <table class="param-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            ${circuit.params.map(p => `
            <tr>
              <td><code>${this.escapeHtml(p.name)}</code></td>
              <td><code>${this.escapeHtml(p.type)}</code></td>
              <td>${p.description ? this.escapeHtml(p.description) : '<em>No description</em>'}</td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>` : ''}

      <div class="circuit-section">
        <h4>Returns</h4>
        <p><code>${this.escapeHtml(circuit.returns.type)}</code>${circuit.returns.description ? ` - ${this.escapeHtml(circuit.returns.description)}` : ''}</p>
      </div>

      ${circuit.examples.length > 0 ? `
      <div class="circuit-section">
        <h4>Examples</h4>
        ${circuit.examples.map(ex => `<pre class="example"><code>${this.escapeHtml(ex)}</code></pre>`).join('')}
      </div>` : ''}

      ${circuit.seeAlso.length > 0 ? `
      <div class="circuit-section">
        <h4>See Also</h4>
        <ul>
          ${circuit.seeAlso.map(s => `<li>${this.escapeHtml(s)}</li>`).join('')}
        </ul>
      </div>` : ''}
    </div>`;
  }

  /**
   * Escape HTML special characters
   */
  private escapeHtml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /**
   * Get CSS styles
   */
  private getStyles(): string {
    return `
      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
      }

      body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        display: flex;
        min-height: 100vh;
        background: #f5f5f5;
        color: #333;
      }

      .sidebar {
        width: 280px;
        background: #1e1e1e;
        color: #e0e0e0;
        padding: 30px 20px;
        position: fixed;
        height: 100vh;
        overflow-y: auto;
      }

      .logo {
        font-size: 1.5rem;
        font-weight: 700;
        margin-bottom: 10px;
      }

      .contract-name {
        font-size: 1.1rem;
        color: #4169E1;
        margin-bottom: 30px;
        padding-bottom: 20px;
        border-bottom: 1px solid #444;
      }

      .nav-section {
        margin-bottom: 25px;
      }

      .nav-header {
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: #888;
        margin-bottom: 10px;
        font-weight: 600;
      }

      .nav-link {
        display: block;
        padding: 8px 12px;
        color: #b0b0b0;
        text-decoration: none;
        border-radius: 4px;
        transition: all 0.2s;
        font-size: 0.9rem;
      }

      .nav-link:hover {
        background: #2d2d2d;
        color: #fff;
      }

      .content {
        margin-left: 280px;
        flex: 1;
        padding: 40px 60px;
        max-width: 1200px;
      }

      header {
        margin-bottom: 50px;
      }

      h1 {
        font-size: 3rem;
        color: #1e1e1e;
        margin-bottom: 10px;
      }

      .subtitle {
        font-size: 1.2rem;
        color: #666;
        margin-bottom: 20px;
      }

      .metadata {
        display: flex;
        gap: 20px;
        flex-wrap: wrap;
        font-size: 0.9rem;
        color: #888;
      }

      .metadata span {
        padding: 6px 12px;
        background: #fff;
        border-radius: 4px;
        border: 1px solid #ddd;
      }

      h2 {
        font-size: 2rem;
        margin: 50px 0 30px;
        color: #1e1e1e;
        border-bottom: 2px solid #4169E1;
        padding-bottom: 10px;
      }

      h3 {
        font-size: 1.5rem;
        color: #333;
      }

      h4 {
        font-size: 1.1rem;
        margin: 20px 0 10px;
        color: #555;
      }

      .overview-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 20px;
        margin-bottom: 30px;
      }

      .overview-card {
        background: #fff;
        padding: 25px;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      }

      .overview-label {
        font-size: 0.85rem;
        color: #888;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-bottom: 8px;
      }

      .overview-value {
        font-size: 2rem;
        font-weight: 700;
        color: #4169E1;
      }

      .state-var {
        background: #fff;
        border: 1px solid #ddd;
        border-radius: 8px;
        padding: 20px;
        margin-bottom: 20px;
      }

      .state-var-header {
        display: flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 10px;
      }

      .state-var-name {
        font-size: 1.2rem;
        font-weight: 600;
        color: #333;
      }

      .state-var-kind {
        padding: 4px 10px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
      }

      .state-var-kind.ledger {
        background: #1976D2;
        color: white;
      }

      .state-var-kind.witness {
        background: #F57F17;
        color: white;
      }

      .state-var-type {
        margin: 10px 0;
      }

      .state-var-description {
        color: #666;
        margin-top: 10px;
      }

      .circuit {
        background: #fff;
        border: 1px solid #ddd;
        border-radius: 8px;
        padding: 30px;
        margin-bottom: 30px;
      }

      .circuit-header {
        display: flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 20px;
      }

      .circuit-name {
        margin: 0;
      }

      .badge {
        padding: 4px 10px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
      }

      .badge.exported {
        background: #28a745;
        color: white;
      }

      .badge.internal {
        background: #6c757d;
        color: white;
      }

      .badge.complexity-low {
        background: #d4edda;
        color: #155724;
      }

      .badge.complexity-medium {
        background: #fff3cd;
        color: #856404;
      }

      .badge.complexity-high {
        background: #f8d7da;
        color: #721c24;
      }

      .badge.complexity-very-high {
        background: #dc3545;
        color: white;
      }

      .circuit-signature {
        background: #f8f9fa;
        border: 1px solid #ddd;
        border-radius: 4px;
        padding: 15px;
        margin-bottom: 20px;
        overflow-x: auto;
      }

      .circuit-signature code {
        font-family: 'Courier New', monospace;
        font-size: 0.95rem;
        white-space: pre-wrap;
      }

      .circuit-description {
        color: #555;
        line-height: 1.6;
        margin-bottom: 20px;
      }

      .circuit-section {
        margin: 25px 0;
      }

      .param-table {
        width: 100%;
        border-collapse: collapse;
      }

      .param-table th {
        background: #f8f9fa;
        padding: 12px;
        text-align: left;
        font-weight: 600;
        border-bottom: 2px solid #ddd;
      }

      .param-table td {
        padding: 12px;
        border-bottom: 1px solid #ddd;
      }

      code {
        background: #f8f9fa;
        padding: 2px 6px;
        border-radius: 3px;
        font-family: 'Courier New', monospace;
        font-size: 0.9em;
      }

      pre {
        background: #f8f9fa;
        border: 1px solid #ddd;
        border-radius: 4px;
        padding: 15px;
        overflow-x: auto;
        margin: 10px 0;
      }

      pre code {
        background: none;
        padding: 0;
      }

      .example {
        background: #1e1e1e;
        color: #e0e0e0;
      }

      .no-content {
        color: #888;
        font-style: italic;
      }

      footer {
        margin-top: 60px;
        padding-top: 30px;
        border-top: 2px solid #ddd;
        text-align: center;
        color: #888;
      }

      footer p {
        margin: 5px 0;
      }

      @media (max-width: 768px) {
        .sidebar {
          position: static;
          width: 100%;
          height: auto;
        }

        .content {
          margin-left: 0;
          padding: 20px;
        }

        h1 {
          font-size: 2rem;
        }
      }
    `;
  }
}
