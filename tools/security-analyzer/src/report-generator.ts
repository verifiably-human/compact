/**
 * Comprehensive Report Generator
 *
 * Generates a single HTML report combining:
 * - Circuit analysis metrics
 * - Embedded visualizations
 * - Performance insights
 * - Optimization recommendations
 */

import { writeFileSync } from 'fs';
import { join } from 'path';
import type { AnalysisResult } from './types.js';
import type { CircuitVisualizer } from './visualizer.js';

export interface ComprehensiveReportOptions {
  outputFile: string;
  includeVisualizations: boolean;
  visualizationFormat: 'svg' | 'png';
  theme: 'light' | 'dark';
}

export class ComprehensiveReportGenerator {
  private result: AnalysisResult;
  private options: ComprehensiveReportOptions;
  private visualizationPaths: Map<string, string>;
  private visualizer?: CircuitVisualizer;

  constructor(
    result: AnalysisResult,
    options: Partial<ComprehensiveReportOptions> = {},
    visualizationPaths: Map<string, string> = new Map(),
    visualizer?: CircuitVisualizer
  ) {
    this.result = result;
    this.options = {
      outputFile: 'circuit-report.html',
      includeVisualizations: true,
      visualizationFormat: 'svg',
      theme: 'light',
      ...options
    };
    this.visualizationPaths = visualizationPaths;
    this.visualizer = visualizer;
  }

  /**
   * Generate comprehensive HTML report
   */
  generate(): void {
    const html = this.generateHTML();
    writeFileSync(this.options.outputFile, html);
    console.log(`\n✅ Comprehensive report generated: ${this.options.outputFile}`);
  }

  /**
   * Generate HTML content
   */
  private generateHTML(): string {
    const isDark = this.options.theme === 'dark';

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <!--
    CSP — defence-in-depth alongside per-interpolation HTML escaping.
    The report is generated locally from user-supplied .compact source;
    if an escape is missed, this prevents inline-script execution and
    external loads. Inline styles are allowed because the generator
    emits a large stylesheet. img-src includes data:/blob:/file: so
    embedded visualizations (PNG/SVG) load from disk.
  -->
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src 'unsafe-inline'; img-src data: blob: file:; font-src data:;">
  <title>Circuit Analysis Report - ${this.escapeHtml(this.result.contractFile)}</title>
  <style>
    ${this.getStyles(isDark)}
  </style>
</head>
<body>
  <div class="container">
    ${this.generateHeader()}
    ${this.result.baselineApplication ? this.generateBaselineBanner() : ''}
    ${this.result.policyAssessment ? this.generatePolicyAssessment() : ''}
    ${this.result.profile ? this.generateContractProfile() : ''}
    ${this.generateSummary()}
    ${this.result.security ? this.generateSecurityAnalysis() : ''}
    ${this.result.nonceAnalysis ? this.generateNonceHygiene() : ''}
    ${this.result.correlatorAnalysis ? this.generateCorrelators() : ''}
    ${this.generateCircuitDetails()}
    ${this.generatePerformanceInsights()}
    ${this.generateRecommendations()}
    ${this.options.includeVisualizations ? this.generateVisualizationsSection() : ''}
    ${this.generateFooter()}
  </div>
  <!--
    Inline <script> intentionally omitted to keep the CSP at
    script-src 'none'. The previous block provided two cosmetic
    behaviours (table-row highlight on click, Ctrl+P print handler)
    that the browser handles or are non-essential. If future
    interactivity is needed, prefer adding a <script> with a
    sha256 hash listed in the CSP, or move to a sandboxed iframe.
  -->
</body>
</html>`;
  }

  /**
   * Generate CSS styles
   */
  private getStyles(isDark: boolean): string {
    const bg = isDark ? '#1e1e1e' : '#ffffff';
    const fg = isDark ? '#e0e0e0' : '#333333';
    const cardBg = isDark ? '#2d2d2d' : '#f8f9fa';
    const border = isDark ? '#444444' : '#dee2e6';
    const accent = '#4169E1';

    return `
      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
      }

      body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
        line-height: 1.6;
        color: ${fg};
        background: ${bg};
        padding: 20px;
      }

      .container {
        max-width: 1200px;
        margin: 0 auto;
      }

      header {
        text-align: center;
        padding: 40px 0;
        border-bottom: 3px solid ${accent};
        margin-bottom: 40px;
      }

      h1 {
        font-size: 2.5rem;
        margin-bottom: 10px;
        color: ${accent};
      }

      h2 {
        font-size: 1.8rem;
        margin: 40px 0 20px;
        color: ${accent};
        border-bottom: 2px solid ${border};
        padding-bottom: 10px;
      }

      h3 {
        font-size: 1.3rem;
        margin: 30px 0 15px;
        color: ${fg};
      }

      .subtitle {
        font-size: 1.1rem;
        color: ${isDark ? '#b0b0b0' : '#666666'};
      }

      .metadata {
        display: flex;
        justify-content: center;
        gap: 30px;
        margin-top: 20px;
        flex-wrap: wrap;
      }

      .metadata-item {
        display: flex;
        flex-direction: column;
        align-items: center;
      }

      .metadata-label {
        font-size: 0.85rem;
        color: ${isDark ? '#888888' : '#999999'};
        text-transform: uppercase;
        letter-spacing: 1px;
      }

      .metadata-value {
        font-size: 1.2rem;
        font-weight: 600;
        margin-top: 5px;
      }

      .summary-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 20px;
        margin: 30px 0;
      }

      .card {
        background: ${cardBg};
        border: 1px solid ${border};
        border-radius: 8px;
        padding: 25px;
        transition: transform 0.2s, box-shadow 0.2s;
      }

      .card:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px ${isDark ? 'rgba(0,0,0,0.5)' : 'rgba(0,0,0,0.1)'};
      }

      .card-title {
        font-size: 0.9rem;
        color: ${isDark ? '#888888' : '#999999'};
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-bottom: 10px;
      }

      .card-value {
        font-size: 2rem;
        font-weight: 700;
        color: ${accent};
      }

      .card-subtitle {
        font-size: 0.9rem;
        color: ${isDark ? '#b0b0b0' : '#666666'};
        margin-top: 5px;
      }

      table {
        width: 100%;
        border-collapse: collapse;
        margin: 20px 0;
        background: ${cardBg};
      }

      thead {
        background: ${isDark ? '#3d3d3d' : '#e9ecef'};
      }

      th, td {
        padding: 12px 15px;
        text-align: left;
        border-bottom: 1px solid ${border};
      }

      th {
        font-weight: 600;
        text-transform: uppercase;
        font-size: 0.85rem;
        letter-spacing: 1px;
      }

      tr:hover {
        background: ${isDark ? '#3a3a3a' : '#f5f5f5'};
      }

      .complexity-low { color: #28a745; font-weight: 600; }
      .complexity-medium { color: #ffc107; font-weight: 600; }
      .complexity-high { color: #fd7e14; font-weight: 600; }
      .complexity-very-high { color: #dc3545; font-weight: 600; }

      .insights {
        background: ${cardBg};
        border-left: 4px solid ${accent};
        padding: 20px;
        margin: 20px 0;
        border-radius: 4px;
      }

      .insight-item {
        margin: 15px 0;
        padding-left: 25px;
        position: relative;
      }

      .insight-item::before {
        content: "→";
        position: absolute;
        left: 0;
        color: ${accent};
        font-weight: bold;
      }

      .recommendations {
        background: ${isDark ? '#2d4a2d' : '#d4edda'};
        border-left: 4px solid #28a745;
        padding: 20px;
        margin: 20px 0;
        border-radius: 4px;
      }

      .recommendation-item {
        margin: 15px 0;
        padding-left: 25px;
        position: relative;
      }

      .recommendation-item::before {
        content: "✓";
        position: absolute;
        left: 0;
        color: #28a745;
        font-weight: bold;
      }

      .visualization {
        margin: 40px 0;
        text-align: center;
      }

      .visualization img {
        max-width: 100%;
        height: auto;
        border: 1px solid ${border};
        border-radius: 8px;
        box-shadow: 0 2px 8px ${isDark ? 'rgba(0,0,0,0.5)' : 'rgba(0,0,0,0.1)'};
      }

      .visualization-title {
        font-size: 1.2rem;
        font-weight: 600;
        margin-bottom: 15px;
        color: ${fg};
      }

      .visualization-description {
        font-size: 0.95rem;
        color: ${isDark ? '#b0b0b0' : '#666666'};
        margin-bottom: 20px;
        max-width: 600px;
        margin-left: auto;
        margin-right: auto;
      }

      .legend {
        display: flex;
        flex-wrap: wrap;
        justify-content: center;
        gap: 20px;
        margin-top: 15px;
        padding: 15px;
        background: ${isDark ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.03)'};
        border-radius: 8px;
        max-width: 800px;
        margin-left: auto;
        margin-right: auto;
      }

      .legend-item {
        display: flex;
        align-items: center;
        gap: 8px;
      }

      .legend-color {
        width: 20px;
        height: 20px;
        border-radius: 4px;
        border: 1px solid ${isDark ? 'rgba(255,255,255,0.2)' : 'rgba(0,0,0,0.2)'};
      }

      .legend-label {
        font-size: 0.9rem;
        color: ${fg};
      }

      footer {
        text-align: center;
        margin-top: 60px;
        padding-top: 30px;
        border-top: 2px solid ${border};
        color: ${isDark ? '#888888' : '#999999'};
        font-size: 0.9rem;
      }

      .badge {
        display: inline-block;
        padding: 4px 8px;
        border-radius: 4px;
        font-size: 0.85rem;
        font-weight: 600;
      }

      .badge-success { background: #28a745; color: white; }
      .badge-warning { background: #ffc107; color: #333; }
      .badge-danger { background: #dc3545; color: white; }

      /* Security Analysis Styles */
      .security-summary {
        background: ${cardBg};
        border: 1px solid ${border};
        border-radius: 8px;
        padding: 25px;
        margin: 30px 0;
      }

      .risk-score {
        display: inline-block;
        padding: 10px 20px;
        border-radius: 8px;
        font-size: 1.5rem;
        font-weight: 700;
        margin: 15px 0;
      }

      .risk-score.low {
        background: ${isDark ? '#1e4620' : '#d4edda'};
        color: #28a745;
        border: 2px solid #28a745;
      }

      .risk-score.medium {
        background: ${isDark ? '#463a1f' : '#fff3cd'};
        color: #ffc107;
        border: 2px solid #ffc107;
      }

      .risk-score.high {
        background: ${isDark ? '#4a2d1f' : '#ffe5d0'};
        color: #fd7e14;
        border: 2px solid #fd7e14;
      }

      .risk-score.critical {
        background: ${isDark ? '#4a1f1f' : '#f8d7da'};
        color: #dc3545;
        border: 2px solid #dc3545;
      }

      .findings-summary {
        display: flex;
        flex-wrap: wrap;
        gap: 15px;
        margin: 20px 0;
      }

      .finding-count {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 8px 15px;
        border-radius: 6px;
        background: ${isDark ? '#3d3d3d' : '#e9ecef'};
        font-weight: 600;
      }

      .finding-count .count {
        font-size: 1.2rem;
      }

      .finding-count.critical { border-left: 4px solid #dc3545; }
      .finding-count.high { border-left: 4px solid #fd7e14; }
      .finding-count.medium { border-left: 4px solid #ffc107; }
      .finding-count.low { border-left: 4px solid #17a2b8; }
      .finding-count.info { border-left: 4px solid #6c757d; }

      .security-finding {
        background: ${cardBg};
        border: 1px solid ${border};
        border-radius: 8px;
        padding: 20px;
        margin: 20px 0;
        border-left: 4px solid ${border};
      }

      .security-finding.critical { border-left-color: #dc3545; }
      .security-finding.high { border-left-color: #fd7e14; }
      .security-finding.medium { border-left-color: #ffc107; }
      .security-finding.low { border-left-color: #17a2b8; }
      .security-finding.info { border-left-color: #6c757d; }

      .finding-header {
        display: flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 15px;
      }

      .finding-severity {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 4px;
        font-size: 0.8rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
      }

      .finding-severity.critical {
        background: #dc3545;
        color: white;
      }

      .finding-severity.high {
        background: #fd7e14;
        color: white;
      }

      .finding-severity.medium {
        background: #ffc107;
        color: #333;
      }

      .finding-severity.low {
        background: #17a2b8;
        color: white;
      }

      .finding-severity.info {
        background: #6c757d;
        color: white;
      }

      .finding-code {
        background: ${isDark ? '#1a1a1a' : '#f5f5f5'};
        border: 1px solid ${border};
        border-radius: 4px;
        padding: 12px;
        margin: 10px 0;
        font-family: 'Courier New', Courier, monospace;
        font-size: 0.9rem;
        overflow-x: auto;
        white-space: pre-wrap;
        word-break: break-word;
      }

      .no-findings {
        background: ${isDark ? '#1e4620' : '#d4edda'};
        border: 1px solid #28a745;
        border-radius: 8px;
        padding: 30px;
        text-align: center;
        color: #28a745;
        font-size: 1.1rem;
        margin: 20px 0;
      }

      /* Contract Profile section */
      .contract-profile {
        margin: 30px 0;
      }
      .contract-profile h2 { margin-bottom: 16px; }
      .contract-profile h3 { font-size: 1.1rem; margin: 14px 0 8px 0; }
      .profile-postures, .profile-surface, .profile-inventory {
        background: ${isDark ? '#262626' : '#f8f9fa'};
        border-left: 4px solid ${isDark ? '#5d8aa8' : '#2c5aa0'};
        padding: 12px 18px;
        margin-bottom: 12px;
        border-radius: 4px;
      }
      .profile-row {
        padding: 4px 0;
        font-size: 0.95rem;
      }
      .profile-row strong { display: inline-block; min-width: 200px; }
      .profile-badge {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 12px;
        color: white;
        font-size: 0.85rem;
        font-weight: 600;
        margin-right: 6px;
      }
      .profile-flag {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        background: #dc3545;
        color: white;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.5px;
        margin-left: 6px;
      }
      .profile-mute {
        color: ${isDark ? '#888' : '#666'};
        font-size: 0.85rem;
        font-family: ui-monospace, SFMono-Regular, Monaco, monospace;
      }
      .profile-surface-item {
        padding: 3px 0;
        font-size: 0.9rem;
      }
      .profile-surface-label {
        font-weight: 600;
        display: inline-block;
        min-width: 140px;
      }
      .profile-surface-value {
        font-family: ui-monospace, SFMono-Regular, Monaco, monospace;
        color: ${isDark ? '#b0b0b0' : '#444'};
      }

      /* Highlighted summary card (worst-case proving time) */
      .card.highlight {
        border-left: 4px solid ${isDark ? '#5d8aa8' : '#2c5aa0'};
        background: ${isDark ? '#262626' : '#f0f4f8'};
      }
      .card.highlight .card-value {
        color: ${isDark ? '#a0c4ec' : '#2c5aa0'};
      }

      /* Cumulative-metrics details block */
      .cumulative-metrics {
        margin: 20px 0;
        padding: 12px 18px;
        background: ${isDark ? '#1f1f1f' : '#fafafa'};
        border: 1px dashed ${isDark ? '#444' : '#ccc'};
        border-radius: 4px;
        font-size: 0.9rem;
      }
      .cumulative-metrics > summary {
        cursor: pointer;
        font-weight: 600;
        color: ${isDark ? '#aaa' : '#666'};
      }
      .cumulative-metrics p,
      .cumulative-metrics ul {
        margin-top: 10px;
        color: ${isDark ? '#aaa' : '#555'};
      }
      .cumulative-metrics em {
        color: ${isDark ? '#888' : '#777'};
        font-size: 0.85em;
      }

      /* Nonce Hygiene section */
      .nonce-hygiene { margin: 30px 0; }
      .nonce-witness-status {
        padding: 10px 14px;
        background: ${isDark ? '#262626' : '#f0f4f8'};
        border-left: 4px solid ${isDark ? '#5d8aa8' : '#2c5aa0'};
        border-radius: 4px;
        margin-bottom: 14px;
        font-size: 0.9rem;
      }
      .nonce-finding {
        background: ${isDark ? '#2d2d2d' : '#fff'};
        border: 1px solid ${isDark ? '#444' : '#ddd'};
        border-left: 4px solid #f44336;
        padding: 14px 18px;
        margin-bottom: 12px;
        border-radius: 4px;
      }
      .nonce-finding-header {
        display: flex;
        gap: 10px;
        align-items: center;
        flex-wrap: wrap;
        margin-bottom: 8px;
      }
      .nonce-finding-severity {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 4px;
        color: white;
        font-size: 0.8rem;
        font-weight: 700;
        letter-spacing: 0.5px;
      }
      .nonce-finding-kind {
        font-family: ui-monospace, SFMono-Regular, Monaco, monospace;
        color: ${isDark ? '#aaa' : '#666'};
        font-size: 0.9rem;
      }
      .nonce-finding-id {
        margin-left: auto;
        font-size: 0.8rem;
        color: ${isDark ? '#888' : '#999'};
      }
      .nonce-claim {
        font-style: italic;
        color: ${isDark ? '#b0b0b0' : '#555'};
        font-size: 0.9rem;
      }
      .nonce-sites ul { margin: 6px 0; padding-left: 22px; }
      .nonce-sites li { padding: 4px 0; font-size: 0.9rem; }
      .nonce-site-kind {
        display: inline-block;
        padding: 1px 7px;
        background: ${isDark ? '#3d3d3d' : '#e9ecef'};
        border-radius: 3px;
        font-size: 0.75rem;
        font-family: ui-monospace, SFMono-Regular, Monaco, monospace;
        margin-right: 6px;
      }
      .nonce-snippet {
        margin: 6px 0;
        padding: 6px 10px;
        background: ${isDark ? '#1a1a1a' : '#f5f5f5'};
        border-radius: 3px;
        font-size: 0.85rem;
        overflow-x: auto;
        white-space: pre-wrap;
      }
      .nonce-recommendation {
        margin-top: 8px;
        padding: 8px 12px;
        background: ${isDark ? '#1f2d3d' : '#e7f3ff'};
        border-radius: 3px;
        font-size: 0.9rem;
      }

      /* Policy Assessment block */
      .policy-assessment { margin: 24px 0; }
      .policy-banner {
        padding: 18px 24px;
        border-radius: 6px;
        color: white;
        margin-bottom: 16px;
      }
      .policy-banner-label {
        font-size: 1.6rem;
        font-weight: 800;
        letter-spacing: 1px;
        margin-bottom: 4px;
      }
      .policy-banner-sub {
        font-size: 0.9rem;
        opacity: 0.95;
      }
      .policy-reasons {
        list-style: none;
        padding: 0;
        margin: 0;
      }
      .policy-reason {
        background: ${isDark ? '#262626' : '#fff'};
        border: 1px solid ${isDark ? '#444' : '#ddd'};
        padding: 12px 16px;
        margin-bottom: 8px;
        border-radius: 4px;
        font-size: 0.9rem;
      }
      .policy-reason-severity {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 3px;
        color: white;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.5px;
        margin-right: 8px;
      }
      .policy-reason-rule {
        font-family: ui-monospace, SFMono-Regular, Monaco, monospace;
        color: ${isDark ? '#888' : '#777'};
        font-size: 0.85rem;
        margin-right: 8px;
      }
      .policy-no-reasons {
        padding: 12px 16px;
        background: ${isDark ? '#1f3d1f' : '#d4edda'};
        border-radius: 4px;
        color: ${isDark ? '#a0d4a0' : '#155724'};
      }

      /* Correlators section */
      .correlators { margin: 30px 0; }
      .correlator-finding {
        background: ${isDark ? '#2d2d2d' : '#fff'};
        border: 1px solid ${isDark ? '#444' : '#ddd'};
        border-left: 4px solid #f44336;
        padding: 14px 18px;
        margin-bottom: 12px;
        border-radius: 4px;
      }
      .correlator-header {
        display: flex;
        gap: 10px;
        align-items: center;
        margin-bottom: 8px;
      }
      .correlator-severity {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 4px;
        color: white;
        font-size: 0.8rem;
        font-weight: 700;
        letter-spacing: 0.5px;
      }
      .correlator-id {
        margin-left: auto;
        font-size: 0.8rem;
        color: ${isDark ? '#888' : '#999'};
      }
      .correlator-summary {
        font-style: italic;
        color: ${isDark ? '#b0b0b0' : '#555'};
        font-size: 0.9rem;
      }
      .correlator-intent {
        background: ${isDark ? '#1f3d1f' : '#d4edda'};
        padding: 6px 10px;
        border-radius: 3px;
        font-size: 0.85rem;
        margin: 8px 0;
      }
      .correlator-sites ul { margin: 6px 0; padding-left: 22px; }
      .correlator-sites li { padding: 4px 0; font-size: 0.9rem; }
      .correlator-exposure {
        padding: 8px 12px;
        background: ${isDark ? '#262626' : '#f8f9fa'};
        border-radius: 3px;
        font-size: 0.85rem;
        margin: 8px 0;
      }
      .correlator-recommendation {
        margin-top: 8px;
        padding: 8px 12px;
        background: ${isDark ? '#1f2d3d' : '#e7f3ff'};
        border-radius: 3px;
        font-size: 0.9rem;
      }

      @media print {
        body { background: white; color: black; }
        .card { page-break-inside: avoid; }
        .visualization { page-break-inside: avoid; }
      }

      @media (max-width: 768px) {
        .metadata { flex-direction: column; gap: 15px; }
        .summary-grid { grid-template-columns: 1fr; }
        h1 { font-size: 2rem; }
        h2 { font-size: 1.5rem; }
      }
    `;
  }

  /**
   * Generate header section
   */
  private generateHeader(): string {
    const date = new Date(this.result.timestamp).toLocaleString();

    return `
    <header>
      <h1>🎨 Circuit Analysis Report</h1>
      <p class="subtitle">${this.escapeHtml(this.result.contractFile)}</p>
      <div class="metadata">
        <div class="metadata-item">
          <span class="metadata-label">Generated</span>
          <span class="metadata-value">${date}</span>
        </div>
        <div class="metadata-item">
          <span class="metadata-label">Compiler Version</span>
          <span class="metadata-value">${this.escapeHtml(this.result.compilerVersion || 'Unknown')}</span>
        </div>
        <div class="metadata-item">
          <span class="metadata-label">Compilation Time</span>
          <span class="metadata-value">${(this.result.compilationTime / 1000).toFixed(2)}s</span>
        </div>
      </div>
    </header>
    `;
  }

  /**
   * One-row banner summarising the baseline outcome. Rendered when
   * `result.baselineApplication` is set (i.e. a baseline file or inline
   * acks were honoured). Acked findings appear in their own collapsible
   * list so reviewers can see what was suppressed.
   */
  private generateBaselineBanner(): string {
    const ba = this.result.baselineApplication;
    if (!ba) return '';
    const acked = ba.acksApplied;
    const netNew = ba.netNewFindings;
    const expired = ba.acksExpired.length;
    const unmatched = ba.acksUnmatched.length;
    const escape = (s: string) => s.replace(/[&<>"']/g, c => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] ?? c
    ));
    const sec = ba.suppressedSecurity;
    const non = ba.suppressedNonce;
    const cor = ba.suppressedCorrelator;
    const totalSuppressed = sec.length + non.length + cor.length;
    const suppressedRows = [
      ...sec.map(f => ({
        id: f.id ?? '(no id)',
        kind: 'security',
        title: f.title,
        ack: f.ack,
      })),
      ...non.map(f => ({
        id: f.id ?? '(no id)',
        kind: 'nonce',
        title: `${f.kind}: ${f.witnessFunction ?? f.ledgerField ?? '?'}`,
        ack: (f as { ack?: { reason: string; by: string; source: string; severityEscalatedSinceAck?: boolean } }).ack,
      })),
      ...cor.map(f => ({
        id: f.id ?? '(no id)',
        kind: 'correlator',
        title: f.linkabilitySummary,
        ack: (f as { ack?: { reason: string; by: string; source: string; severityEscalatedSinceAck?: boolean } }).ack,
      })),
    ];
    const rowsHtml = suppressedRows.map(r => `
      <tr>
        <td><code>${escape(r.id)}</code></td>
        <td>${escape(r.kind)}</td>
        <td>${escape(r.title.slice(0, 80))}</td>
        <td>${escape(r.ack?.by ?? '')} ${r.ack?.source === 'inline-annotation' ? '<small>(inline)</small>' : ''}</td>
        <td>${escape(r.ack?.reason ?? '')}</td>
        <td>${r.ack?.severityEscalatedSinceAck ? '<strong style="color:#b91c1c">↑ escalated</strong>' : ''}</td>
      </tr>`).join('');
    return `
    <section class="baseline-banner">
      <h2>Baseline applied</h2>
      <p>
        <strong>${acked}</strong> acked,
        <strong>${netNew}</strong> net-new high/critical
        ${expired ? `, <strong>${expired}</strong> expired` : ''}
        ${unmatched ? `, <strong>${unmatched}</strong> unmatched (consider removing from baseline)` : ''}
      </p>
      ${totalSuppressed > 0 ? `
      <details>
        <summary>${totalSuppressed} suppressed finding${totalSuppressed === 1 ? '' : 's'}</summary>
        <table class="baseline-suppressed">
          <thead><tr><th>ID</th><th>Kind</th><th>Title</th><th>Ack by</th><th>Reason</th><th>Severity</th></tr></thead>
          <tbody>${rowsHtml}</tbody>
        </table>
      </details>` : ''}
    </section>`;
  }

  /**
   * Generate the Policy Assessment block. Sits at the very top of
   * the report and gives a reviewer / CI gate the deploy
   * recommendation in one glance, followed by the rules that fired
   * to produce it.
   */
  private generatePolicyAssessment(): string {
    const pa = this.result.policyAssessment;
    if (!pa) return '';

    const recommendationColor: Record<string, string> = {
      block: '#b71c1c',
      warn: '#fd7e14',
      ok: '#28a745',
    };
    const recommendationLabel: Record<string, string> = {
      block: '⛔ BLOCK',
      warn: '⚠️ WARN',
      ok: '✅ OK',
    };
    const color = recommendationColor[pa.deployRecommendation] ?? '#6c757d';
    const label = recommendationLabel[pa.deployRecommendation] ?? pa.deployRecommendation.toUpperCase();

    const reasonsHTML = pa.reasons.length
      ? `<ul class="policy-reasons">${
          pa.reasons.map(r => `
            <li class="policy-reason policy-reason-${this.escapeHtml(r.severity)}">
              <span class="policy-reason-severity" style="background-color: ${recommendationColor[r.severity] ?? '#6c757d'}">${this.escapeHtml(r.severity.toUpperCase())}</span>
              <code class="policy-reason-rule">${this.escapeHtml(r.rule)}</code>
              ${this.escapeHtml(r.message)}
            </li>`).join('')
        }</ul>`
      : '<p class="policy-no-reasons">No policy rules triggered. The contract\'s profile + findings combination is clean against the default ruleset.</p>';

    return `
    <section class="policy-assessment">
      <h2>🚦 Deploy Policy Assessment</h2>
      <div class="policy-banner" style="background-color: ${color}">
        <div class="policy-banner-label">${label}</div>
        <div class="policy-banner-sub">Recommendation derived from contract profile + findings via explicit rules. Each rule that fired contributes one reason below.</div>
      </div>
      ${reasonsHTML}
    </section>`;
  }

  /**
   * Generate Contract Profile section. Sets the lens — value posture,
   * privacy posture, authority model, contract class — at the top of
   * the report so a reviewer triages findings against the right
   * threat model.
   */
  private generateContractProfile(): string {
    const profile = this.result.profile;
    const inventory = this.result.valueInventory;
    if (!profile) return '';

    const postureBadgeColor: Record<string, string> = {
      // value
      none: '#6c757d',
      receives: '#17a2b8',
      holds: '#ffc107',
      mints: '#fd7e14',
      bridges: '#dc3545',
      // privacy
      open: '#6c757d',
      selective: '#ffc107',
      'strong-with-disclosures': '#17a2b8',
      strong: '#28a745',
      // authority
      permissionless: '#dc3545',
      'single-owner': '#fd7e14',
      'multi-key': '#ffc107',
      'membership-proof': '#17a2b8',
      unclear: '#6c757d',
    };
    const badge = (text: string, key: string): string => {
      const color = postureBadgeColor[key] ?? '#6c757d';
      return `<span class="profile-badge" style="background-color: ${color}">${this.escapeHtml(text)}</span>`;
    };

    const surfaceItem = (label: string, items: string[]): string => {
      if (items.length === 0) return '';
      return `
        <div class="profile-surface-item">
          <span class="profile-surface-label">${this.escapeHtml(label)}:</span>
          <span class="profile-surface-value">${this.escapeHtml(items.join(', '))}</span>
        </div>`;
    };

    let inventoryHTML = '';
    if (inventory) {
      const v = inventory.valueAtRiskSummary;
      const flags: string[] = [];
      if (v.isUnboundedMint) flags.push('UNBOUNDED-MINT');
      if (v.isValueHolding) flags.push('value-holding');
      inventoryHTML = `
        <div class="profile-inventory">
          <h3>Value Inventory</h3>
          <div class="profile-row"><strong>Estimated class:</strong>
            ${badge(v.estimatedClass, 'unclear')}
            ${flags.length ? flags.map(f => `<span class="profile-flag">${this.escapeHtml(f)}</span>`).join(' ') : ''}
          </div>
          <div class="profile-row"><strong>Mint operations:</strong> ${inventory.mintOperations.length}
            ${inventory.mintOperations.length ? `<span class="profile-mute">(${this.escapeHtml(inventory.mintOperations.map(m => `${m.circuit}:${m.primitive}[auth=${m.authorizedBy}]`).join(', '))})</span>` : ''}
          </div>
          <div class="profile-row"><strong>Send operations:</strong> ${inventory.sendOperations.length}</div>
          <div class="profile-row"><strong>Receive operations:</strong> ${inventory.receiveOperations.length}</div>
          <div class="profile-row"><strong>Balance fields:</strong> ${inventory.balanceFields.length}
            ${inventory.balanceFields.length ? `<span class="profile-mute">(${this.escapeHtml(inventory.balanceFields.map(b => `${b.field}${b.overflowAssertionPresent ? '' : ' [no overflow assert]'}`).join(', '))})</span>` : ''}
          </div>
          <div class="profile-row"><strong>Commitment+Nullifier pairs:</strong> ${inventory.commitmentNullifierPairs.length}</div>
          <div class="profile-row"><strong>Max-supply constraints:</strong> ${inventory.maxSupplyConstraints.length}</div>
          <div class="profile-row"><strong>Off-chain custody hints:</strong>
            ${inventory.offChainCustodySignals.length
              ? `<span class="profile-mute">${this.escapeHtml(inventory.offChainCustodySignals.join(', '))}</span>`
              : 'none'}
          </div>
        </div>`;
    }

    return `
    <section class="contract-profile">
      <h2>🧭 Contract Profile</h2>
      <div class="profile-postures">
        <div class="profile-row"><strong>Value posture:</strong> ${badge(profile.valuePosture, profile.valuePosture)}</div>
        <div class="profile-row"><strong>Privacy posture:</strong> ${badge(profile.privacyPosture, profile.privacyPosture)}</div>
        <div class="profile-row"><strong>Authority model:</strong> ${badge(profile.authorityModel, profile.authorityModel)}</div>
        <div class="profile-row"><strong>Circuits:</strong>
          ${profile.exportedCircuitCount}/${profile.circuitCount} exported,
          ${profile.witnessFunctionCount} witness function(s)
        </div>
      </div>
      <div class="profile-surface">
        <h3>Ledger Surface (${profile.ledgerSurface.fieldsTotal} field${profile.ledgerSurface.fieldsTotal === 1 ? '' : 's'},
          ${profile.ledgerSurface.fieldsSealed} sealed)</h3>
        ${surfaceItem('Balance-like', profile.ledgerSurface.balanceLike)}
        ${surfaceItem('Commitment-like', profile.ledgerSurface.commitmentLike)}
        ${surfaceItem('Nullifier-like', profile.ledgerSurface.nullifierLike)}
        ${surfaceItem('Counter-like', profile.ledgerSurface.counterLike)}
        ${surfaceItem('Key-like', profile.ledgerSurface.keyLike)}
      </div>
      ${inventoryHTML}
    </section>
    `;
  }

  /**
   * Generate Nonce Hygiene section.
   *
   * Distinct from generic security findings: nonces are the underlying
   * mechanism privacy claims rest on, and the analysis combines source
   * (Counter increments) with witness-file inspection. A reviewer
   * triages this section separately from the heuristic security
   * findings above it.
   */
  private generateNonceHygiene(): string {
    const na = this.result.nonceAnalysis;
    if (!na) return '';

    const severityRank: Record<string, number> = {
      critical: 0, high: 1, medium: 2, low: 3, info: 4,
    };
    const severityColor: Record<string, string> = {
      critical: '#b71c1c',
      high: '#f44336',
      medium: '#ff9800',
      low: '#ffeb3b',
      info: '#2196f3',
    };

    const sortedFindings = [...na.findings].sort((a, b) =>
      (severityRank[a.severity] ?? 99) - (severityRank[b.severity] ?? 99));

    const witnessStatus = na.witnessFile
      ? `Witness file: <code>${this.escapeHtml(na.witnessFile)}</code>`
      : na.witnessFileSkipped
        ? `⚠️ Witness file not found — constant-return-witness check was skipped. Pass <code>--witness-file &lt;path&gt;</code> to enable.`
        : `Witness file not loaded.`;

    let findingsHTML = '';
    if (sortedFindings.length === 0) {
      findingsHTML = '<p class="no-findings">✅ No nonce hygiene issues detected by this analyzer.</p>';
    } else {
      for (const f of sortedFindings) {
        const color = severityColor[f.severity] ?? '#6c757d';
        const sitesHTML = f.sites.map(s => `
          <li>
            <span class="nonce-site-kind">${this.escapeHtml(s.kind)}</span>
            <code>${this.escapeHtml(s.file)}${s.line ? ':' + s.line : ''}</code>
            ${s.circuit ? `(circuit <code>${this.escapeHtml(s.circuit)}</code>)` : ''}
            ${s.snippet ? `<pre class="nonce-snippet">${this.escapeHtml(s.snippet)}</pre>` : ''}
          </li>`).join('');
        const subject = f.witnessFunction
          ? `witness <code>${this.escapeHtml(f.witnessFunction)}</code>`
          : f.ledgerField
            ? `ledger field <code>${this.escapeHtml(f.ledgerField)}</code>`
            : '';
        findingsHTML += `
        <div class="nonce-finding">
          <div class="nonce-finding-header">
            <span class="nonce-finding-severity" style="background-color: ${color}">${this.escapeHtml(f.severity.toUpperCase())}</span>
            <span class="nonce-finding-kind">${this.escapeHtml(f.kind)}</span>
            <span class="nonce-finding-id">id: <code>${this.escapeHtml(f.id)}</code></span>
          </div>
          <p>${subject}</p>
          ${f.evidence?.claimFromSource ? `<p class="nonce-claim">${this.escapeHtml(f.evidence.claimFromSource)}</p>` : ''}
          <div class="nonce-sites">
            <strong>Sites:</strong>
            <ul>${sitesHTML}</ul>
          </div>
          <div class="nonce-recommendation">
            <strong>Recommendation:</strong> ${this.escapeHtml(f.recommendation)}
          </div>
        </div>`;
      }
    }

    return `
    <section class="nonce-hygiene">
      <h2>🎲 Nonce Hygiene</h2>
      <p class="nonce-witness-status">${witnessStatus}</p>
      ${findingsHTML}
    </section>`;
  }

  /**
   * Generate Correlators section (phase 3).
   *
   * Surfaces cross-circuit linkability candidates derived from the
   * compiler's witness disclosure records. Each finding lists the
   * witness origin and the disclose sites that share it.
   * Acknowledged findings (via `// @disclose-intent: <tag>`) appear
   * at info severity with the tag and reason inline.
   */
  private generateCorrelators(): string {
    const ca = this.result.correlatorAnalysis;
    if (!ca) return '';

    const severityRank: Record<string, number> = {
      critical: 0, high: 1, medium: 2, low: 3, info: 4,
    };
    const severityColor: Record<string, string> = {
      critical: '#b71c1c',
      high: '#f44336',
      medium: '#ff9800',
      low: '#ffeb3b',
      info: '#2196f3',
    };

    const sorted = [...ca.findings].sort((a, b) =>
      (severityRank[a.severity] ?? 99) - (severityRank[b.severity] ?? 99));

    let findingsHTML = '';
    if (sorted.length === 0) {
      findingsHTML = '<p class="no-findings">✅ No cross-circuit correlators detected.</p>';
    } else {
      for (const f of sorted) {
        const color = severityColor[f.severity] ?? '#6c757d';
        const sitesHTML = f.linkedDisclosureSites.map(s => `
          <li>
            circuit <code>${this.escapeHtml(s.circuit)}</code> at
            <code>${this.escapeHtml(s.location.file)}${s.location.line ? ':' + s.location.line : ''}</code>
            — final exposure: <em>${this.escapeHtml(s.finalExposure)}</em>
          </li>`).join('');
        const intent = f.intentCheck.annotationPresent
          ? `<div class="correlator-intent">✓ Acknowledged via <code>@disclose-intent: ${this.escapeHtml(f.intentCheck.annotationTag ?? '')}</code>${f.intentCheck.annotationReason ? `: ${this.escapeHtml(f.intentCheck.annotationReason)}` : ''}</div>`
          : '';
        const originDesc = f.witnessOrigin.kind === 'witness-return-value'
          ? `witness <code>${this.escapeHtml(f.witnessOrigin.function ?? '?')}</code>`
          : f.witnessOrigin.kind === 'constructor-argument'
            ? `constructor argument <code>${this.escapeHtml(f.witnessOrigin.argument ?? '?')}</code>`
            : `argument <code>${this.escapeHtml(f.witnessOrigin.argument ?? '?')}</code> of circuit <code>${this.escapeHtml(f.witnessOrigin.function ?? '?')}</code>`;
        findingsHTML += `
        <div class="correlator-finding">
          <div class="correlator-header">
            <span class="correlator-severity" style="background-color: ${color}">${this.escapeHtml(f.severity.toUpperCase())}</span>
            <span class="correlator-id">id: <code>${this.escapeHtml(f.id)}</code></span>
          </div>
          <p>Origin: ${originDesc}</p>
          <p class="correlator-summary">${this.escapeHtml(f.linkabilitySummary)}</p>
          ${intent}
          <div class="correlator-sites">
            <strong>Linked disclosure sites:</strong>
            <ul>${sitesHTML}</ul>
          </div>
          <div class="correlator-exposure">
            <strong>Exposure structure:</strong>
            same final exposure: ${f.exposureStructure.sameFinalExposure ? 'yes' : 'no'};
            blinder present: ${f.exposureStructure.blinderPresent ? 'yes' : 'no'};
            stable identifier present: ${f.exposureStructure.stableIdentifierPresent ? 'yes' : 'no'}.
          </div>
          <div class="correlator-recommendation">
            <strong>Recommendation:</strong> ${this.escapeHtml(f.recommendation)}
          </div>
        </div>`;
      }
    }

    return `
    <section class="correlators">
      <h2>🔗 Correlators (cross-circuit linkability)</h2>
      ${findingsHTML}
    </section>`;
  }

  /**
   * Generate summary section
   */
  private generateSummary(): string {
    // Proving-time metrics. The previous "Total proving time" was a
    // raw sum of every circuit's estimate, which only makes sense if
    // every circuit were proved once back-to-back — not a real
    // workload. Real users invoke ONE circuit per transaction. The
    // top-line metric is now the worst-case single-call proving time
    // (max), with the median alongside for typical-case framing. The
    // legacy sum is preserved lower as "if every circuit were proved
    // once," explicitly labelled as not-a-real-workload.
    const times = this.result.circuits.map(c => c.provingTimeEstimate);
    const memories = this.result.circuits.map(c => c.memoryEstimate);
    const sortedTimes = [...times].sort((a, b) => a - b);
    const worstCaseTime = times.length ? Math.max(...times) : 0;
    const medianTime = sortedTimes.length
      ? sortedTimes[Math.floor(sortedTimes.length / 2)]
      : 0;
    const slowestCircuit = this.result.circuits.find(c => c.provingTimeEstimate === worstCaseTime);
    const cumulativeTime = times.reduce((a, b) => a + b, 0);

    const peakMemory = memories.length ? Math.max(...memories) : 0;
    const peakMemCircuit = this.result.circuits.find(c => c.memoryEstimate === peakMemory);
    const cumulativeMemory = memories.reduce((a, b) => a + b, 0);

    const avgKValue = this.result.circuits.length > 0
      ? (this.result.circuits.reduce((sum, c) => sum + c.kValue, 0) / this.result.circuits.length).toFixed(1)
      : '0';

    return `
    <section>
      <h2>📊 Summary</h2>
      <div class="summary-grid">
        <div class="card">
          <div class="card-title">Total Circuits</div>
          <div class="card-value">${this.result.circuits.length}</div>
          <div class="card-subtitle">Exported circuits</div>
        </div>
        <div class="card">
          <div class="card-title">Total Constraints</div>
          <div class="card-value">${this.result.totalConstraints.toLocaleString()}</div>
          <div class="card-subtitle">Sum across circuits (not per-tx)</div>
        </div>
        <div class="card highlight">
          <div class="card-title">Worst-case Proving Time</div>
          <div class="card-value">${worstCaseTime.toFixed(1)}s</div>
          <div class="card-subtitle">Slowest single call${peakMemCircuit ? '' : ''}${slowestCircuit ? ` (${this.escapeHtml(slowestCircuit.name)})` : ''}</div>
        </div>
        <div class="card">
          <div class="card-title">Median Proving Time</div>
          <div class="card-value">${medianTime.toFixed(1)}s</div>
          <div class="card-subtitle">Typical single call</div>
        </div>
        <div class="card">
          <div class="card-title">Peak Memory</div>
          <div class="card-value">${peakMemory.toFixed(0)} MB</div>
          <div class="card-subtitle">Slowest single call${peakMemCircuit ? ` (${this.escapeHtml(peakMemCircuit.name)})` : ''}</div>
        </div>
        <div class="card">
          <div class="card-title">Average K-Value</div>
          <div class="card-value">${avgKValue}</div>
          <div class="card-subtitle">Plonk domain size</div>
        </div>
      </div>
      <details class="cumulative-metrics">
        <summary>Cumulative metrics (not a real workload)</summary>
        <p>The numbers below assume every circuit is proved once in sequence on a single machine.
        Real users invoke one circuit per transaction; these are useful only for full-test-suite
        timing budgets, deploy-time stress estimation, or batch-proving infrastructure planning.</p>
        <ul>
          <li><strong>If every circuit were proved once (sequential):</strong> ${cumulativeTime.toFixed(1)}s</li>
          <li><strong>Sum of per-circuit memory estimates:</strong> ${cumulativeMemory.toFixed(0)} MB
            <em>(parallel proof workers would each need their own peak memory; this number is not the
            host's required RAM for normal operation)</em></li>
        </ul>
      </details>
    </section>
    `;
  }

  /**
   * Generate security analysis section
   */
  private generateSecurityAnalysis(): string {
    if (!this.result.security) {
      return '';
    }

    const sec = this.result.security;
    const riskLevel = sec.riskScore < 20 ? 'low' : sec.riskScore < 50 ? 'medium' : sec.riskScore < 75 ? 'high' : 'critical';
    const riskColor = riskLevel === 'low' ? '#4caf50' : riskLevel === 'medium' ? '#ff9800' : riskLevel === 'high' ? '#f44336' : '#b71c1c';

    // Order findings by severity (critical → info), then by title for
    // stable rendering across runs. A reviewer scanning the report
    // top-to-bottom should hit the highest-severity items first.
    const severityRank: Record<string, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      info: 4,
    };
    const sortedFindings = [...sec.findings].sort((a, b) => {
      const sa = severityRank[a.severity] ?? 99;
      const sb = severityRank[b.severity] ?? 99;
      if (sa !== sb) return sa - sb;
      return a.title.localeCompare(b.title);
    });

    // Findings carry data parsed from user-supplied .compact source
    // (circuit names, witness names, etc.). The report HTML is opened
    // in a browser — escape every dynamic interpolation. Severity is
    // restricted to a known enum before reflection into class names
    // and color/icon lookups.
    const ALLOWED_SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);
    const severityColors: Record<string, string> = {
      critical: '#b71c1c',
      high: '#f44336',
      medium: '#ff9800',
      low: '#ffeb3b',
      info: '#2196f3',
    };
    const severityIcons: Record<string, string> = {
      critical: '🔴',
      high: '🟠',
      medium: '🟡',
      low: '🟢',
      info: 'ℹ️',
    };

    let findingsHTML = '';
    for (const finding of sortedFindings) {
      const rawSev = String(finding.severity).toLowerCase();
      const severity = ALLOWED_SEVERITIES.has(rawSev) ? rawSev : 'info';
      const severityColor = severityColors[severity];
      const severityIcon = severityIcons[severity];

      findingsHTML += `
        <div class="security-finding severity-${severity}">
          <div class="finding-header">
            <span class="finding-severity" style="background-color: ${severityColor}">${severityIcon} ${severity.toUpperCase()}</span>
            <span class="finding-type">${this.escapeHtml(finding.type)}</span>
          </div>
          <h4 class="finding-title">${this.escapeHtml(finding.title)}</h4>
          <p class="finding-description">${this.escapeHtml(finding.description)}</p>
          ${finding.location ? `
            <div class="finding-location">
              <strong>Location:</strong> Circuit "${this.escapeHtml(finding.location.circuit)}"
              ${finding.location.code ? `<pre class="finding-code">${this.escapeHtml(finding.location.code)}</pre>` : ''}
            </div>
          ` : ''}
          <div class="finding-impact">
            <strong>Impact:</strong> ${this.escapeHtml(finding.impact)}
          </div>
          <div class="finding-recommendation">
            <strong>Recommendation:</strong> ${this.escapeHtml(finding.recommendation)}
          </div>
        </div>
      `;
    }

    return `
    <section>
      <h2>🔒 Security Analysis</h2>
      <div class="security-summary">
        <div class="risk-score" style="border-color: ${riskColor}">
          <div class="risk-label">Overall Risk Score</div>
          <div class="risk-value" style="color: ${riskColor}">${sec.riskScore}/100</div>
          <div class="risk-level">${riskLevel.toUpperCase()}</div>
        </div>
        <div class="findings-summary">
          <div class="finding-count critical">
            <span class="count">${sec.summary.critical}</span>
            <span class="label">Critical</span>
          </div>
          <div class="finding-count high">
            <span class="count">${sec.summary.high}</span>
            <span class="label">High</span>
          </div>
          <div class="finding-count medium">
            <span class="count">${sec.summary.medium}</span>
            <span class="label">Medium</span>
          </div>
          <div class="finding-count low">
            <span class="count">${sec.summary.low}</span>
            <span class="label">Low</span>
          </div>
          <div class="finding-count info">
            <span class="count">${sec.summary.info}</span>
            <span class="label">Info</span>
          </div>
        </div>
      </div>

      ${sec.findings.length > 0 ? `
        <h3>Security Findings</h3>
        <div class="security-findings">
          ${findingsHTML}
        </div>
      ` : '<p class="no-findings">✅ No security issues detected! This contract follows security best practices.</p>'}
    </section>
    `;
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
   * Generate circuit details section
   */
  private generateCircuitDetails(): string {
    // getComplexityClass/Label return values from a fixed enum, so
    // they are safe to interpolate as a class name.
    let rows = '';
    for (const circuit of this.result.circuits) {
      const complexity = this.getComplexityClass(circuit.constraints);
      rows += `
        <tr>
          <td><strong>${this.escapeHtml(circuit.name)}</strong></td>
          <td>${circuit.constraints.toLocaleString()}</td>
          <td>${circuit.kValue}</td>
          <td>${(circuit.proofSize / 1024).toFixed(1)} KB</td>
          <td>${circuit.provingTimeEstimate.toFixed(1)}s</td>
          <td>${circuit.memoryEstimate.toFixed(0)} MB</td>
          <td><span class="${complexity}">${this.escapeHtml(this.getComplexityLabel(circuit.constraints))}</span></td>
        </tr>
      `;
    }

    return `
    <section>
      <h2>🔗 Circuit Details</h2>
      <table>
        <thead>
          <tr>
            <th>Circuit</th>
            <th>Constraints</th>
            <th>K-Value</th>
            <th>Proof Size</th>
            <th>Proving Time</th>
            <th>Memory</th>
            <th>Complexity</th>
          </tr>
        </thead>
        <tbody>
          ${rows}
        </tbody>
      </table>
    </section>
    `;
  }

  /**
   * Generate performance insights
   */
  private generatePerformanceInsights(): string {
    const insights: string[] = [];

    // High constraint circuits
    const highConstraintCircuits = this.result.circuits.filter(c => c.constraints > 100000);
    if (highConstraintCircuits.length > 0) {
      insights.push(`${highConstraintCircuits.length} circuit(s) with very high constraint count (>100K): ${highConstraintCircuits.map(c => c.name).join(', ')}`);
    }

    // Long proving times
    const slowCircuits = this.result.circuits.filter(c => c.provingTimeEstimate > 30);
    if (slowCircuits.length > 0) {
      insights.push(`${slowCircuits.length} circuit(s) with slow proving time (>30s): ${slowCircuits.map(c => `${c.name} (${c.provingTimeEstimate.toFixed(1)}s)`).join(', ')}`);
    }

    // High memory circuits
    const memoryIntensiveCircuits = this.result.circuits.filter(c => c.memoryEstimate > 1000);
    if (memoryIntensiveCircuits.length > 0) {
      insights.push(`${memoryIntensiveCircuits.length} circuit(s) require significant memory (>1GB): ${memoryIntensiveCircuits.map(c => c.name).join(', ')}`);
    }

    // Large proof sizes
    const largeProofCircuits = this.result.circuits.filter(c => c.proofSize > 2048);
    if (largeProofCircuits.length > 0) {
      insights.push(`${largeProofCircuits.length} circuit(s) generate large proofs (>2KB): ${largeProofCircuits.map(c => c.name).join(', ')}`);
    }

    // Good performance
    if (insights.length === 0) {
      insights.push('All circuits show good performance characteristics');
      insights.push(`Average proving time: ${(this.result.circuits.reduce((sum, c) => sum + c.provingTimeEstimate, 0) / this.result.circuits.length).toFixed(1)}s`);
    }

    return `
    <section>
      <h2>⚡ Performance Insights</h2>
      <div class="insights">
        ${insights.map(insight => `<div class="insight-item">${this.escapeHtml(insight)}</div>`).join('')}
      </div>
    </section>
    `;
  }

  /**
   * Generate recommendations
   */
  private generateRecommendations(): string {
    const recommendations: string[] = [];

    // Constraint optimization
    const highConstraintCircuits = this.result.circuits.filter(c => c.constraints > 50000);
    if (highConstraintCircuits.length > 0) {
      recommendations.push(`Consider breaking down high-complexity circuits (${highConstraintCircuits.map(c => c.name).join(', ')}) into smaller sub-circuits for better performance and maintainability`);
    }

    // Memory optimization
    const memoryIntensiveCircuits = this.result.circuits.filter(c => c.memoryEstimate > 1000);
    if (memoryIntensiveCircuits.length > 0) {
      recommendations.push(`Memory-intensive circuits (${memoryIntensiveCircuits.map(c => c.name).join(', ')}) may require optimization or hardware upgrades for proving`);
    }

    // Parallelization
    if (this.result.circuits.length > 3) {
      recommendations.push(`With ${this.result.circuits.length} circuits, consider parallelizing proof generation to reduce overall proving time`);
    }

    // Testing
    const criticalCircuits = this.result.circuits.filter(c => c.constraints > 100000);
    if (criticalCircuits.length > 0) {
      recommendations.push(`Ensure thorough testing of high-complexity circuits (${criticalCircuits.map(c => c.name).join(', ')}) before deployment`);
    }

    // General advice
    if (recommendations.length === 0) {
      recommendations.push('Circuit complexity is within reasonable bounds');
      recommendations.push('Continue monitoring performance as the contract evolves');
      recommendations.push('Consider adding benchmarks to track performance over time');
    }

    return `
    <section>
      <h2>💡 Recommendations</h2>
      <div class="recommendations">
        ${recommendations.map(rec => `<div class="recommendation-item">${this.escapeHtml(rec)}</div>`).join('')}
      </div>
    </section>
    `;
  }

  /**
   * Generate visualizations section
   */
  private generateVisualizationsSection(): string {
    if (this.visualizationPaths.size === 0) {
      return '';
    }

    const visualizations = [
      {
        key: 'dependency',
        title: 'Circuit Dependency Graph',
        description: 'Shows the dependencies between circuits in the contract. Each node represents a circuit, and edges show which circuits call other circuits. Node colors indicate circuit complexity based on constraint counts. If no edges are shown, circuits are independent of each other (common when using library functions).',
        hasLegend: true
      },
      {
        key: 'state-flow',
        title: 'State Flow Diagram',
        description: 'Maps how circuits interact with contract state. Ledger variables (public state, stored on-chain) are shown as cylinders. Witness variables (private inputs, known only to prover) are shown as diamonds. Arrows indicate read operations (data flowing from state to circuit) and write operations (circuit modifying state). This helps identify which circuits access which state and whether that state is public or private.',
        hasLegend: false
      },
      {
        key: 'performance',
        title: 'Performance Heatmap',
        description: 'Identifies performance characteristics of each circuit based on constraint count and estimated proving time. Circuits are color-coded by their performance impact to help prioritize optimization efforts.',
        hasLegend: true
      }
    ];

    let vizHtml = '<section><h2>📈 Visualizations</h2>';

    for (const viz of visualizations) {
      const path = this.visualizationPaths.get(viz.key);
      if (path) {
        let legendHtml = '';
        if (viz.hasLegend && this.visualizer) {
          if (viz.key === 'dependency') {
            legendHtml = this.visualizer.getDependencyLegendHTML(this.options.theme);
          } else if (viz.key === 'performance') {
            legendHtml = this.visualizer.getPerformanceLegendHTML(this.options.theme);
          }
        }

        // viz.title/description come from a fixed-literal array above
        // (currently static text) but defense in depth: escape them so
        // a future contributor can't introduce XSS by switching to
        // dynamic descriptions. path is a local filesystem path
        // produced by the visualizer; escape for attribute context.
        // legendHtml is pre-rendered HTML from the visualizer and is
        // intentionally not escaped.
        vizHtml += `
          <div class="visualization">
            <div class="visualization-title">${this.escapeHtml(viz.title)}</div>
            <div class="visualization-description">${this.escapeHtml(viz.description)}</div>
            <img src="${this.escapeHtml(path)}" alt="${this.escapeHtml(viz.title)}" loading="lazy" />
            ${legendHtml}
          </div>
        `;
      }
    }

    vizHtml += '</section>';
    return vizHtml;
  }

  /**
   * Generate footer
   */
  private generateFooter(): string {
    return `
    <footer>
      <p>Generated by <strong>Compact Circuit Analyzer</strong> v0.1.0</p>
      <p>Powered by the Minokawa compact compiler</p>
    </footer>
    `;
  }

  /**
   * Generate interactive scripts
   */
  // getScripts() removed in favour of an empty CSP script-src.
  // See the comment in the main template for context.

  /**
   * Get complexity CSS class
   */
  private getComplexityClass(constraints: number): string {
    if (constraints < 1000) return 'complexity-low';
    if (constraints < 10000) return 'complexity-medium';
    if (constraints < 100000) return 'complexity-high';
    return 'complexity-very-high';
  }

  /**
   * Get complexity label
   */
  private getComplexityLabel(constraints: number): string {
    if (constraints < 1000) return 'Low';
    if (constraints < 10000) return 'Medium';
    if (constraints < 100000) return 'High';
    return 'Very High';
  }
}
