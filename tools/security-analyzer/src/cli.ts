#!/usr/bin/env node
/**
 * Compact Circuit Analyzer CLI
 * Production-grade constraint analysis for Midnight Compact smart contracts
 */

import { Command } from 'commander';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { resolve, join, dirname, basename } from 'path';
import { checkCompilerAvailable } from './compiler.js';
import { analyzeContract, analyzeContracts } from './analyzer.js';
import {
  loadBaseline,
  writeBaseline,
  generateBaseline,
  type AckEntry,
  type BaselineFile,
} from './baseline.js';
import { generateReport } from './reporter.js';
import { CircuitVisualizer } from './visualizer.js';
import { ComprehensiveReportGenerator } from './report-generator.js';
import { ApiDocGenerator } from './api-doc-generator.js';
import { DiagramGenerator } from './diagram-generator.js';
import { IntegrationExamplesGenerator } from './integration-examples.js';
import { AttackScenarioModeler } from './attack-scenario-modeler.js';
import type { ReportOptions, VisualizationOptions } from './types.js';

const program = new Command();

program
  .name('compact-analyzer')
  .description('Production-grade constraint analysis for Midnight Compact smart contracts')
  .version('1.0.0');

program
  .command('analyze')
  .description('Analyze one or more Compact contracts')
  .argument('<files...>', 'Compact contract files (.compact)')
  .option('-o, --output <file>', 'Output file (default: console)')
  .option('-f, --format <format>', 'Output format: console, markdown, json, sarif', 'console')
  .option('-v, --verbose', 'Show detailed metrics', false)
  .option('--no-warnings', 'Suppress warnings for large circuits')
  .option('--timeout <ms>', 'Compilation timeout in milliseconds', '120000')
  .action(async (files: string[], options) => {
    try {
      // Validate inputs
      for (const file of files) {
        if (!existsSync(file)) {
          console.error(`❌ Error: File not found: ${file}`);
          process.exit(1);
        }

        if (!file.endsWith('.compact')) {
          console.error(`❌ Error: Not a Compact file: ${file}`);
          console.error('   Expected: .compact extension');
          process.exit(1);
        }
      }

      // Check if compact compiler is available
      const compilerAvailable = await checkCompilerAvailable();
      if (!compilerAvailable) {
        console.error('❌ Error: Compact compiler not found');
        console.error('');
        console.error('Please install the Compact compiler:');
        console.error('  https://docs.midnight.network/develop/tutorial/compiling');
        console.error('');
        console.error('Or ensure "compact" is in your PATH.');
        process.exit(1);
      }

      // Show progress
      console.log(`Analyzing ${files.length} contract(s)...`);
      console.log('');

      // Analyze contracts
      const results = await analyzeContracts(files, {
        verbose: false,
        timeout: parseInt(options.timeout, 10),
      });

      // Generate reports
      const reportOptions: ReportOptions = {
        format: options.format as 'console' | 'markdown' | 'json' | 'sarif',
        outputFile: options.output,
        verbose: options.verbose,
        warnings: options.warnings,
      };

      for (const result of results) {
        generateReport(result, reportOptions);
      }

      process.exit(0);
    } catch (error) {
      if (error instanceof Error) {
        console.error(`❌ Error: ${error.message}`);
        if (options.verbose && error.stack) {
          console.error('');
          console.error('Stack trace:');
          console.error(error.stack);
        }
      } else {
        console.error('❌ Unknown error occurred');
      }
      process.exit(1);
    }
  });

program
  .command('visualize')
  .description('Generate visual diagrams of circuit dependencies and flows')
  .argument('<files...>', 'One or more Compact contract files (.compact). Each gets its own subdirectory.')
  .option('-o, --output <dir>', 'Output directory. With one file: the diagrams land here directly. With multiple files: this is the parent dir; per-contract subdirs are created inside.', './circuit-visualizations')
  .option('-f, --format <format>', 'Output format: png, svg, pdf, dot', 'png')
  .option('-t, --theme <theme>', 'Theme: default, dark, light, colorful', 'default')
  .option('--type <types...>', 'Visualization types: dependency, constraint, variable, ledger, performance, all', ['all'])
  .option('--no-details', 'Exclude detailed information')
  .option('--no-legend', 'Exclude legend from diagrams')
  .option('--performance', 'Include performance metrics')
  .option('--timeout <ms>', 'Compilation timeout in milliseconds', '120000')
  .action(async (files: string[], options) => {
    try {
      for (const file of files) {
        if (!existsSync(file)) {
          console.error(`❌ Error: File not found: ${file}`);
          process.exit(1);
        }
        if (!file.endsWith('.compact')) {
          console.error(`❌ Error: Not a Compact file: ${file}`);
          console.error('   Expected: .compact extension');
          process.exit(1);
        }
      }

      const compilerAvailable = await checkCompilerAvailable();
      if (!compilerAvailable) {
        console.error('❌ Error: Compact compiler not found');
        console.error('');
        console.error('Please install the Compact compiler:');
        console.error('  https://docs.midnight.network/develop/tutorial/compiling');
        console.error('');
        console.error('Or ensure "compact" is in your PATH.');
        process.exit(1);
      }

      const multi = files.length > 1;
      const failed: Array<{ file: string; error: string }> = [];

      for (const [i, file] of files.entries()) {
        const contractName = basename(file, '.compact');
        const outputDir = multi
          ? join(options.output, contractName)
          : options.output;

        if (multi) {
          console.log(`── [${i + 1}/${files.length}] ${basename(file)} ──`);
        }
        console.log(`Analyzing ${file}...\n`);

        try {
          const result = await analyzeContract(file, {
            verbose: false,
            timeout: parseInt(options.timeout, 10),
          });

          const vizOptions: Partial<VisualizationOptions> = {
            outputDir,
            format: options.format as 'png' | 'svg' | 'pdf' | 'dot',
            theme: options.theme as 'default' | 'dark' | 'light' | 'colorful',
            types: options.type as Array<'dependency' | 'state-flow' | 'performance' | 'all'>,
            includeDetails: options.details !== false,
            includeLegend: options.legend !== false,
            includePerformance: options.performance === true,
          };

          const visualizer = new CircuitVisualizer(result, vizOptions);
          await visualizer.visualize();
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          failed.push({ file, error: msg });
          console.error(`❌ Visualize failed for ${basename(file)}: ${msg}\n`);
        }
      }

      if (multi) {
        console.log('\n══ Summary ══');
        console.log(`  ✅ Succeeded: ${files.length - failed.length}`);
        console.log(`  ❌ Failed:    ${failed.length}`);
        for (const f of failed) {
          console.log(`     - ${basename(f.file)}: ${f.error}`);
        }
      }

      process.exit(failed.length === 0 ? 0 : 1);
    } catch (error) {
      if (error instanceof Error) {
        console.error(`❌ Error: ${error.message}`);
      } else {
        console.error('❌ Unknown error occurred');
      }
      process.exit(1);
    }
  });

program
  .command('report')
  .description('Generate comprehensive HTML report(s) with analysis and visualizations')
  .argument('<files...>', 'One or more Compact contract files (.compact). Each gets its own report directory.')
  .option('-o, --output <dir>', 'Output directory. With one file: the report dir itself. With multiple files: a parent dir holding one subdir per contract. (default: contract name in cwd)')
  .option('-t, --theme <theme>', 'Theme: light, dark', 'light')
  .option('--viz-format <format>', 'Visualization format: svg, png', 'svg')
  .option('--no-visualizations', 'Exclude visualizations from report')
  .option('--witness-file <path>', 'Path to the witness JS/TS implementation file. Used by the nonce analyzer to detect constant-return witnesses. Omit to auto-search conventional locations.')
  .option('--from-build-dir <path>', 'Skip compilation; consume an existing compactc output directory (must contain compiler/, optionally zkir/ and keys/). Useful for CI pipelines that already compiled, or for fast iteration on the analyzer without paying the compile cost.')
  .option('--baseline-file <path>', 'Honor an explicit baseline file. Defaults to auto-discovery: ./.security-analyzer-baseline.json walking up to the repo root.')
  .option('--no-baseline', 'Ignore any baseline file; report every finding. Useful for first-run audits.')
  .option('--baseline-mode <mode>', 'How acked findings are reported: suppress | downgrade-to-info | accounting-only (default: suppress)', 'suppress')
  .option('--update-baseline', 'Walk current findings and write entries to the baseline file. Reads ack reasons from stdin as a JSON object {findingId: reason}; pass --update-baseline-by <name> to record the author. Existing acks are preserved.', false)
  .option('--update-baseline-by <name>', 'Author identifier recorded on baseline entries written by --update-baseline.', 'unknown@local')
  .option('--timeout <ms>', 'Compilation timeout in milliseconds', '120000')
  .action(async (files: string[], options) => {
    try {
      // Validate every input up-front so a typo in arg N doesn't surface only
      // after N-1 reports are generated.
      for (const file of files) {
        if (!existsSync(file)) {
          console.error(`❌ Error: File not found: ${file}`);
          process.exit(1);
        }
        if (!file.endsWith('.compact')) {
          console.error(`❌ Error: Not a Compact file: ${file}`);
          console.error('   Expected: .compact extension');
          process.exit(1);
        }
      }

      // Check if compact compiler is available
      const compilerAvailable = await checkCompilerAvailable();
      if (!compilerAvailable) {
        console.error('❌ Error: Compact compiler not found');
        console.error('');
        console.error('Please install the Compact compiler:');
        console.error('  https://docs.midnight.network/develop/tutorial/compiling');
        console.error('');
        console.error('Or ensure "compact" is in your PATH.');
        process.exit(1);
      }

      // --update-baseline: run analysis to gather findings, read reasons
      // from stdin as a JSON map, write the baseline file, exit. The
      // report HTML is NOT generated in this mode — the goal is a tight
      // "audit triage then commit" loop, not a full report.
      if (options.updateBaseline) {
        if (files.length !== 1) {
          console.error('❌ Error: --update-baseline takes exactly one .compact file');
          process.exit(1);
        }
        const baselinePath = options.baselineFile
          ?? join(dirname(resolve(files[0])), '.security-analyzer-baseline.json');
        try {
          await runUpdateBaseline(files[0], baselinePath, options);
          process.exit(0);
        } catch (err) {
          console.error(`❌ Error: ${err instanceof Error ? err.message : String(err)}`);
          process.exit(1);
        }
      }

      const multi = files.length > 1;
      if (multi) {
        console.log(`📚 Generating reports for ${files.length} contracts...\n`);
      }

      const succeeded: string[] = [];
      const failed: Array<{ file: string; error: string }> = [];

      for (const [i, file] of files.entries()) {
        const contractName = basename(file, '.compact');
        // Resolve output dir:
        //   single file + --output X     -> X is the report dir
        //   single file + no --output    -> ./<contractName>
        //   multi  + --output X          -> X/<contractName>
        //   multi  + no --output         -> ./<contractName>
        const outputDir = multi
          ? join(options.output ?? '.', contractName)
          : (options.output || contractName);

        if (!existsSync(outputDir)) {
          mkdirSync(outputDir, { recursive: true });
        }

        if (multi) {
          console.log(`── [${i + 1}/${files.length}] ${basename(file)} ──`);
        }
        console.log(`📊 Generating comprehensive report for ${basename(file)}...`);
        console.log(`📁 Output directory: ${outputDir}\n`);

        try {
          await generateOneReport(file, outputDir, options);
          succeeded.push(outputDir);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          failed.push({ file, error: msg });
          console.error(`❌ Report failed for ${basename(file)}: ${msg}\n`);
          // Continue with the remaining contracts rather than abort the batch.
        }
      }

      if (multi) {
        console.log('\n══ Summary ══');
        console.log(`  ✅ Succeeded: ${succeeded.length}`);
        console.log(`  ❌ Failed:    ${failed.length}`);
        for (const f of failed) {
          console.log(`     - ${basename(f.file)}: ${f.error}`);
        }
      }

      process.exit(failed.length === 0 ? 0 : 1);
    } catch (error) {
      if (error instanceof Error) {
        console.error(`❌ Error: ${error.message}`);
      } else {
        console.error('❌ Unknown error occurred');
      }
      process.exit(1);
    }
  });

/**
 * Run the analyzer in --update-baseline mode. Discovers findings and
 * writes (or updates) a baseline file using reasons supplied via stdin.
 *
 * stdin format: JSON object mapping finding ID → reason string. Any
 * finding ID without a reason in the input is skipped (NOT silently
 * acked). Existing entries in the baseline are preserved.
 *
 * If stdin is empty or `{}`, no new entries are written — useful as a
 * "list current findings" smoke test before authoring reasons.
 */
async function runUpdateBaseline(
  file: string,
  baselinePath: string,
  options: any,
): Promise<void> {
  console.log(`🔧 Updating baseline for ${basename(file)}...`);
  const result = await analyzeContract(file, {
    verbose: false,
    timeout: parseInt(options.timeout, 10),
    witnessFile: options.witnessFile,
    fromBuildDir: options.fromBuildDir,
    // Don't suppress acks during update — we want to surface every
    // current finding so the human can decide which need acks.
    noBaseline: true,
  });

  const security = result.security?.findings ?? [];
  const nonce = result.nonceAnalysis?.findings ?? [];
  const correlator = result.correlatorAnalysis?.findings ?? [];

  // Build a flat catalog for the user, written to stderr so stdout stays
  // reserved for any future programmatic emission.
  console.error('\nCurrent findings (paste reasons into the JSON map you pipe to stdin):');
  const announce = (kind: string, list: { id?: string; severity?: string; title?: string }[]) => {
    for (const f of list) {
      if (!f.id) continue;
      const t = (f.title ?? '').slice(0, 80);
      console.error(`  [${kind}] ${f.id}  ${f.severity ?? ''}  ${t}`);
    }
  };
  announce('security', security as { id?: string; severity?: string; title?: string }[]);
  announce('nonce', nonce as { id?: string; severity?: string; title?: string }[]);
  announce('correlator', correlator as { id?: string; severity?: string; title?: string }[]);
  console.error('');

  // Read reasons from stdin. Empty input → no new entries written.
  let reasonsRaw = '';
  try {
    reasonsRaw = readFileSync(0, 'utf-8');
  } catch {
    // No piped input — treat as empty.
  }
  let reasons: Record<string, string> = {};
  if (reasonsRaw.trim()) {
    try {
      reasons = JSON.parse(reasonsRaw);
    } catch (e) {
      throw new Error(`stdin is not valid JSON: ${(e as Error).message}`);
    }
  }

  const prior: BaselineFile | undefined = existsSync(baselinePath)
    ? loadBaseline(baselinePath).baseline
    : undefined;

  const updated = generateBaseline({
    security: security as any[],
    nonce: nonce as any[],
    correlator: correlator as any[],
    prior,
    reasonByIdFn: (id) => reasons[id] ?? null,
    ackBy: options.updateBaselineBy ?? 'unknown@local',
    toolVersion: 'security-analyzer@1.0.0',
  });

  writeBaseline(baselinePath, updated);
  const newCount = updated.acks.length - (prior?.acks.length ?? 0);
  console.log(`✅ Wrote ${baselinePath} (${updated.acks.length} total, ${newCount} new)`);
}

async function generateOneReport(
  file: string,
  outputDir: string,
  options: any,
): Promise<void> {
  {

      // Analyze contract
      console.log('1️⃣  Analyzing circuit...');
      if (options.fromBuildDir) {
        console.log(`   📁 Using existing build dir: ${options.fromBuildDir}`);
      }
      const result = await analyzeContract(file, {
        verbose: false,
        timeout: parseInt(options.timeout, 10),
        witnessFile: options.witnessFile,
        fromBuildDir: options.fromBuildDir,
        baselineFile: options.baselineFile,
        noBaseline: options.baseline === false || options.noBaseline === true,
        baselineMode: options.baselineMode as 'suppress' | 'downgrade-to-info' | 'accounting-only',
      });

      if (result.baselineApplication) {
        const ba = result.baselineApplication;
        const acked = ba.acksApplied;
        const netNew = ba.netNewFindings;
        const expired = ba.acksExpired.length;
        const unmatched = ba.acksUnmatched.length;
        console.log(
          `   🔇 Baseline: ${acked} acked, ${netNew} net-new high/critical` +
          (expired ? `, ${expired} expired` : '') +
          (unmatched ? `, ${unmatched} unmatched (consider removing from baseline)` : '')
        );
      }
      console.log('   ✅ Analysis complete\n');

      // Generate visualizations if requested
      const visualizationPaths = new Map<string, string>();
      let visualizer: CircuitVisualizer | undefined;

      if (options.visualizations !== false) {
        console.log('2️⃣  Generating visualizations...');

        // Create visualizations subdirectory
        const vizDir = join(outputDir, 'visualizations');

        if (!existsSync(vizDir)) {
          mkdirSync(vizDir, { recursive: true });
        }

        const vizOptions: Partial<VisualizationOptions> = {
          outputDir: vizDir,
          format: options.vizFormat as 'svg' | 'png',
          theme: options.theme === 'dark' ? 'dark' : 'default',
          types: ['all'],
          includeDetails: true,
          includeLegend: false, // Legends will be added as HTML in the report
          includePerformance: true
        };

        visualizer = new CircuitVisualizer(result, vizOptions);
        await visualizer.visualize();

        // Store relative paths to visualizations
        const vizTypes = ['dependency', 'state-flow', 'performance'];
        for (const type of vizTypes) {
          const filename = `${type === 'state-flow' ? 'state-flow' :
                           type === 'performance' ? 'performance-heatmap' :
                           'dependency-graph'}.${options.vizFormat}`;

          const fullPath = join(vizDir, filename);
          if (existsSync(fullPath)) {
            visualizationPaths.set(type, `visualizations/${filename}`);
          }
        }
        console.log('   ✅ Visualizations generated\n');
      }

      // Generate HTML report
      console.log('3️⃣  Generating HTML report...');
      const htmlPath = join(outputDir, 'report.html');
      const reportGen = new ComprehensiveReportGenerator(
        result,
        {
          outputFile: htmlPath,
          includeVisualizations: options.visualizations !== false,
          visualizationFormat: options.vizFormat,
          theme: options.theme
        },
        visualizationPaths,
        visualizer
      );

      reportGen.generate();

      // Emit machine-readable Contract Profile + Value Inventory.
      // Sibling artifact to the compiler's security-analysis.json so
      // CI gates, dashboards, and downstream tools can consume the
      // analyzer's classification without parsing HTML.
      if (result.profile || result.valueInventory || result.nonceAnalysis || result.correlatorAnalysis || result.policyAssessment) {
        const profileJsonPath = join(outputDir, 'security-profile.json');
        writeFileSync(
          profileJsonPath,
          JSON.stringify(
            {
              schema_version: '1.0.0',
              contract_file: result.contractFile,
              analyzer_version: '1.0.0',
              generated_at: result.timestamp,
              // Policy assessment leads — the deploy_recommendation is
              // the first thing a CI gate or operator reads.
              policy_assessment: result.policyAssessment,
              profile: result.profile,
              value_inventory: result.valueInventory,
              nonce_analysis: result.nonceAnalysis,
              correlator_analysis: result.correlatorAnalysis,
            },
            null,
            2,
          ) + '\n',
        );
        console.log(`   📄 security-profile.json written: ${profileJsonPath}`);
      }

      // Generate API documentation
      console.log('4️⃣  Generating API documentation...');
      const apiDocPath = join(outputDir, 'api-docs.html');
      const apiDocGen = new ApiDocGenerator(file, result);
      apiDocGen.generate(apiDocPath);
      console.log('   ✅ API docs generated\n');

      // Generate attack scenarios
      console.log('5️⃣  Generating attack scenarios...');
      const attackScenarioPath = join(outputDir, 'attack-scenarios.html');
      const attackModeler = new AttackScenarioModeler(file, result);
      attackModeler.generate(attackScenarioPath);
      console.log('   ✅ Attack scenarios generated\n');

      // Generate diagrams
      console.log('6️⃣  Generating sequence and state diagrams...');
      const diagramGen = new DiagramGenerator(file, result);

      const sequenceDiagram = diagramGen.generateSequenceDiagram();
      const sequencePath = join(outputDir, 'sequence-diagram.mmd');
      writeFileSync(sequencePath, sequenceDiagram);

      const stateMachine = diagramGen.generateStateMachineDiagram();
      const stateMachinePath = join(outputDir, 'state-machine.mmd');
      writeFileSync(stateMachinePath, stateMachine);

      const deploymentSeq = diagramGen.generateDeploymentSequence();
      const deploymentPath = join(outputDir, 'deployment-sequence.mmd');
      writeFileSync(deploymentPath, deploymentSeq);

      console.log('   ✅ Diagrams generated\n');

      // Generate integration examples
      console.log('7️⃣  Generating integration examples...');
      const integrationExamplesPath = join(outputDir, 'integration-examples.ts');
      const examplesGen = new IntegrationExamplesGenerator(file, result);
      const examples = examplesGen.generate();
      writeFileSync(integrationExamplesPath, examples);
      console.log('   ✅ Integration examples generated\n');

      console.log('\n🎉 Report generated successfully!');
      console.log(`   📁 ${outputDir}/`);
      console.log(`      ├── report.html`);
      console.log(`      ├── api-docs.html`);
      console.log(`      ├── attack-scenarios.html`);
      console.log(`      ├── integration-examples.ts`);
      console.log(`      ├── sequence-diagram.mmd`);
      console.log(`      ├── state-machine.mmd`);
      console.log(`      ├── deployment-sequence.mmd`);
      if (options.visualizations !== false) {
        console.log(`      └── visualizations/`);
        console.log(`          ├── dependency-graph.${options.vizFormat}`);
        console.log(`          ├── constraint-flow.${options.vizFormat}`);
        console.log(`          ├── variable-map.${options.vizFormat}`);
        console.log(`          ├── ledger-interactions.${options.vizFormat}`);
        console.log(`          └── performance-heatmap.${options.vizFormat}`);
      }
      console.log(`\n   📖 Open ${htmlPath} in your browser to view the main report.`);
      console.log(`   📚 Open ${apiDocPath} for API documentation.`);
      console.log(`   🛡️  Open ${attackScenarioPath} for security attack scenarios.\n`);
  }
}

program
  .command('version')
  .description('Show compact-analyzer and compiler versions')
  .action(async () => {
    try {
      console.log(`compact-analyzer: 1.0.0`);

      const compilerAvailable = await checkCompilerAvailable();
      if (compilerAvailable) {
        const { getCompilerVersion } = await import('./compiler.js');
        const version = await getCompilerVersion();
        console.log(`compact compiler: ${version || 'unknown'}`);
      } else {
        console.log('compact compiler: not found');
      }
    } catch (error) {
      console.error('Error checking versions:', error);
      process.exit(1);
    }
  });

// Show help if no command provided
if (process.argv.length <= 2) {
  program.help();
}

program.parse();
