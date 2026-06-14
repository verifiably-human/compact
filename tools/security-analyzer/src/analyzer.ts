/**
 * Main Analyzer Module
 * Orchestrates compilation and analysis
 */

import { tmpdir } from 'os';
import { mkdirSync, rmSync, existsSync } from 'fs';
import { join, resolve, basename } from 'path';
import {
  compileContract,
  getCompilerVersion,
  getOutputDirName,
  getZkirDirPath,
} from './compiler.js';
import { parseCircuits } from './parser.js';
import { SecurityAnalyzer } from './security-analyzer.js';
import { AdvancedAnalyzer } from './advanced-analyzer.js';
import { ProfileAnalyzer } from './profile-analyzer.js';
import { NonceAnalyzer } from './nonce-analyzer.js';
import { CorrelatorAnalyzer } from './correlator-analyzer.js';
import { assessPolicy } from './policy-assessor.js';
import {
  readCompilerSecurityAnalysis,
  convertCompilerFindings,
  mergeSecurityFindings,
} from './compiler-security-reader.js';
import type { AnalysisResult, CompilerOptions, ContractProfile, CorrelatorAnalysis, NonceAnalysis, PolicyAssessment, ValueInventory } from './types.js';
import { addIdsToSecurityFindings } from './finding-id.js';
import {
  loadBaseline,
  applyBaseline,
  inlineAnnotationAcks,
  type BaselineApplication,
} from './baseline.js';

/**
 * Analyze a Compact contract
 */
export async function analyzeContract(
  contractPath: string,
  options: CompilerOptions = {}
): Promise<AnalysisResult> {
  const absolutePath = resolve(contractPath);
  const contractName = getOutputDirName(absolutePath);

  // Two modes:
  //   compile-and-analyse (default): create a tempDir, run compactc into
  //                                   it, read artifacts, delete tempDir
  //                                   at the end.
  //   --from-build-dir <path>:       skip compilation; read artifacts
  //                                   from the supplied directory. The
  //                                   directory must contain the layout
  //                                   compactc emits (compiler/, zkir/,
  //                                   optionally keys/).
  const fromBuildDir = options.fromBuildDir ? resolve(options.fromBuildDir) : null;
  const useExistingBuild = fromBuildDir !== null;
  const workDir = useExistingBuild ? fromBuildDir! : join(tmpdir(), `compact-analyzer-${Date.now()}`);
  let compileDurationMs = 0;
  let zkirAvailable = false;

  if (!useExistingBuild) {
    mkdirSync(workDir, { recursive: true });
  } else if (!existsSync(workDir)) {
    throw new Error(`--from-build-dir not found: ${workDir}`);
  } else if (!existsSync(join(workDir, 'compiler'))) {
    throw new Error(`--from-build-dir missing 'compiler/' subdirectory: ${workDir}`);
  }

  try {
    let circuits: ReturnType<typeof parseCircuits>;

    if (useExistingBuild) {
      // Try to parse zkir artifacts; tolerate absence (a CI that ran
      // only the compiler without the zkir step still produces useful
      // analysis, just without constraint counts).
      const zkirDir = getZkirDirPath(workDir);
      try {
        circuits = parseCircuits(zkirDir);
        zkirAvailable = circuits.length > 0;
      } catch {
        circuits = [];
        zkirAvailable = false;
      }
    } else {
      // Compile the contract
      const compileResult = await compileContract(absolutePath, workDir, {
        ...options,
        skipZk: true, // Always skip ZK generation for constraint analysis
      });
      compileDurationMs = compileResult.duration;

      // Parse ZKIR files
      const zkirDir = getZkirDirPath(workDir);
      circuits = parseCircuits(zkirDir);
      zkirAvailable = circuits.length > 0;
    }

    // Get compiler version
    const compilerVersion = await getCompilerVersion();

    // Calculate totals
    const totalConstraints = circuits.reduce((sum, c) => sum + c.constraints, 0);

    // Run security analysis. The compiler emits `compiler/security-analysis.json`
    // (COIP v1.0.0) on every successful compile; presence of the file is the
    // capability signal. Heuristic analysis still runs and is merged in for
    // categories the compiler does not cover (access control, nullifier reuse,
    // etc.).
    let securityAnalysis;
    let profile: ContractProfile | undefined;
    let valueInventory: ValueInventory | undefined;
    let nonceAnalysis: NonceAnalysis | undefined;
    let correlatorAnalysis: CorrelatorAnalysis | undefined;
    let policyAssessment: PolicyAssessment | undefined;
    let baselineApplication: BaselineApplication | undefined;
    try {
      const compilerAnalysis = readCompilerSecurityAnalysis(workDir);
      const compilerSecurityAnalysis = compilerAnalysis
        ? convertCompilerFindings(compilerAnalysis)
        : null;

      if (options.verbose) {
        if (compilerAnalysis) {
          const leakCount = compilerAnalysis.leaks.length;
          const discCount = compilerAnalysis.disclosures.length;
          console.log(
            `✓ Compiler security analysis loaded (schema ${compilerAnalysis.schema_version}, ` +
            `${leakCount} leaks, ${discCount} disclosures, ${compilerAnalysis.witness_count} witnesses)`
          );
        } else {
          console.log('⚠️  No compiler/security-analysis.json found — falling back to heuristic-only analysis');
        }
      }

      const securityAnalyzer = new SecurityAnalyzer(absolutePath);
      const heuristicAnalysis = securityAnalyzer.analyze();

      securityAnalysis = mergeSecurityFindings(compilerSecurityAnalysis, heuristicAnalysis);
      // Every finding gets a stable ID before downstream consumers
      // (baselines, SARIF emitter, report) ever see it.
      addIdsToSecurityFindings(securityAnalysis.findings);

      // Profile + Value Inventory. Runs after security analysis so it
      // can read the access-control findings to classify authorityModel
      // and authorizedBy on mint operations.
      try {
        const profileAnalyzer = new ProfileAnalyzer({
          contractSource: securityAnalyzer.getContractSource(),
          contractPath: securityAnalyzer.getContractPath(),
          circuits: securityAnalyzer.getCircuits().map(c => ({
            name: c.name,
            body: c.body,
            isExported: c.isExported,
            returnType: c.returnType,
          })),
          stateVars: securityAnalyzer.getStateVars().map(v => ({
            name: v.name,
            type: v.type,
            kind: v.kind,
            sealed: v.sealed,
          })),
          findings: securityAnalysis.findings,
        });
        const { profile: p, valueInventory: vi } = profileAnalyzer.analyze();
        profile = p;
        valueInventory = vi;
      } catch (err) {
        console.warn('⚠️  Profile analysis failed:', err instanceof Error ? err.message : 'Unknown error');
      }

      // Nonce hygiene (phase 2). Inspects the witness JS/TS file and
      // scans the contract source for missing Counter increments.
      try {
        const nonceAnalyzer = new NonceAnalyzer({
          contractSource: securityAnalyzer.getContractSource(),
          contractPath: securityAnalyzer.getContractPath(),
          circuits: securityAnalyzer.getCircuits().map(c => ({
            name: c.name,
            body: c.body,
            isExported: c.isExported,
          })),
          stateVars: securityAnalyzer.getStateVars().map(v => ({
            name: v.name,
            type: v.type,
            kind: v.kind,
          })),
          witnessFilePathOverride: options.witnessFile,
        });
        nonceAnalysis = nonceAnalyzer.analyze();
        if (nonceAnalysis.witnessFileSkipped) {
          console.warn('   ℹ️  Witness file not found — constant-return-witness check skipped. Pass --witness-file to enable.');
        }
      } catch (err) {
        console.warn('⚠️  Nonce analysis failed:', err instanceof Error ? err.message : 'Unknown error');
      }

      // Correlator analysis (phase 3). Cross-circuit join over the
      // compiler's disclose records to surface witness origins that
      // flow to multiple circuits without per-event blinders. Requires
      // the compiler analysis to be present; skipped otherwise.
      if (compilerSecurityAnalysis !== null) {
        try {
          // Compute approximate body line ranges for each circuit so
          // disclose sites can be bound to a circuit. We use a simple
          // scan: each `circuit name(...) {` opens a body; matching `}`
          // closes it. Brace counting handles nested blocks.
          const source = securityAnalyzer.getContractSource();
          const lines = source.split('\n');
          const circuitsForCorrelator = securityAnalyzer.getCircuits().map(c => {
            const declRegex = new RegExp(`(?:export\\s+)?circuit\\s+${c.name}\\b`);
            let bodyStartLine: number | undefined;
            let bodyEndLine: number | undefined;
            let braceDepth = 0;
            let inBody = false;
            for (let i = 0; i < lines.length; i++) {
              if (!inBody && declRegex.test(lines[i])) {
                bodyStartLine = i + 1;
                braceDepth = 0;
                inBody = true;
              }
              if (inBody) {
                for (const ch of lines[i]) {
                  if (ch === '{') braceDepth++;
                  else if (ch === '}') {
                    braceDepth--;
                    if (braceDepth === 0) {
                      bodyEndLine = i + 1;
                      inBody = false;
                      break;
                    }
                  }
                }
                if (!inBody) break;
              }
            }
            return { name: c.name, bodyStartLine, bodyEndLine };
          });

          // compilerAnalysis is the raw object from
          // readCompilerSecurityAnalysis (validated upstream). The
          // correlator analyzer reads the disclosures directly.
          const correlatorAnalyzer = new CorrelatorAnalyzer({
            compilerAnalysis: compilerAnalysis!,
            annotations: securityAnalyzer.getAnnotations(),
            circuits: circuitsForCorrelator,
          });
          correlatorAnalysis = correlatorAnalyzer.analyze();
        } catch (err) {
          console.warn('⚠️  Correlator analysis failed:', err instanceof Error ? err.message : 'Unknown error');
        }
      }

      // Baseline application (phase: baselines). Acks loaded from
      // .security-analyzer-baseline.json plus inline @audit-ack
      // annotations remove or downgrade findings the team has already
      // reviewed. Runs BEFORE policy assessment so the policy verdict
      // honours the baseline.
      if (!options.noBaseline) {
        const baselinePath = options.baselineFile
          ?? resolveDefaultBaselinePath(absolutePath);
        try {
          const fileAcks = baselinePath
            ? loadBaseline(baselinePath).baseline.acks
            : [];
          const inlineAcks = inlineAnnotationAcks(securityAnalyzer.getAnnotations());
          baselineApplication = applyBaseline({
            security: securityAnalysis.findings,
            nonce: nonceAnalysis?.findings ?? [],
            correlator: correlatorAnalysis?.findings ?? [],
            fileAcks,
            inlineAcks,
            mode: options.baselineMode ?? 'suppress',
          });
          securityAnalysis = {
            ...securityAnalysis,
            findings: baselineApplication.filteredSecurity,
          };
          if (nonceAnalysis) {
            nonceAnalysis = { ...nonceAnalysis, findings: baselineApplication.filteredNonce };
          }
          if (correlatorAnalysis) {
            correlatorAnalysis = { ...correlatorAnalysis, findings: baselineApplication.filteredCorrelator };
          }
        } catch (err) {
          console.warn('⚠️  Baseline application failed:', err instanceof Error ? err.message : 'Unknown error');
        }
      }

      // Policy assessment (phase 4). Synthesises a deploy
      // recommendation from the profile + value inventory + findings.
      // Runs last so it has access to every other analyzer's output.
      try {
        if (profile && valueInventory) {
          policyAssessment = assessPolicy({
            profile,
            valueInventory,
            security: securityAnalysis,
            nonceAnalysis,
            correlatorAnalysis,
          });
        }
      } catch (err) {
        console.warn('⚠️  Policy assessment failed:', err instanceof Error ? err.message : 'Unknown error');
      }

    } catch (error) {
      console.warn('⚠️  Security analysis failed:', error instanceof Error ? error.message : 'Unknown error');
      securityAnalysis = undefined;
    }

    // Run advanced analysis (complexity, coverage, dead code)
    let advancedAnalysis;
    try {
      const advancedAnalyzer = new AdvancedAnalyzer(absolutePath);
      advancedAnalysis = advancedAnalyzer.analyze();
    } catch (error) {
      console.warn('⚠️  Advanced analysis failed:', error instanceof Error ? error.message : 'Unknown error');
      advancedAnalysis = undefined;
    }

    // Build result
    const result: AnalysisResult = {
      contractFile: absolutePath, // Store full path so visualizer can read source
      circuits,
      totalConstraints,
      compilationTime: compileDurationMs,
      timestamp: new Date().toISOString(),
      compilerVersion: compilerVersion || undefined,
      security: securityAnalysis,
      complexity: advancedAnalysis?.complexity,
      coverage: advancedAnalysis?.coverage,
      deadCode: advancedAnalysis?.deadCode,
      profile,
      valueInventory,
      nonceAnalysis,
      correlatorAnalysis,
      policyAssessment,
      baselineApplication,
    };

    return result;
  } finally {
    // Only clean up the tempDir we created — never delete a user-supplied
    // --from-build-dir.
    if (!useExistingBuild && existsSync(workDir)) {
      rmSync(workDir, { recursive: true, force: true });
    }
  }
}

/**
 * Look for a default baseline file next to the contract source. Returns
 * the path if found, or null. Search order:
 *   1. <contractDir>/.security-analyzer-baseline.json
 *   2. Walk parent directories looking for the same filename, up to the
 *      filesystem root or the first git repo root.
 */
function resolveDefaultBaselinePath(contractPath: string): string | null {
  const baselineName = '.security-analyzer-baseline.json';
  let dir = resolve(contractPath, '..');
  for (let depth = 0; depth < 32; depth++) {
    const candidate = join(dir, baselineName);
    if (existsSync(candidate)) return candidate;
    const gitDir = join(dir, '.git');
    if (existsSync(gitDir)) return null; // stop at repo root
    const parent = resolve(dir, '..');
    if (parent === dir) return null;     // filesystem root
    dir = parent;
  }
  return null;
}

/**
 * Analyze multiple contracts
 */
export async function analyzeContracts(
  contractPaths: string[],
  options: CompilerOptions = {}
): Promise<AnalysisResult[]> {
  const results: AnalysisResult[] = [];

  for (const contractPath of contractPaths) {
    const result = await analyzeContract(contractPath, options);
    results.push(result);
  }

  return results;
}
