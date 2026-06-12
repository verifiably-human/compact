/**
 * Nonce hygiene analyzer (phase 2).
 *
 * Implements two kinds of NonceFinding:
 *
 *  1. constant-return-witness — the witness JS/TS implementation returns
 *     a constant value where the circuit consumes it as a nonce. This
 *     defeats unlinkability without breaking the proof system. The
 *     compiler can't see this because the witness file is outside the
 *     compiler's view.
 *
 *  2. missing-counter-increment — a ledger field typed as Counter (or
 *     named like a sequence/nonce/version) is read into a hash without
 *     being incremented anywhere in the contract. Same nonce on every
 *     call.
 *
 * The two higher-FP kinds from the locked schema (multi-call-binding,
 * hash-without-blinder) are deferred to phase 2b.
 */

import { createHash } from 'crypto';
import { existsSync, readFileSync } from 'fs';
import { basename, dirname, join, resolve } from 'path';
import {
  NonceAnalysis,
  NonceFinding,
  NonceFindingKind,
  NonceSite,
} from './types.js';

// ---------------------------------------------------------------------------
// Inputs.
// ---------------------------------------------------------------------------

export interface CircuitForNonce {
  name: string;
  body: string;
  isExported: boolean;
}

export interface StateVarForNonce {
  name: string;
  type: string;
  kind: 'ledger' | 'witness';
}

export interface NonceAnalyzerInput {
  contractSource: string;
  contractPath: string;
  circuits: CircuitForNonce[];
  stateVars: StateVarForNonce[];
  // Optional override; CLI passes --witness-file here if supplied. When
  // null, the analyzer searches a small set of conventional locations.
  witnessFilePathOverride?: string;
}

// ---------------------------------------------------------------------------
// Heuristic config.
// ---------------------------------------------------------------------------

/**
 * Witness function names whose role suggests randomness/nonce.
 * The analyzer is conservative: it flags constant returns only for
 * functions whose name matches at least one of these patterns.
 */
const NONCE_ROLE_NAME_PATTERNS = [
  /nonce/i,
  /salt/i,
  /blinder/i,
  /random/i,
  /seed/i,
];

/**
 * Patterns that look like a constant return in JS/TS witness files.
 * `new Uint8Array(N)` with no fill, `Buffer.alloc(N)`, hardcoded array
 * literals, and direct returns of identifier-only expressions.
 */
const CONSTANT_RETURN_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /new\s+Uint8Array\s*\(\s*\d+\s*\)/, label: 'new Uint8Array(N) → all-zero bytes' },
  { pattern: /Buffer\.alloc\s*\(\s*\d+\s*\)/, label: 'Buffer.alloc(N) → all-zero bytes' },
  { pattern: /new\s+Uint8Array\s*\(\s*\[\s*[0-9,\s]+\s*\]\s*\)/, label: 'Uint8Array of literal bytes' },
  { pattern: /Buffer\.from\s*\(\s*['"`]/, label: 'Buffer.from(<string-literal>) → deterministic bytes' },
  { pattern: /Buffer\.from\s*\(\s*\[\s*[0-9,\s]+\s*\]\s*\)/, label: 'Buffer.from(literal-array) → fixed bytes' },
];

/**
 * Patterns indicating a proper CSPRNG draw inside the witness body.
 * If any of these appears AND no constant pattern is present, the
 * function is treated as random (no finding).
 */
const CSPRNG_PATTERNS = [
  /crypto\.randomBytes\b/,
  /\brandomBytes\s*\(/,
  /crypto\.getRandomValues\b/,
  /window\.crypto\.subtle\b/,
  /require\(\s*['"]crypto['"]\s*\)\.randomBytes/,
];

// ---------------------------------------------------------------------------
// Analyzer.
// ---------------------------------------------------------------------------

export class NonceAnalyzer {
  private input: NonceAnalyzerInput;
  private findings: NonceFinding[] = [];
  private witnessFile: string | null = null;
  private witnessFileText: string | null = null;

  constructor(input: NonceAnalyzerInput) {
    this.input = input;
  }

  analyze(): NonceAnalysis {
    this.witnessFile = this.locateWitnessFile();
    if (this.witnessFile) {
      try {
        this.witnessFileText = readFileSync(this.witnessFile, 'utf8');
      } catch {
        this.witnessFileText = null;
      }
    }

    this.detectConstantReturnWitnesses();
    this.detectMissingCounterIncrement();
    this.detectMultiCallBinding();
    this.detectHashWithoutBlinder();

    return {
      schemaVersion: '1.0.0',
      witnessFile: this.witnessFile,
      witnessFileSkipped: this.witnessFileText === null,
      findings: this.findings,
    };
  }

  // -------------------------------------------------------------------------
  // Witness file location.
  //
  // Tries, in order:
  //   1. CLI override (witnessFilePathOverride)
  //   2. Same dir as contract: <stem>-witnesses.{ts,js}, witness.{ts,js}, witnesses.{ts,js}
  //   3. ./witnesses/<stem>-witnesses.{ts,js}, ./witnesses/<stem>.{ts,js}
  //   4. ../witnesses/<stem>-witnesses.{ts,js}, ../witnesses/<stem>.{ts,js}
  //   5. ../deploy/witnesses/<stem>-witnesses.{ts,js}    (pattern7a-style)
  // -------------------------------------------------------------------------

  private locateWitnessFile(): string | null {
    if (this.input.witnessFilePathOverride) {
      const abs = resolve(this.input.witnessFilePathOverride);
      return existsSync(abs) ? abs : null;
    }

    const contractDir = dirname(this.input.contractPath);
    const fullStem = basename(this.input.contractPath, '.compact');
    // Some projects name the contract <product>-<variant>.compact but
    // the witness file uses only the product stem (pattern7a-custodial
    // → pattern7a-witnesses). Try the full stem first, then progressively
    // drop hyphen-suffixed segments.
    const stems: string[] = [fullStem];
    let s = fullStem;
    while (s.includes('-')) {
      s = s.replace(/-[^-]+$/, '');
      stems.push(s);
    }

    const dirs = [
      contractDir,
      join(contractDir, 'witnesses'),
      join(contractDir, '..', 'witnesses'),
      join(contractDir, '..', 'deploy', 'witnesses'),
      join(contractDir, '..', '..', 'deploy', 'witnesses'),
      join(contractDir, '..', 'src', 'witnesses'),
    ];
    const exts = ['ts', 'js'];

    // Files in priority order, per directory.
    const fileTemplates = (stem: string) => [
      `${stem}-witnesses`,
      `${stem}.witnesses`,
      `${stem}`,
      `witnesses`,
      `witness`,
    ];

    for (const dir of dirs) {
      for (const stem of stems) {
        for (const tmpl of fileTemplates(stem)) {
          for (const ext of exts) {
            const candidate = join(dir, `${tmpl}.${ext}`);
            try {
              if (existsSync(candidate)) return resolve(candidate);
            } catch { /* ignore */ }
          }
        }
      }
    }
    return null;
  }

  // -------------------------------------------------------------------------
  // Detector 1: constant-return witness.
  // -------------------------------------------------------------------------

  private detectConstantReturnWitnesses(): void {
    if (this.witnessFileText === null || this.witnessFile === null) return;

    // Step 1: collect candidate witness functions from the witness file.
    // We look for object-property style first (common in Compact JS
    // bindings: `{ getCommitmentNonce: (context) => [...] }`), then
    // also for standalone function declarations.
    const witnessFunctions = this.parseWitnessFunctions(this.witnessFileText);

    // Step 2: for each function whose name suggests a nonce role,
    // classify its body.
    for (const wf of witnessFunctions) {
      const nonceRole = NONCE_ROLE_NAME_PATTERNS.some(p => p.test(wf.name));
      if (!nonceRole) continue;

      const hasCsprng = CSPRNG_PATTERNS.some(p => p.test(wf.body));
      if (hasCsprng) continue;

      for (const { pattern, label } of CONSTANT_RETURN_PATTERNS) {
        const match = pattern.exec(wf.body);
        if (!match) continue;

        const sites: NonceSite[] = [
          {
            kind: 'witness-impl',
            file: this.witnessFile,
            line: this.lineOfMatch(this.witnessFileText, wf.bodyStart + match.index),
            snippet: this.snippetAround(this.witnessFileText, wf.bodyStart + match.index, match[0].length),
          },
        ];

        // If we can find the circuit that calls this witness, list it
        // as a co-located site so the reviewer sees both halves.
        const callerCircuits = this.findCircuitsCalling(wf.name);
        for (const circuit of callerCircuits) {
          const callPattern = new RegExp(`\\b${wf.name}\\s*\\(`, 'g');
          const callMatch = callPattern.exec(circuit.body);
          if (callMatch) {
            sites.push({
              kind: 'circuit-call',
              file: this.input.contractPath,
              line: this.lineOfMatch(this.input.contractSource, this.offsetInSource(circuit) + callMatch.index),
              snippet: callMatch[0],
              circuit: circuit.name,
            });
          }
        }

        this.findings.push({
          id: this.makeId('constant-return-witness', wf.name, sites),
          kind: 'constant-return-witness',
          severity: 'critical',
          witnessFunction: wf.name,
          sites,
          evidence: {
            claimFromSource: `${label}. Witness returns the same bytes on every call; downstream commitments and nullifiers derived from it are deterministic.`,
          },
          recommendation: `In ${basename(this.witnessFile)}, replace the constant return with a fresh draw from a CSPRNG (Node: crypto.randomBytes(N); Browser: crypto.getRandomValues(new Uint8Array(N))). The nonce must be sampled per-call and stored in the dApp's private state alongside any receipt the holder needs to reconstruct.`,
          autoDismissible: false,
        });
        break; // one constant-shape finding per witness function
      }
    }
  }

  // -------------------------------------------------------------------------
  // Detector 2: missing counter increment.
  //
  // A ledger field typed `Counter` (or named `*nonce`, `sequence`,
  // `*Counter`) that's read inside a hash but never incremented in any
  // circuit that touches it. Heuristic — increments via `.increment()`
  // and via direct assignment `X = (X + 1) ...` both count.
  // -------------------------------------------------------------------------

  private detectMissingCounterIncrement(): void {
    const counterCandidates = this.input.stateVars.filter(v => {
      if (v.kind !== 'ledger') return false;
      const typeIsCounter = /\bCounter\b/.test(v.type);
      const nameSuggestsNonce =
        /nonce/i.test(v.name) || /sequence/i.test(v.name) ||
        /\bversion\b/i.test(v.name) || /counter/i.test(v.name);
      return typeIsCounter || nameSuggestsNonce;
    });

    for (const field of counterCandidates) {
      const readInHash = this.input.circuits.some(c =>
        this.fieldReadInHash(c.body, field.name));
      if (!readInHash) continue;

      const incremented = this.input.circuits.some(c =>
        this.fieldIncremented(c.body, field.name));
      if (incremented) continue;

      // Build sites: the read locations.
      const sites: NonceSite[] = [];
      for (const circuit of this.input.circuits) {
        const readPattern = new RegExp(
          `(persistentHash|transientHash)\\s*[<(][^;]*\\b${field.name}\\b[^;]*[>)]`,
          'g',
        );
        let m: RegExpExecArray | null;
        while ((m = readPattern.exec(circuit.body)) !== null) {
          sites.push({
            kind: 'circuit-body',
            file: this.input.contractPath,
            line: this.lineOfMatch(
              this.input.contractSource,
              this.offsetInSource(circuit) + m.index,
            ),
            snippet: m[0].length > 120 ? m[0].slice(0, 120) + '…' : m[0],
            circuit: circuit.name,
          });
        }
      }
      if (sites.length === 0) continue;

      // Always include the field declaration site.
      const declOffset = this.input.contractSource.search(
        new RegExp(`\\bledger\\s+${field.name}\\s*:`),
      );
      if (declOffset >= 0) {
        sites.unshift({
          kind: 'ledger-field',
          file: this.input.contractPath,
          line: this.lineOfMatch(this.input.contractSource, declOffset),
          snippet: `ledger ${field.name}: ${field.type};`,
        });
      }

      this.findings.push({
        id: this.makeId('missing-counter-increment', field.name, sites),
        kind: 'missing-counter-increment',
        severity: 'high',
        ledgerField: field.name,
        sites,
        evidence: {
          claimFromSource: `Field "${field.name}" appears in a hash construction but no circuit increments it. The same value enters the hash on every call; downstream commitments/nullifiers are deterministic.`,
        },
        recommendation: `Add an increment of ${field.name} in the circuit(s) that read it before the hash. For a Counter field: \`${field.name}.increment(1);\` or \`${field.name} = (disclose(${field.name}) + 1) as Counter;\` Then the hash mixes a fresh value per call.`,
        autoDismissible: false,
      });
    }
  }

  // -------------------------------------------------------------------------
  // Detector 3: multi-call binding.
  //
  // A Compact witness function can return a different value on each
  // invocation; the runtime memoises within a single proving session,
  // but the compiler doesn't constrain "same witness call always
  // returns the same value here." If a circuit calls the same witness
  // function more than once without binding to a const, the second
  // call can legally return a different value — breaking any invariant
  // the code thought it had.
  //
  // Heuristic: for each witness function declared in the contract,
  // count direct invocations in each circuit body. If more than one
  // invocation appears AND the body doesn't have a const binding for
  // the witness result, flag.
  //
  // False positives: a developer intentionally calling the witness
  // multiple times for fresh values per call (e.g., requesting
  // independent nonces). For such cases use a clear naming convention
  // or different witness functions, or annotate as intentional in a
  // future @audit-ack annotation.
  // -------------------------------------------------------------------------

  private detectMultiCallBinding(): void {
    const witnesses = this.input.stateVars.filter(v => v.kind === 'witness');
    for (const witness of witnesses) {
      for (const circuit of this.input.circuits) {
        const callPattern = new RegExp(`\\b${witness.name}\\s*\\(`, 'g');
        const callMatches = [...circuit.body.matchAll(callPattern)];
        if (callMatches.length < 2) continue;

        // Check whether the witness is bound via const and reused
        // through that binding. If a `const X = witnessName(...)` exists
        // AND every OTHER invocation of witnessName is also in that
        // form (one binding, used multiple times via X), no finding.
        const bindingPattern = new RegExp(`\\bconst\\s+\\w+\\s*=\\s*${witness.name}\\s*\\(`, 'g');
        const bindings = [...circuit.body.matchAll(bindingPattern)];
        // If there's exactly one binding and every call is the bound
        // call, that's safe — the const captures the witness once and
        // reuses it. (Multiple bindings of the same witness fn into
        // different consts is the suspicious case.)
        if (bindings.length === 1 && bindings.length === callMatches.length) continue;

        const sites: NonceSite[] = callMatches.map(m => ({
          kind: 'circuit-call',
          file: this.input.contractPath,
          line: this.lineOfMatch(
            this.input.contractSource,
            this.offsetInSource(circuit) + (m.index ?? 0),
          ),
          snippet: m[0],
          circuit: circuit.name,
        }));

        this.findings.push({
          id: this.makeId('multi-call-binding', witness.name, sites),
          kind: 'multi-call-binding',
          severity: 'medium',
          witnessFunction: witness.name,
          sites,
          evidence: {
            claimFromSource: `Witness "${witness.name}" is called ${callMatches.length} times in circuit "${circuit.name}" without being captured in a single const binding. Witness functions may return different values per invocation; downstream code that assumes equality across calls is unsound.`,
          },
          recommendation: `Bind the witness call to a const at the top of the circuit and reuse the binding: \`const ${witness.name.replace(/[^A-Za-z0-9]/g, '_')}Value = ${witness.name}();\`. If you genuinely want fresh values per call, use distinct witness functions and document the intent.`,
          autoDismissible: false,
        });
      }
    }
  }

  // -------------------------------------------------------------------------
  // Detector 4: hash-without-blinder.
  //
  // A persistentHash that includes only stable identifiers (ledger
  // field values, circuit arguments derived from public data) with no
  // per-event nonce / blinder argument is deterministic per (caller,
  // arguments). The same caller calling twice produces the same hash.
  // For commitment-style uses this defeats hiding (observer can guess
  // the input set and confirm). For anchor / lookup uses this is
  // intentional.
  //
  // The detector is a prompt for review, not a "fix this" — many
  // valid contracts emit deterministic hashes (e.g., persistentHash
  // of a public key for an identity registry). Flagging the
  // construction lets the auditor confirm intent.
  // -------------------------------------------------------------------------

  private detectHashWithoutBlinder(): void {
    const witnessNames = new Set(
      this.input.stateVars.filter(v => v.kind === 'witness').map(v => v.name),
    );
    const nonceNamePatterns = [/nonce/i, /salt/i, /blinder/i, /random/i, /seed/i];

    for (const circuit of this.input.circuits) {
      // Find persistentHash / transientHash invocations with arg tuples.
      // The type parameter can itself contain `<...>` (e.g.,
      // `<[Bytes<32>, Counter]>`), so we allow one level of nesting:
      //   <  (non-<>-chars  |  <non->-chars>)*  >
      // That covers <[Bytes<32>, T]> while still anchored.
      const hashPattern = /(persistentHash|transientHash)\s*<(?:[^<>]|<[^>]*>)*>\s*\(\s*\[([^\]]*)\]\s*\)/g;
      const matches = [...circuit.body.matchAll(hashPattern)];

      for (const m of matches) {
        const argList = m[2];
        // Tokenise on commas (depth-0; nested brackets within args
        // are uncommon for hash inputs and are handled coarsely).
        const args = argList.split(',').map(s => s.trim()).filter(Boolean);
        if (args.length === 0) continue;

        // Does any arg look like a per-event nonce? Either: it's the
        // result of a nonce-named witness call, or its identifier
        // name itself matches a nonce-role pattern.
        const hasBlinder = args.some(arg => {
          if (nonceNamePatterns.some(p => p.test(arg))) return true;
          // arg might be a call expression: witnessName()
          const callMatch = /^([\w$]+)\s*\(/.exec(arg);
          if (callMatch && witnessNames.has(callMatch[1])
              && nonceNamePatterns.some(p => p.test(callMatch[1]))) {
            return true;
          }
          return false;
        });
        if (hasBlinder) continue;

        // No blinder found. Skip if every arg is itself a constant
        // (literal numbers / pad() / fixed bytes) — those hashes are
        // just compile-time anchors and the lack of blinder is fine.
        const allLiteral = args.every(arg =>
          /^(\d+|0x[0-9a-f]+|'[^']*'|pad\s*\(|default)/i.test(arg));
        if (allLiteral) continue;

        const offset = this.offsetInSource(circuit) + (m.index ?? 0);
        const line = this.lineOfMatch(this.input.contractSource, offset);
        const sites: NonceSite[] = [{
          kind: 'circuit-body',
          file: this.input.contractPath,
          line,
          snippet: m[0].length > 120 ? m[0].slice(0, 120) + '…' : m[0],
          circuit: circuit.name,
        }];

        this.findings.push({
          id: this.makeId('hash-without-blinder', m[0], sites),
          kind: 'hash-without-blinder',
          severity: 'low',
          sites,
          evidence: {
            claimFromSource: `Circuit "${circuit.name}" computes a ${m[1]} over (${args.join(', ')}) with no per-event nonce/salt/blinder argument. The same input set produces the same hash on every call.`,
          },
          recommendation: `If this hash is intended as a commitment (hiding the inputs from observers), add a per-event blinder: pass a nonce as an additional hash argument and persist it for later opening. If this hash is intentionally deterministic (identity anchor, lookup key, dedupe key), document the intent — a future \`// @disclose-intent: protocol-required\` annotation will downgrade this finding.`,
          autoDismissible: false,
        });
      }
    }
  }

  // -------------------------------------------------------------------------
  // Helpers.
  // -------------------------------------------------------------------------

  /**
   * Parse witness functions from a JS/TS file. Returns name + body text
   * + offset of the body within the file.
   *
   * We don't have a real JS parser; instead we walk the file line-by-line,
   * detect a witness-shaped declaration, and capture the body greedily
   * from the `=>` (or opening `{`) to a heuristic terminator. Bodies
   * commonly contain commas inside arrays/calls; a regex with a comma
   * terminator (the previous implementation) truncated those.
   *
   * Patterns detected:
   *   1. Property arrow:   name: (params) => expr           (single-line)
   *   2. Property method:  name(params) { ... }
   *   3. Function decl:    function name(params) { ... }
   *   4. Const arrow:      const name = (params) => expr;
   */
  private parseWitnessFunctions(text: string): Array<{ name: string; body: string; bodyStart: number }> {
    const results: Array<{ name: string; body: string; bodyStart: number }> = [];
    const lines = text.split('\n');
    let cumulativeOffset = 0;

    for (const line of lines) {
      // Pattern 1: property arrow on a single line.
      //   name: (params) => <rest-of-line>
      const arrowProp = /(\w+)\s*:\s*\([^)]*\)\s*=>\s*(.+?)\s*,?\s*$/;
      const arrowMatch = arrowProp.exec(line);
      if (arrowMatch) {
        const bodyOffsetInLine = line.indexOf(arrowMatch[2]);
        results.push({
          name: arrowMatch[1],
          body: arrowMatch[2],
          bodyStart: cumulativeOffset + bodyOffsetInLine,
        });
      }

      // Pattern 4: const arrow on a single line.
      const constArrow = /^\s*(?:const|let|var)\s+(\w+)\s*=\s*\([^)]*\)\s*=>\s*(.+?)\s*;?\s*$/;
      const constMatch = constArrow.exec(line);
      if (constMatch) {
        const bodyOffsetInLine = line.indexOf(constMatch[2]);
        results.push({
          name: constMatch[1],
          body: constMatch[2],
          bodyStart: cumulativeOffset + bodyOffsetInLine,
        });
      }

      cumulativeOffset += line.length + 1; // +1 for newline
    }

    // Patterns 2 & 3 use multi-line bodies; capture via balanced-brace
    // matching on the full text. We allow up to one level of nesting in
    // the regex (sufficient for typical witness implementations).
    const methodProp = /(\w+)\s*\(([^)]*)\)\s*(\{(?:[^{}]|\{[^{}]*\})*\})/g;
    let m: RegExpExecArray | null;
    while ((m = methodProp.exec(text)) !== null) {
      // Skip arrow-fn matches with the same name to avoid double-counting.
      if (results.some(r => r.name === m![1])) continue;
      results.push({
        name: m[1],
        body: m[3],
        bodyStart: m.index + m[0].indexOf(m[3]),
      });
    }

    const fnDecl = /function\s+(\w+)\s*\([^)]*\)\s*(\{(?:[^{}]|\{[^{}]*\})*\})/g;
    while ((m = fnDecl.exec(text)) !== null) {
      results.push({
        name: m[1],
        body: m[2],
        bodyStart: m.index + m[0].indexOf(m[2]),
      });
    }

    return results;
  }

  private findCircuitsCalling(witnessName: string): CircuitForNonce[] {
    const pattern = new RegExp(`\\b${witnessName}\\s*\\(`);
    return this.input.circuits.filter(c => pattern.test(c.body));
  }

  private fieldReadInHash(body: string, fieldName: string): boolean {
    const pattern = new RegExp(
      `(persistentHash|transientHash)\\s*[<(][^;]*\\b${fieldName}\\b`,
    );
    return pattern.test(body);
  }

  private fieldIncremented(body: string, fieldName: string): boolean {
    // ADT method
    if (new RegExp(`\\b${fieldName}\\.increment\\s*\\(`).test(body)) return true;
    // Direct assignment increment: `name = (... + 1) as ...` or
    // `name = name + 1` etc. Conservative — requires the field to
    // appear on both sides of `=` with a `+`.
    const assignPattern = new RegExp(
      `\\b${fieldName}\\s*=\\s*[^;]*\\b${fieldName}\\b[^;]*\\+\\s*\\d`,
    );
    return assignPattern.test(body);
  }

  private lineOfMatch(text: string, offset: number): number {
    return text.slice(0, offset).split('\n').length;
  }

  private snippetAround(text: string, offset: number, len: number): string {
    const start = Math.max(0, offset - 0);
    const end = Math.min(text.length, offset + len);
    return text.slice(start, end).replace(/\s+/g, ' ').trim();
  }

  private offsetInSource(circuit: CircuitForNonce): number {
    const pattern = new RegExp(`circuit\\s+${circuit.name}\\b`);
    const m = pattern.exec(this.input.contractSource);
    return m ? m.index : 0;
  }

  private makeId(kind: NonceFindingKind, subject: string, sites: NonceSite[]): string {
    const siteKey = sites
      .map(s => `${s.file}:${s.line ?? '0'}:${s.kind}`)
      .sort()
      .join('|');
    const h = createHash('sha256');
    h.update(`${kind}|${subject}|${siteKey}`);
    return `nonce-${h.digest('hex').slice(0, 12)}`;
  }
}
