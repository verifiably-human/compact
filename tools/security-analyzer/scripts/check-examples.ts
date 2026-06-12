/**
 * Acceptance check for the COIP "Machine-readable security-analysis output"
 * (v1.0.0).
 *
 * For every `.compact` file under examples/:
 *   1. Compile with `--skip-zk` to a temp directory.
 *   2. If compilation succeeded:
 *        - Assert `compiler/security-analysis.json` exists.
 *        - Validate it against schema/security-analysis.v1.json.
 *   3. If compilation failed:
 *        - Record as a negative case (expected for examples/errors, /bugs,
 *          /wpp, etc.). Assert no JSON was written.
 *
 * Exit code: 0 if all positive cases pass; 1 otherwise.
 *
 * Usage:
 *   tsx scripts/check-examples.ts [--examples <dir>] [--compiler <path>]
 *                                 [--concurrency N] [--limit N] [--verbose]
 *
 * Defaults assume this script runs from inside `tools/security-analyzer/` in
 * the compact-coip-security repo.
 */

import { spawn } from 'node:child_process';
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from 'node:fs';
import { cpus, tmpdir } from 'node:os';
import {
  dirname,
  join,
  relative,
  resolve,
} from 'node:path';
import { fileURLToPath } from 'node:url';
import { readdir } from 'node:fs/promises';

import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

interface Args {
  examplesDir: string;
  compiler: string;
  concurrency: number;
  limit: number;
  verbose: boolean;
}

function parseArgs(): Args {
  const here = dirname(fileURLToPath(import.meta.url));
  const repoRoot = resolve(here, '..', '..', '..');
  const defaults: Args = {
    examplesDir: join(repoRoot, 'examples'),
    compiler: join(repoRoot, 'result', 'bin', 'compactc'),
    concurrency: Math.max(2, Math.min(8, cpus().length - 2)),
    limit: 0,
    verbose: false,
  };
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '--examples': defaults.examplesDir = resolve(argv[++i]); break;
      case '--compiler': defaults.compiler = resolve(argv[++i]); break;
      case '--concurrency': defaults.concurrency = Number(argv[++i]); break;
      case '--limit': defaults.limit = Number(argv[++i]); break;
      case '--verbose': case '-v': defaults.verbose = true; break;
      case '--help': case '-h':
        console.log(__doc__);
        process.exit(0);
      default:
        console.error(`unknown flag: ${a}`);
        process.exit(2);
    }
  }
  return defaults;
}

const __doc__ = `\
Compile every examples/*.compact and verify the COIP security-analysis.json
contract.

Flags:
  --examples DIR     Override examples directory.
  --compiler PATH    Override compactc binary path.
  --concurrency N    Parallel compiles (default: cores-2, clamped to [2,8]).
  --limit N          Stop after N files (debug aid).
  --verbose, -v      Per-file detail.
`;

// ---------------------------------------------------------------------------
// Schema validator
// ---------------------------------------------------------------------------

function loadValidator() {
  const here = dirname(fileURLToPath(import.meta.url));
  const schemaPath = resolve(here, '..', 'schema', 'security-analysis.v1.json');
  const schema = JSON.parse(readFileSync(schemaPath, 'utf8'));
  const ajv = new (Ajv2020 as unknown as typeof Ajv2020.default)({ allErrors: true, strict: false });
  (addFormats as unknown as { default: (a: unknown) => void }).default(ajv);
  return ajv.compile(schema);
}

// ---------------------------------------------------------------------------
// File discovery
// ---------------------------------------------------------------------------

async function findCompactFiles(root: string): Promise<string[]> {
  const out: string[] = [];
  async function walk(dir: string) {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const e of entries) {
      const p = join(dir, e.name);
      if (e.isDirectory()) await walk(p);
      else if (e.isFile() && e.name.endsWith('.compact')) out.push(p);
    }
  }
  await walk(root);
  out.sort();
  return out;
}

// ---------------------------------------------------------------------------
// Compile + verify one file
// ---------------------------------------------------------------------------

type Verdict =
  | { kind: 'pass'; file: string }
  | { kind: 'fail'; file: string; reason: string; detail?: string }
  | { kind: 'negative'; file: string }
  | { kind: 'error'; file: string; reason: string };

async function checkOne(
  compiler: string,
  contract: string,
  validate: (data: unknown) => boolean,
  validatorErrors: () => string,
): Promise<Verdict> {
  const outDir = mkdtempSync(join(tmpdir(), 'sec-acc-'));
  try {
    const { code, stderr } = await runCompile(compiler, contract, outDir);
    const jsonPath = join(outDir, 'compiler', 'security-analysis.json');

    if (code !== 0) {
      if (existsSync(jsonPath)) {
        return {
          kind: 'fail',
          file: contract,
          reason: 'failed compile left security-analysis.json on disk',
        };
      }
      return { kind: 'negative', file: contract };
    }

    if (!existsSync(jsonPath)) {
      return {
        kind: 'fail',
        file: contract,
        reason: 'successful compile did not emit security-analysis.json',
        detail: stderr.slice(0, 400),
      };
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(jsonPath, 'utf8'));
    } catch (err) {
      return {
        kind: 'fail',
        file: contract,
        reason: 'security-analysis.json is not valid JSON',
        detail: err instanceof Error ? err.message : String(err),
      };
    }

    if (!validate(parsed)) {
      return {
        kind: 'fail',
        file: contract,
        reason: 'security-analysis.json failed schema validation',
        detail: validatorErrors(),
      };
    }

    return { kind: 'pass', file: contract };
  } catch (err) {
    return {
      kind: 'error',
      file: contract,
      reason: err instanceof Error ? err.message : String(err),
    };
  } finally {
    rmSync(outDir, { recursive: true, force: true });
  }
}

function runCompile(
  compiler: string,
  contract: string,
  outDir: string,
): Promise<{ code: number; stderr: string }> {
  return new Promise((res) => {
    const child = spawn(compiler, ['--skip-zk', contract, outDir], {
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    let stderr = '';
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    const killer = setTimeout(() => {
      child.kill('SIGKILL');
    }, 60_000);
    child.on('close', (code) => {
      clearTimeout(killer);
      res({ code: code ?? -1, stderr });
    });
    child.on('error', (err) => {
      clearTimeout(killer);
      res({ code: -1, stderr: String(err) });
    });
  });
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

async function runPool<T, R>(
  items: T[],
  width: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: width }, async () => {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return results;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const args = parseArgs();

  if (!existsSync(args.compiler)) {
    console.error(`compiler not found at ${args.compiler}`);
    console.error('build the compiler (e.g. via nix) and pass --compiler, or symlink it into result/bin/');
    process.exit(2);
  }
  if (!existsSync(args.examplesDir)) {
    console.error(`examples dir not found at ${args.examplesDir}`);
    process.exit(2);
  }

  const validator = loadValidator();
  const validateFn = (data: unknown) => validator(data) === true;
  const errorsFn = () =>
    (validator.errors ?? [])
      .map((e) => `${e.instancePath || '/'} ${e.message ?? ''}`)
      .join('\n');

  let files = await findCompactFiles(args.examplesDir);
  if (args.limit > 0) files = files.slice(0, args.limit);

  console.log(
    `\nCOIP v1.0.0 acceptance check`
    + `\n  compiler: ${args.compiler}`
    + `\n  examples: ${args.examplesDir}`
    + `\n  files:    ${files.length}`
    + `\n  workers:  ${args.concurrency}\n`,
  );

  const start = Date.now();
  let done = 0;
  const verdicts = await runPool(files, args.concurrency, async (f) => {
    const v = await checkOne(args.compiler, f, validateFn, errorsFn);
    done++;
    if (args.verbose || v.kind === 'fail' || v.kind === 'error') {
      const tag = {
        pass: 'PASS', fail: 'FAIL', negative: 'NEG ', error: 'ERR ',
      }[v.kind];
      const rel = relative(args.examplesDir, f);
      const extra = 'reason' in v ? `  — ${v.reason}` : '';
      console.log(`  [${done}/${files.length}] ${tag}  ${rel}${extra}`);
      if (v.kind === 'fail' && v.detail) {
        console.log(`        detail: ${v.detail.split('\n').join('\n        ')}`);
      }
    } else if (done % 25 === 0) {
      console.log(`  ... ${done}/${files.length}`);
    }
    return v;
  });

  const elapsed = ((Date.now() - start) / 1000).toFixed(1);

  const pass = verdicts.filter((v) => v.kind === 'pass');
  const fail = verdicts.filter((v) => v.kind === 'fail');
  const neg = verdicts.filter((v) => v.kind === 'negative');
  const err = verdicts.filter((v) => v.kind === 'error');

  console.log(
    `\nResults (${elapsed}s):`
    + `\n  PASS     ${pass.length}  (successful compile + valid JSON)`
    + `\n  NEG      ${neg.length}  (compile failed; no JSON expected)`
    + `\n  FAIL     ${fail.length}  (positive case that failed acceptance)`
    + `\n  ERROR    ${err.length}  (script-level error)`,
  );

  if (fail.length > 0) {
    console.log('\nFailing files:');
    for (const v of fail) {
      console.log(`  - ${relative(args.examplesDir, v.file)}: ${(v as any).reason}`);
    }
  }
  if (err.length > 0) {
    console.log('\nScript errors:');
    for (const v of err) {
      console.log(`  - ${relative(args.examplesDir, v.file)}: ${(v as any).reason}`);
    }
  }

  process.exit(fail.length === 0 && err.length === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(2);
});
