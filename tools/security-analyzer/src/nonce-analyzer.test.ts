import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { NonceAnalyzer } from './nonce-analyzer.js';

const withTempDir = (fn: (dir: string) => void) => {
  const dir = mkdtempSync(join(tmpdir(), 'nonce-test-'));
  try {
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
};

const mkInput = (overrides: {
  contractSource?: string;
  contractPath?: string;
  circuits?: any[];
  stateVars?: any[];
  witnessFilePathOverride?: string;
}) => ({
  contractSource: overrides.contractSource ?? '',
  contractPath: overrides.contractPath ?? '/tmp/test.compact',
  circuits: overrides.circuits ?? [],
  stateVars: overrides.stateVars ?? [],
  witnessFilePathOverride: overrides.witnessFilePathOverride,
});

describe('NonceAnalyzer.constant-return-witness', () => {
  it('flags new Uint8Array(32) in a nonce-role witness', () => {
    withTempDir(dir => {
      const witnessFile = join(dir, 'witness.js');
      writeFileSync(witnessFile, `
        export default function makeWitnesses() {
          return {
            getCommitmentNonce: (ctx) => [ctx.privateState, new Uint8Array(32)],
          };
        }
      `);
      const result = new NonceAnalyzer(mkInput({
        contractPath: join(dir, 'foo.compact'),
        witnessFilePathOverride: witnessFile,
      })).analyze();
      const finding = result.findings.find(f => f.kind === 'constant-return-witness');
      assert.ok(finding, 'expected a constant-return-witness finding');
      assert.equal(finding.witnessFunction, 'getCommitmentNonce');
      assert.equal(finding.severity, 'critical');
    });
  });

  it('does NOT flag when CSPRNG is present alongside constant', () => {
    withTempDir(dir => {
      const witnessFile = join(dir, 'witness.js');
      writeFileSync(witnessFile, `
        export default function makeWitnesses() {
          return {
            getCommitmentNonce: (ctx) => [ctx.privateState, crypto.randomBytes(32)],
          };
        }
      `);
      const result = new NonceAnalyzer(mkInput({
        contractPath: join(dir, 'foo.compact'),
        witnessFilePathOverride: witnessFile,
      })).analyze();
      const finding = result.findings.find(f => f.kind === 'constant-return-witness');
      assert.equal(finding, undefined);
    });
  });

  it('does NOT flag a non-nonce-named witness with a constant return', () => {
    withTempDir(dir => {
      const witnessFile = join(dir, 'witness.js');
      writeFileSync(witnessFile, `
        export default function makeWitnesses() {
          return {
            getKYCLevel: (ctx) => [ctx.privateState, new Uint8Array(32)],
          };
        }
      `);
      const result = new NonceAnalyzer(mkInput({
        contractPath: join(dir, 'foo.compact'),
        witnessFilePathOverride: witnessFile,
      })).analyze();
      const finding = result.findings.find(f => f.kind === 'constant-return-witness');
      assert.equal(finding, undefined);
    });
  });

  it('flags Buffer.alloc(32) as constant', () => {
    withTempDir(dir => {
      const witnessFile = join(dir, 'witness.js');
      writeFileSync(witnessFile, `
        export default function makeWitnesses() {
          return {
            getNonce: (ctx) => [ctx.privateState, Buffer.alloc(32)],
          };
        }
      `);
      const result = new NonceAnalyzer(mkInput({
        contractPath: join(dir, 'foo.compact'),
        witnessFilePathOverride: witnessFile,
      })).analyze();
      const finding = result.findings.find(f => f.kind === 'constant-return-witness');
      assert.ok(finding);
    });
  });

  it('sets witnessFileSkipped=true when witness file is not found', () => {
    const result = new NonceAnalyzer(mkInput({
      contractPath: '/nonexistent/path/foo.compact',
    })).analyze();
    assert.equal(result.witnessFile, null);
    assert.equal(result.witnessFileSkipped, true);
  });

  it('finding ID is stable across runs given identical input', () => {
    withTempDir(dir => {
      const witnessFile = join(dir, 'witness.js');
      writeFileSync(witnessFile, `
        export default function makeWitnesses() {
          return {
            getRandomNonce: (ctx) => [ctx.privateState, new Uint8Array(32)],
          };
        }
      `);
      const r1 = new NonceAnalyzer(mkInput({
        contractPath: join(dir, 'foo.compact'),
        witnessFilePathOverride: witnessFile,
      })).analyze();
      const r2 = new NonceAnalyzer(mkInput({
        contractPath: join(dir, 'foo.compact'),
        witnessFilePathOverride: witnessFile,
      })).analyze();
      assert.equal(r1.findings[0]?.id, r2.findings[0]?.id);
      assert.match(r1.findings[0]?.id ?? '', /^nonce-[0-9a-f]{12}$/);
    });
  });
});

describe('NonceAnalyzer.missing-counter-increment', () => {
  it('flags a Counter field hashed without an increment', () => {
    const result = new NonceAnalyzer(mkInput({
      contractSource: [
        'ledger nonceCounter: Counter;',
        'circuit foo(): [] {',
        '  const h = persistentHash<[Counter]>([nonceCounter]);',
        '  X = disclose(h);',
        '}',
      ].join('\n'),
      stateVars: [{ name: 'nonceCounter', type: 'Counter', kind: 'ledger' }],
      circuits: [{
        name: 'foo',
        body: 'const h = persistentHash<[Counter]>([nonceCounter]); X = disclose(h);',
        isExported: true,
      }],
    })).analyze();
    const finding = result.findings.find(f => f.kind === 'missing-counter-increment');
    assert.ok(finding, 'expected a missing-counter-increment finding');
    assert.equal(finding.ledgerField, 'nonceCounter');
    assert.equal(finding.severity, 'high');
  });

  it('does NOT flag when the field is .increment()ed', () => {
    const result = new NonceAnalyzer(mkInput({
      stateVars: [{ name: 'seqCounter', type: 'Counter', kind: 'ledger' }],
      circuits: [{
        name: 'foo',
        body: 'seqCounter.increment(1); const h = persistentHash<[Counter]>([seqCounter]);',
        isExported: true,
      }],
    })).analyze();
    const finding = result.findings.find(f => f.kind === 'missing-counter-increment');
    assert.equal(finding, undefined);
  });

  it('does NOT flag when the field is incremented via assignment', () => {
    const result = new NonceAnalyzer(mkInput({
      stateVars: [{ name: 'counter', type: 'Counter', kind: 'ledger' }],
      circuits: [{
        name: 'foo',
        body: [
          'const h = persistentHash<[Counter]>([counter]);',
          'counter = (disclose(counter) + 1) as Counter;',
        ].join('\n'),
        isExported: true,
      }],
    })).analyze();
    const finding = result.findings.find(f => f.kind === 'missing-counter-increment');
    assert.equal(finding, undefined);
  });
});

describe('NonceAnalyzer witness-file auto-detection', () => {
  it('finds witnesses.js in the same directory as the contract', () => {
    withTempDir(dir => {
      const contractPath = join(dir, 'foo.compact');
      const witnessFile = join(dir, 'witnesses.js');
      writeFileSync(contractPath, '// contract');
      writeFileSync(witnessFile, `
        export default function makeWitnesses() {
          return {
            getNonce: (ctx) => [ctx.privateState, new Uint8Array(32)],
          };
        }
      `);
      const result = new NonceAnalyzer(mkInput({ contractPath })).analyze();
      assert.equal(result.witnessFile, witnessFile);
      assert.equal(result.witnessFileSkipped, false);
    });
  });

  it('finds witness file via base-stem fallback', () => {
    withTempDir(dir => {
      const contractPath = join(dir, 'pattern7a-custodial.compact');
      const deployDir = join(dir, '..', 'deploy', 'witnesses');
      mkdirSync(deployDir, { recursive: true });
      const witnessFile = join(deployDir, 'pattern7a-witnesses.js');
      writeFileSync(contractPath, '// contract');
      writeFileSync(witnessFile, `
        export default function makeWitnesses() {
          return {
            getNonce: (ctx) => [ctx.privateState, new Uint8Array(32)],
          };
        }
      `);
      const result = new NonceAnalyzer(mkInput({ contractPath })).analyze();
      assert.ok(
        result.witnessFile && result.witnessFile.endsWith('pattern7a-witnesses.js'),
        `expected pattern7a-witnesses.js to be found, got ${result.witnessFile}`,
      );
      rmSync(deployDir, { recursive: true, force: true });
    });
  });
});
