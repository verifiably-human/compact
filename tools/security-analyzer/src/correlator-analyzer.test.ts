import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { CorrelatorAnalyzer } from './correlator-analyzer.js';
import type { CompilerSecurityAnalysis } from './compiler-security-reader.js';

const mkAnalysis = (disclosures: any[]): CompilerSecurityAnalysis => ({
  schema_version: '1.0.0',
  status: 'clean',
  witness_count: 1,
  leaks: [],
  disclosures,
});

const mkCircuits = (...names: Array<[string, number, number]>) =>
  names.map(([name, s, e]) => ({ name, bodyStartLine: s, bodyEndLine: e }));

describe('CorrelatorAnalyzer', () => {
  it('emits no finding when only one circuit discloses an origin', () => {
    const analysis = mkAnalysis([
      {
        location: { file: '/c.compact', line: 10, column: 5 },
        witnesses: [{
          origin: { kind: 'witness-return-value', function: 'secret', location: { file: '/c.compact', line: 1, column: 1 } },
          paths: [{ points: [], final_exposure: 'the witness value' }],
        }],
      },
    ]);
    const result = new CorrelatorAnalyzer({
      compilerAnalysis: analysis,
      annotations: new Map(),
      circuits: mkCircuits(['foo', 5, 30]),
    }).analyze();
    assert.equal(result.findings.length, 0);
  });

  it('emits a finding when the same witness origin spans two circuits', () => {
    const analysis = mkAnalysis([
      {
        location: { file: '/c.compact', line: 10, column: 5 },
        witnesses: [{
          origin: { kind: 'witness-return-value', function: 'secret', location: { file: '/c.compact', line: 1, column: 1 } },
          paths: [{ points: [], final_exposure: 'the witness value' }],
        }],
      },
      {
        location: { file: '/c.compact', line: 50, column: 5 },
        witnesses: [{
          origin: { kind: 'witness-return-value', function: 'secret', location: { file: '/c.compact', line: 1, column: 1 } },
          paths: [{ points: [], final_exposure: 'the witness value' }],
        }],
      },
    ]);
    const result = new CorrelatorAnalyzer({
      compilerAnalysis: analysis,
      annotations: new Map(),
      circuits: mkCircuits(['foo', 5, 30], ['bar', 40, 70]),
    }).analyze();
    assert.equal(result.findings.length, 1);
    const f = result.findings[0];
    assert.equal(f.witnessOrigin.kind, 'witness-return-value');
    assert.equal(f.witnessOrigin.function, 'secret');
    assert.equal(f.linkedDisclosureSites.length, 2);
    assert.equal(f.exposureStructure.blinderPresent, false);
  });

  it('downgrades to info when a path includes a blinder', () => {
    const analysis = mkAnalysis([
      {
        location: { file: '/c.compact', line: 10, column: 5 },
        witnesses: [{
          origin: { kind: 'witness-return-value', function: 'secret', location: { file: '/c.compact', line: 1, column: 1 } },
          paths: [{
            points: [
              { description: 'the binding of nonce', location: { file: '/c.compact', line: 8, column: 1 }, exposure: null },
            ],
            final_exposure: 'a hash of the witness value',
          }],
        }],
      },
      {
        location: { file: '/c.compact', line: 50, column: 5 },
        witnesses: [{
          origin: { kind: 'witness-return-value', function: 'secret', location: { file: '/c.compact', line: 1, column: 1 } },
          paths: [{
            points: [
              { description: 'the binding of nonce', location: { file: '/c.compact', line: 48, column: 1 }, exposure: null },
            ],
            final_exposure: 'a hash of the witness value',
          }],
        }],
      },
    ]);
    const result = new CorrelatorAnalyzer({
      compilerAnalysis: analysis,
      annotations: new Map(),
      circuits: mkCircuits(['foo', 5, 30], ['bar', 40, 70]),
    }).analyze();
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].exposureStructure.blinderPresent, true);
    assert.equal(result.findings[0].severity, 'info');
  });

  it('downgrades to info when @disclose-intent is set on any involved circuit', () => {
    const analysis = mkAnalysis([
      {
        location: { file: '/c.compact', line: 10, column: 5 },
        witnesses: [{
          origin: { kind: 'witness-return-value', function: 'secret', location: { file: '/c.compact', line: 1, column: 1 } },
          paths: [{ points: [], final_exposure: 'the witness value' }],
        }],
      },
      {
        location: { file: '/c.compact', line: 50, column: 5 },
        witnesses: [{
          origin: { kind: 'witness-return-value', function: 'secret', location: { file: '/c.compact', line: 1, column: 1 } },
          paths: [{ points: [], final_exposure: 'the witness value' }],
        }],
      },
    ]);
    const annotations = new Map();
    annotations.set('foo', [{
      key: 'disclose-intent',
      tag: 'intentional-correlator',
      reason: 'regulator anchor',
      line: 4,
      tagKnown: true,
    }]);
    const result = new CorrelatorAnalyzer({
      compilerAnalysis: analysis,
      annotations,
      circuits: mkCircuits(['foo', 5, 30], ['bar', 40, 70]),
    }).analyze();
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].severity, 'info');
    assert.equal(result.findings[0].intentCheck.annotationPresent, true);
    assert.equal(result.findings[0].intentCheck.annotationTag, 'intentional-correlator');
  });

  it('produces stable IDs for the same input', () => {
    const analysis = mkAnalysis([
      {
        location: { file: '/c.compact', line: 10, column: 5 },
        witnesses: [{
          origin: { kind: 'witness-return-value', function: 'secret', location: { file: '/c.compact', line: 1, column: 1 } },
          paths: [{ points: [], final_exposure: 'the witness value' }],
        }],
      },
      {
        location: { file: '/c.compact', line: 50, column: 5 },
        witnesses: [{
          origin: { kind: 'witness-return-value', function: 'secret', location: { file: '/c.compact', line: 1, column: 1 } },
          paths: [{ points: [], final_exposure: 'the witness value' }],
        }],
      },
    ]);
    const circuits = mkCircuits(['foo', 5, 30], ['bar', 40, 70]);
    const r1 = new CorrelatorAnalyzer({ compilerAnalysis: analysis, annotations: new Map(), circuits }).analyze();
    const r2 = new CorrelatorAnalyzer({ compilerAnalysis: analysis, annotations: new Map(), circuits }).analyze();
    assert.equal(r1.findings[0]?.id, r2.findings[0]?.id);
    assert.match(r1.findings[0]?.id ?? '', /^corr-[0-9a-f]{12}$/);
  });
});
