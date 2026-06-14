import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { buildSarifLog, serialiseSarifLog } from './sarif.js';
import type { AnalysisResult } from './types.js';
import type { SecurityFinding } from './security-analyzer.js';

const baseSec = (over: Partial<SecurityFinding> = {}): SecurityFinding => ({
  id: 'sec-aaaaaaaaaaaa',
  type: 'access-control',
  severity: 'high',
  title: 'Missing authorization check: transfer',
  description: 'Anyone can call this.',
  recommendation: 'Add a guard.',
  impact: 'Funds can be moved by any caller.',
  location: { circuit: 'transfer', line: 42 },
  ...over,
});

const baseResult = (sec: SecurityFinding[] = []): AnalysisResult => ({
  contractFile: '/abs/path/to/MyContract.compact',
  circuits: [],
  totalConstraints: 0,
  compilationTime: 0,
  timestamp: '2026-06-13T12:00:00Z',
  security: {
    findings: sec,
    riskScore: 0,
    summary: { critical: 0, high: sec.length, medium: 0, low: 0, info: 0 },
  },
});

describe('buildSarifLog', () => {
  it('produces a SARIF 2.1.0 envelope', () => {
    const log = buildSarifLog({ result: baseResult(), toolVersion: '1.0.0', contractUri: 'MyContract.compact' });
    assert.equal(log.version, '2.1.0');
    assert.equal(log.runs.length, 1);
    assert.equal(log.runs[0].tool.driver.name, 'security-analyzer');
  });

  it('lists every defined rule, not only ones that fired', () => {
    const log = buildSarifLog({ result: baseResult(), toolVersion: '1.0.0', contractUri: 'MyContract.compact' });
    const ids = log.runs[0].tool.driver.rules.map(r => r.id);
    // Sanity: we expect at least the access-control, privacy-leak, nonce:* family
    assert.ok(ids.includes('access-control:missing'));
    assert.ok(ids.includes('access-control:disabled'));
    assert.ok(ids.includes('privacy-leak'));
    assert.ok(ids.includes('nonce:constant-return-witness'));
    assert.ok(ids.includes('correlator:cross-circuit'));
    assert.ok(log.runs[0].tool.driver.rules.length >= 10);
  });

  it('maps a high-severity access-control finding to level=error with correct ruleId', () => {
    const log = buildSarifLog({
      result: baseResult([baseSec()]),
      toolVersion: '1.0.0',
      contractUri: 'MyContract.compact',
    });
    const r = log.runs[0].results[0];
    assert.equal(r.ruleId, 'access-control:missing');
    assert.equal(r.level, 'error');
    assert.equal(r.locations[0].physicalLocation.region?.startLine, 42);
  });

  it('maps medium severity to warning, info/low to note', () => {
    const log = buildSarifLog({
      result: baseResult([
        baseSec({ id: 'sec-mediummmmmmm', severity: 'medium' }),
        baseSec({ id: 'sec-infonnnnnnnn', severity: 'info' }),
        baseSec({ id: 'sec-lownnnnnnnnn', severity: 'low' }),
      ]),
      toolVersion: '1.0.0',
      contractUri: 'MyContract.compact',
    });
    const levels = log.runs[0].results.map(r => r.level);
    assert.deepEqual(levels, ['warning', 'note', 'note']);
  });

  it('mirrors the finding id into partialFingerprints', () => {
    const log = buildSarifLog({
      result: baseResult([baseSec()]),
      toolVersion: '1.0.0',
      contractUri: 'MyContract.compact',
    });
    const r = log.runs[0].results[0];
    assert.equal(r.partialFingerprints?.['stableId/v1'], 'sec-aaaaaaaaaaaa');
  });

  it('emits a suppressions entry when the finding is acked', () => {
    const acked = baseSec({
      ack: {
        source: 'baseline-file',
        by: 'alice@example.com',
        at: '2026-04-15T09:12:00Z',
        reason: 'Intentionally permissionless',
      },
    });
    const log = buildSarifLog({
      result: baseResult([acked]),
      toolVersion: '1.0.0',
      contractUri: 'MyContract.compact',
    });
    const r = log.runs[0].results[0];
    assert.ok(r.suppressions);
    assert.equal(r.suppressions![0].kind, 'external');
    assert.match(r.suppressions![0].justification ?? '', /Intentionally permissionless/);
  });

  it('marks inline-annotation acks with kind=inSource', () => {
    const acked = baseSec({
      ack: {
        source: 'inline-annotation',
        by: 'inline-annotation',
        at: '2026-04-15T09:12:00Z',
        reason: 'Per @audit-ack comment',
      },
    });
    const log = buildSarifLog({
      result: baseResult([acked]),
      toolVersion: '1.0.0',
      contractUri: 'MyContract.compact',
    });
    assert.equal(log.runs[0].results[0].suppressions?.[0].kind, 'inSource');
  });

  it('serialiseSarifLog produces parseable JSON', () => {
    const log = buildSarifLog({
      result: baseResult([baseSec()]),
      toolVersion: '1.0.0',
      contractUri: 'MyContract.compact',
    });
    const text = serialiseSarifLog(log);
    const parsed = JSON.parse(text);
    assert.equal(parsed.version, '2.1.0');
    assert.equal(parsed.runs[0].results.length, 1);
  });

  it('produces an empty results array (not an error) when there are no findings', () => {
    const log = buildSarifLog({ result: baseResult(), toolVersion: '1.0.0', contractUri: 'MyContract.compact' });
    assert.equal(log.runs[0].results.length, 0);
  });
});
