import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  validateBaseline,
  applyBaseline,
  inlineAnnotationAcks,
  generateBaseline,
  type AckEntry,
  type BaselineFile,
} from './baseline.js';
import type { SecurityFinding } from './security-analyzer.js';

const f = (id: string, severity: 'critical' | 'high' | 'medium' | 'low' | 'info', overrides: Partial<SecurityFinding> = {}): SecurityFinding => ({
  id,
  type: 'access-control',
  severity,
  title: `Missing authorization check: x${id.slice(-2)}`,
  description: '',
  recommendation: '',
  impact: '',
  ...overrides,
});

const ackEntry = (id: string, overrides: Partial<AckEntry> = {}): AckEntry => ({
  id,
  rule: undefined,
  severity_at_time_of_ack: 'high',
  title: 'placeholder',
  ack_by: 'alice@example.com',
  ack_at: '2026-04-15T09:12:00Z',
  ack_reason: 'reviewed; acceptable',
  ack_expires_at: null,
  ...overrides,
});

describe('validateBaseline', () => {
  it('accepts a well-formed minimal baseline', () => {
    const r = validateBaseline({
      schema_version: '1.0.0',
      generated_by: 'test',
      generated_at: '2026-04-15T09:12:00Z',
      acks: [
        {
          id: 'sec-000000000001',
          severity_at_time_of_ack: 'high',
          title: 'x',
          ack_by: 'alice',
          ack_at: '2026-04-15T09:12:00Z',
          ack_reason: 'reviewed',
          ack_expires_at: null,
        },
      ],
    });
    assert.equal(r.baseline.acks.length, 1);
    assert.equal(r.warnings.length, 0);
  });

  it('rejects an entry with an empty ack_reason', () => {
    assert.throws(() =>
      validateBaseline({
        schema_version: '1.0.0',
        generated_by: 'test',
        generated_at: '2026-04-15T09:12:00Z',
        acks: [
          {
            id: 'sec-000000000001',
            severity_at_time_of_ack: 'high',
            title: 'x',
            ack_by: 'alice',
            ack_at: '2026-04-15T09:12:00Z',
            ack_reason: '   ',
            ack_expires_at: null,
          },
        ],
      })
    );
  });

  it('rejects unsupported schema_version', () => {
    assert.throws(() =>
      validateBaseline({
        schema_version: '2.0.0',
        generated_by: 'test',
        generated_at: '2026-04-15T09:12:00Z',
        acks: [],
      })
    );
  });

  it('warns but accepts ids that do not match the expected shape', () => {
    const r = validateBaseline({
      schema_version: '1.0.0',
      generated_by: 'test',
      generated_at: '2026-04-15T09:12:00Z',
      acks: [
        {
          id: 'legacy-finding-id',
          severity_at_time_of_ack: 'high',
          title: 'x',
          ack_by: 'alice',
          ack_at: '2026-04-15T09:12:00Z',
          ack_reason: 'reviewed',
          ack_expires_at: null,
        },
      ],
    });
    assert.equal(r.baseline.acks.length, 1);
    assert.equal(r.warnings.length, 1);
  });
});

describe('applyBaseline', () => {
  it('suppresses acked findings under mode=suppress', () => {
    const security = [f('sec-aaaaaaaaaaaa', 'high'), f('sec-bbbbbbbbbbbb', 'critical')];
    const result = applyBaseline({
      security,
      nonce: [],
      correlator: [],
      fileAcks: [ackEntry('sec-aaaaaaaaaaaa')],
      inlineAcks: [],
      mode: 'suppress',
    });
    assert.equal(result.filteredSecurity.length, 1);
    assert.equal(result.filteredSecurity[0].id, 'sec-bbbbbbbbbbbb');
    assert.equal(result.suppressedSecurity.length, 1);
    assert.equal(result.acksApplied, 1);
    assert.equal(result.netNewFindings, 1); // bbbb is critical and net-new
  });

  it('downgrades acked findings under mode=downgrade-to-info', () => {
    const security = [f('sec-aaaaaaaaaaaa', 'high')];
    const result = applyBaseline({
      security,
      nonce: [],
      correlator: [],
      fileAcks: [ackEntry('sec-aaaaaaaaaaaa')],
      inlineAcks: [],
      mode: 'downgrade-to-info',
    });
    assert.equal(result.filteredSecurity.length, 1);
    assert.equal(result.filteredSecurity[0].severity, 'info');
    assert.equal(result.netNewFindings, 0);
  });

  it('keeps findings under mode=accounting-only and excludes them from net-new', () => {
    const security = [f('sec-aaaaaaaaaaaa', 'high'), f('sec-bbbbbbbbbbbb', 'critical')];
    const result = applyBaseline({
      security,
      nonce: [],
      correlator: [],
      fileAcks: [ackEntry('sec-aaaaaaaaaaaa')],
      inlineAcks: [],
      mode: 'accounting-only',
    });
    assert.equal(result.filteredSecurity.length, 2);
    assert.equal(result.netNewFindings, 1); // critical bbbb still counts
    assert.equal(result.suppressedSecurity.length, 1); // aaaa is acked
  });

  it('reports acks present in baseline that no finding matches', () => {
    const security = [f('sec-aaaaaaaaaaaa', 'high')];
    const result = applyBaseline({
      security,
      nonce: [],
      correlator: [],
      fileAcks: [ackEntry('sec-aaaaaaaaaaaa'), ackEntry('sec-deadbeefdead')],
      inlineAcks: [],
      mode: 'suppress',
    });
    assert.equal(result.acksUnmatched.length, 1);
    assert.equal(result.acksUnmatched[0].id, 'sec-deadbeefdead');
  });

  it('treats inline acks the same as file acks', () => {
    const security = [f('sec-aaaaaaaaaaaa', 'high')];
    const annotations = new Map([
      ['transfer', [{ key: 'audit-ack', tag: 'sec-aaaaaaaaaaaa', reason: 'OK by design', line: 10 }]],
    ]);
    const inlineAcks = inlineAnnotationAcks(annotations);
    const result = applyBaseline({
      security,
      nonce: [],
      correlator: [],
      fileAcks: [],
      inlineAcks,
      mode: 'suppress',
    });
    assert.equal(result.acksApplied, 1);
    assert.equal(result.suppressedSecurity[0].ack?.source, 'inline-annotation');
  });

  it('treats expired acks as not-acked and lists them under acksExpired', () => {
    const security = [f('sec-aaaaaaaaaaaa', 'high')];
    const result = applyBaseline({
      security,
      nonce: [],
      correlator: [],
      fileAcks: [ackEntry('sec-aaaaaaaaaaaa', { ack_expires_at: '2020-01-01T00:00:00Z' })],
      inlineAcks: [],
      mode: 'suppress',
      now: new Date('2026-06-13T00:00:00Z'),
    });
    assert.equal(result.acksApplied, 0);
    assert.equal(result.filteredSecurity.length, 1);
    assert.equal(result.acksExpired.length, 1);
  });

  it('flags severity-escalated-since-ack when the rule severity went up', () => {
    const security = [f('sec-aaaaaaaaaaaa', 'critical')];
    const result = applyBaseline({
      security,
      nonce: [],
      correlator: [],
      fileAcks: [ackEntry('sec-aaaaaaaaaaaa', { severity_at_time_of_ack: 'medium' })],
      inlineAcks: [],
      mode: 'downgrade-to-info',
    });
    assert.equal(result.suppressedSecurity[0].ack?.severityEscalatedSinceAck, true);
  });
});

describe('inlineAnnotationAcks', () => {
  it('ignores non audit-ack annotations', () => {
    const annotations = new Map([
      ['x', [
        { key: 'access-control', tag: 'documented', reason: 'x', line: 1 },
        { key: 'audit-ack', tag: 'sec-aaaaaaaaaaaa', reason: 'OK', line: 5 },
      ]],
    ]);
    const acks = inlineAnnotationAcks(annotations);
    assert.equal(acks.length, 1);
    assert.equal(acks[0].id, 'sec-aaaaaaaaaaaa');
  });

  it('drops malformed-id annotations', () => {
    const annotations = new Map([
      ['x', [{ key: 'audit-ack', tag: 'not-a-real-id', reason: '', line: 1 }]],
    ]);
    assert.equal(inlineAnnotationAcks(annotations).length, 0);
  });
});

describe('generateBaseline', () => {
  it('preserves prior acks and only writes new entries with reasons', () => {
    const prior: BaselineFile = {
      schema_version: '1.0.0',
      generated_by: 'test',
      generated_at: '2026-04-15T09:12:00Z',
      acks: [ackEntry('sec-existingnnnnn')],
    };
    const fresh = generateBaseline({
      security: [f('sec-existingnnnnn', 'high'), f('sec-newnnnnnnnnnn', 'high'), f('sec-noreasonnnnn', 'high')],
      nonce: [],
      correlator: [],
      prior,
      reasonByIdFn: (id) => (id === 'sec-newnnnnnnnnnn' ? 'reviewed' : null),
      ackBy: 'bob@example.com',
      toolVersion: 'test',
      now: new Date('2026-06-13T00:00:00Z'),
    });
    assert.equal(fresh.acks.length, 2);
    const ids = fresh.acks.map(a => a.id).sort();
    assert.deepEqual(ids, ['sec-existingnnnnn', 'sec-newnnnnnnnnnn']);
  });
});
