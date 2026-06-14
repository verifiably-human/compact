import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  deriveSecurityFindingId,
  deriveRuleKey,
  isWellFormedFindingId,
  addIdsToSecurityFindings,
} from './finding-id.js';
import type { SecurityFinding } from './security-analyzer.js';

const baseFinding = (overrides: Partial<SecurityFinding> = {}): SecurityFinding => ({
  type: 'access-control',
  severity: 'high',
  title: 'Missing authorization check: transfer',
  description: '',
  recommendation: '',
  impact: '',
  ...overrides,
});

describe('deriveRuleKey', () => {
  it('maps "Missing authorization check" titles to access-control:missing', () => {
    const f = baseFinding({ title: 'Missing authorization check: transfer' });
    assert.equal(deriveRuleKey(f), 'access-control:missing');
  });

  it('maps "Disabled authorization check" titles to access-control:disabled', () => {
    const f = baseFinding({ title: 'Disabled authorization check: init' });
    assert.equal(deriveRuleKey(f), 'access-control:disabled');
  });

  it('strips [Heuristic] prefix before matching', () => {
    const f = baseFinding({ title: '[Heuristic] Missing authorization check: foo' });
    assert.equal(deriveRuleKey(f), 'access-control:missing');
  });

  it('preserves the type for non-access-control kinds', () => {
    assert.equal(deriveRuleKey(baseFinding({ type: 'privacy-leak' })), 'privacy-leak');
    assert.equal(deriveRuleKey(baseFinding({ type: 'state-mutation' })), 'state-mutation');
    assert.equal(deriveRuleKey(baseFinding({ type: 'nullifier' })), 'nullifier');
  });
});

describe('deriveSecurityFindingId', () => {
  it('produces a stable sec-<12 hex> id', () => {
    const id = deriveSecurityFindingId(baseFinding());
    assert.match(id, /^sec-[0-9a-f]{12}$/);
  });

  it('is idempotent on repeated calls', () => {
    const a = deriveSecurityFindingId(baseFinding());
    const b = deriveSecurityFindingId(baseFinding());
    assert.equal(a, b);
  });

  it('changes when the affected target (circuit/function) changes', () => {
    const a = deriveSecurityFindingId(baseFinding({ title: 'Missing authorization check: transfer' }));
    const b = deriveSecurityFindingId(baseFinding({ title: 'Missing authorization check: mint' }));
    assert.notEqual(a, b);
  });

  it('changes when the rule changes', () => {
    const a = deriveSecurityFindingId(baseFinding({ title: 'Missing authorization check: transfer' }));
    const b = deriveSecurityFindingId(baseFinding({ title: 'Disabled authorization check: transfer' }));
    assert.notEqual(a, b);
  });

  it('changes when the circuit (location) changes', () => {
    const a = deriveSecurityFindingId(baseFinding({ location: { circuit: 'transfer' } }));
    const b = deriveSecurityFindingId(baseFinding({ location: { circuit: 'mint' } }));
    assert.notEqual(a, b);
  });

  it('does NOT change across [Heuristic]/[Compiler] prefix promotion', () => {
    const heur = deriveSecurityFindingId(baseFinding({ title: '[Heuristic] Missing authorization check: transfer' }));
    const comp = deriveSecurityFindingId(baseFinding({ title: '[Compiler] Missing authorization check: transfer' }));
    assert.equal(heur, comp);
  });

  it('does NOT change across description/impact/recommendation edits', () => {
    const a = deriveSecurityFindingId(baseFinding({ description: 'one' }));
    const b = deriveSecurityFindingId(baseFinding({ description: 'two' }));
    assert.equal(a, b);
  });

  it('treats missing location as the global anchor', () => {
    const a = deriveSecurityFindingId(baseFinding({ location: undefined }));
    const b = deriveSecurityFindingId(baseFinding({ location: { circuit: 'global' } }));
    assert.equal(a, b);
  });
});

describe('isWellFormedFindingId', () => {
  it('accepts sec-, nonce-, corr- prefixes', () => {
    assert.equal(isWellFormedFindingId('sec-000000000001'), true);
    assert.equal(isWellFormedFindingId('nonce-abcdef012345'), true);
    assert.equal(isWellFormedFindingId('corr-fedcba987654'), true);
  });

  it('rejects malformed shapes', () => {
    assert.equal(isWellFormedFindingId('sec-'), false);
    assert.equal(isWellFormedFindingId('sec-too-short'), false);
    assert.equal(isWellFormedFindingId('xyz-abcdef012345'), false);
    assert.equal(isWellFormedFindingId('sec-ABCDEF012345'), false); // uppercase
    assert.equal(isWellFormedFindingId(''), false);
  });
});

describe('addIdsToSecurityFindings', () => {
  it('populates id on each finding', () => {
    const fs: SecurityFinding[] = [baseFinding(), baseFinding({ title: 'Missing authorization check: foo' })];
    addIdsToSecurityFindings(fs);
    for (const f of fs) assert.match(f.id ?? '', /^sec-[0-9a-f]{12}$/);
  });

  it('does not overwrite a pre-set id', () => {
    const f = baseFinding();
    f.id = 'sec-preset000000';
    addIdsToSecurityFindings([f]);
    assert.equal(f.id, 'sec-preset000000');
  });
});
