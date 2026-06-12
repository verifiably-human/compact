import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { ProfileAnalyzer } from './profile-analyzer.js';

const mkInput = (overrides: Partial<{
  contractSource: string;
  contractPath: string;
  circuits: any[];
  stateVars: any[];
  findings: any[];
}> = {}) => ({
  contractSource: overrides.contractSource ?? '',
  contractPath: overrides.contractPath ?? '/tmp/test.compact',
  circuits: overrides.circuits ?? [],
  stateVars: overrides.stateVars ?? [],
  findings: overrides.findings ?? [],
});

describe('ProfileAnalyzer.valuePosture', () => {
  it('returns "none" when no token primitives and no balance fields', () => {
    const { profile } = new ProfileAnalyzer(mkInput()).analyze();
    assert.equal(profile.valuePosture, 'none');
  });

  it('returns "mints" when a circuit calls mintShieldedToken', () => {
    const input = mkInput({
      circuits: [{ name: 'mint', body: 'mintShieldedToken(...)', isExported: true, returnType: '[]' }],
    });
    const { profile } = new ProfileAnalyzer(input).analyze();
    assert.equal(profile.valuePosture, 'mints');
  });

  it('returns "bridges" when mint + send + off-chain custody hint coincide', () => {
    const input = mkInput({
      circuits: [
        { name: 'mintToVault', body: 'mintShieldedToken(...)', isExported: true, returnType: '[]' },
        { name: 'withdraw', body: 'sendUnshielded(...)', isExported: true, returnType: '[]' },
      ],
      stateVars: [{ name: 'vaultBalance', type: 'Uint<128>', kind: 'ledger' }],
    });
    const { profile } = new ProfileAnalyzer(input).analyze();
    assert.equal(profile.valuePosture, 'bridges');
  });

  it('returns "receives" when only receive primitives exist', () => {
    const input = mkInput({
      circuits: [{ name: 'deposit', body: 'receiveShielded(...)', isExported: true, returnType: '[]' }],
    });
    const { profile } = new ProfileAnalyzer(input).analyze();
    assert.equal(profile.valuePosture, 'receives');
  });

  it('returns "holds" when balance fields exist but no mint', () => {
    const input = mkInput({
      stateVars: [{ name: 'totalSupply', type: 'Counter', kind: 'ledger' }],
    });
    const { profile } = new ProfileAnalyzer(input).analyze();
    assert.equal(profile.valuePosture, 'holds');
  });
});

describe('ProfileAnalyzer.privacyPosture', () => {
  it('returns "open" when no witnesses are declared', () => {
    const { profile } = new ProfileAnalyzer(mkInput()).analyze();
    assert.equal(profile.privacyPosture, 'open');
  });

  it('returns "strong" when witnesses present but no disclose calls', () => {
    const input = mkInput({
      stateVars: [{ name: 'secret', type: 'Field', kind: 'witness' }],
      circuits: [{ name: 'foo', body: 'const x = 1;', isExported: true, returnType: '[]' }],
    });
    const { profile } = new ProfileAnalyzer(input).analyze();
    assert.equal(profile.privacyPosture, 'strong');
  });

  it('returns "selective" with disclose() outside a protocol-required call', () => {
    const input = mkInput({
      stateVars: [{ name: 'secret', type: 'Field', kind: 'witness' }],
      circuits: [
        {
          name: 'foo',
          body: 'X = disclose(secret());',
          isExported: true,
          returnType: '[]',
        },
      ],
    });
    const { profile } = new ProfileAnalyzer(input).analyze();
    assert.equal(profile.privacyPosture, 'selective');
  });

  it('returns "strong-with-disclosures" when disclose appears with a token primitive', () => {
    const input = mkInput({
      stateVars: [{ name: 'secret', type: 'Field', kind: 'witness' }],
      circuits: [
        {
          name: 'mint',
          body: 'mintShieldedToken(disclose(secret()));',
          isExported: true,
          returnType: '[]',
        },
      ],
    });
    const { profile } = new ProfileAnalyzer(input).analyze();
    assert.equal(profile.privacyPosture, 'strong-with-disclosures');
  });
});

describe('ProfileAnalyzer.authorityModel', () => {
  it('returns "permissionless" when every exported circuit has a missing-auth finding', () => {
    const input = mkInput({
      circuits: [
        { name: 'a', body: '', isExported: true, returnType: '[]' },
        { name: 'b', body: '', isExported: true, returnType: '[]' },
      ],
      findings: [
        { type: 'access-control', severity: 'high', title: 'Missing authorization check: a', location: { circuit: 'a' }, description: '', recommendation: '', impact: '' },
        { type: 'access-control', severity: 'high', title: 'Missing authorization check: b', location: { circuit: 'b' }, description: '', recommendation: '', impact: '' },
      ],
    });
    const { profile } = new ProfileAnalyzer(input).analyze();
    assert.equal(profile.authorityModel, 'permissionless');
  });

  it('returns "single-owner" with exactly one owner-like ledger field', () => {
    const input = mkInput({
      circuits: [{ name: 'guarded', body: 'requireOwner();', isExported: true, returnType: '[]' }],
      stateVars: [{ name: 'owner', type: 'Bytes<32>', kind: 'ledger' }],
    });
    const { profile } = new ProfileAnalyzer(input).analyze();
    assert.equal(profile.authorityModel, 'single-owner');
  });

  it('returns "membership-proof" with a Merkle-root-like ledger field', () => {
    const input = mkInput({
      circuits: [{ name: 'guarded', body: '', isExported: true, returnType: '[]' }],
      stateVars: [{ name: 'membershipMerkleRoot', type: 'Bytes<32>', kind: 'ledger' }],
    });
    const { profile } = new ProfileAnalyzer(input).analyze();
    assert.equal(profile.authorityModel, 'membership-proof');
  });
});

describe('ProfileAnalyzer.ledgerSurface classification', () => {
  it('classifies balance, commitment, nullifier, key fields', () => {
    const input = mkInput({
      stateVars: [
        { name: 'vaultBalance', type: 'Uint<128>', kind: 'ledger' },
        { name: 'fooCommitment', type: 'Bytes<32>', kind: 'ledger' },
        { name: 'spentNullifier', type: 'Bytes<32>', kind: 'ledger' },
        { name: 'ownerKey', type: 'Bytes<32>', kind: 'ledger' },
        { name: 'someCounter', type: 'Counter', kind: 'ledger' },
      ],
    });
    const { profile } = new ProfileAnalyzer(input).analyze();
    assert.deepEqual(profile.ledgerSurface.balanceLike, ['vaultBalance']);
    assert.deepEqual(profile.ledgerSurface.commitmentLike, ['fooCommitment']);
    assert.deepEqual(profile.ledgerSurface.nullifierLike, ['spentNullifier']);
    assert.deepEqual(profile.ledgerSurface.keyLike, ['ownerKey']);
    assert.deepEqual(profile.ledgerSurface.counterLike, ['someCounter']);
  });
});

describe('ProfileAnalyzer.valueInventory', () => {
  it('flags isUnboundedMint when mint has missing auth and no max-supply assert', () => {
    const input = mkInput({
      circuits: [{
        name: 'mint',
        body: 'mintShieldedToken(...);',
        isExported: true,
        returnType: '[]',
      }],
      findings: [
        { type: 'access-control', severity: 'high', title: 'Missing authorization check: mint', location: { circuit: 'mint' }, description: '', recommendation: '', impact: '' },
      ],
    });
    const { valueInventory } = new ProfileAnalyzer(input).analyze();
    assert.equal(valueInventory.valueAtRiskSummary.isUnboundedMint, true);
    assert.equal(valueInventory.mintOperations[0]?.authorizedBy, 'missing');
  });

  it('detects commitment+nullifier pair by stem', () => {
    const input = mkInput({
      stateVars: [
        { name: 'spendCommitment', type: 'Bytes<32>', kind: 'ledger' },
        { name: 'spendNullifier', type: 'Bytes<32>', kind: 'ledger' },
      ],
    });
    const { valueInventory } = new ProfileAnalyzer(input).analyze();
    assert.equal(valueInventory.commitmentNullifierPairs.length, 1);
    assert.equal(valueInventory.commitmentNullifierPairs[0].commitmentField, 'spendCommitment');
    assert.equal(valueInventory.commitmentNullifierPairs[0].nullifierField, 'spendNullifier');
  });

  it('classifies a custodial-token shape correctly', () => {
    const input = mkInput({
      circuits: [
        { name: 'mintToVault', body: 'mintShieldedToken(...);', isExported: true, returnType: '[]' },
        { name: 'withdraw', body: 'sendUnshielded(...);', isExported: true, returnType: '[]' },
      ],
      stateVars: [
        { name: 'vaultBalance', type: 'Uint<128>', kind: 'ledger' },
      ],
    });
    const { valueInventory } = new ProfileAnalyzer(input).analyze();
    assert.equal(valueInventory.valueAtRiskSummary.estimatedClass, 'custodial-token');
  });
});
