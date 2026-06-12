import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { assessPolicy } from './policy-assessor.js';
import type {
  ContractProfile,
  ValueInventory,
  NonceAnalysis,
  CorrelatorAnalysis,
} from './types.js';

const baseProfile = (overrides: Partial<ContractProfile> = {}): ContractProfile => ({
  schemaVersion: '1.0.0',
  valuePosture: 'none',
  privacyPosture: 'strong',
  authorityModel: 'single-owner',
  tokenPrimitives: [],
  ledgerSurface: {
    fieldsTotal: 0,
    fieldsSealed: 0,
    balanceLike: [],
    commitmentLike: [],
    nullifierLike: [],
    counterLike: [],
    keyLike: [],
  },
  externalCustodyHints: [],
  circuitCount: 1,
  exportedCircuitCount: 1,
  witnessFunctionCount: 0,
  ...overrides,
});

const baseInventory = (overrides: Partial<ValueInventory> = {}): ValueInventory => ({
  schemaVersion: '1.0.0',
  mintOperations: [],
  sendOperations: [],
  receiveOperations: [],
  balanceFields: [],
  commitmentNullifierPairs: [],
  maintenanceAuthorityRefs: [],
  maxSupplyConstraints: [],
  offChainCustodySignals: [],
  valueAtRiskSummary: {
    estimatedClass: 'unknown',
    isUnboundedMint: false,
    isValueHolding: false,
  },
  ...overrides,
});

describe('assessPolicy', () => {
  it('returns ok when nothing is wrong', () => {
    const result = assessPolicy({
      profile: baseProfile(),
      valueInventory: baseInventory(),
      security: undefined,
      nonceAnalysis: undefined,
      correlatorAnalysis: undefined,
    });
    assert.equal(result.deployRecommendation, 'ok');
    assert.equal(result.reasons.length, 0);
  });

  it('blocks on unbounded mint', () => {
    const result = assessPolicy({
      profile: baseProfile({ valuePosture: 'mints' }),
      valueInventory: baseInventory({
        valueAtRiskSummary: { estimatedClass: 'shielded-token', isUnboundedMint: true, isValueHolding: true },
      }),
      security: undefined,
      nonceAnalysis: undefined,
      correlatorAnalysis: undefined,
    });
    assert.equal(result.deployRecommendation, 'block');
    assert.ok(result.reasons.some(r => r.rule === 'unbounded-mint'));
  });

  it('blocks on any critical security finding', () => {
    const result = assessPolicy({
      profile: baseProfile(),
      valueInventory: baseInventory(),
      security: {
        findings: [{
          type: 'access-control',
          severity: 'critical',
          title: 'Disabled authorization check: foo',
          description: '',
          recommendation: '',
          impact: '',
        }],
        riskScore: 100,
        summary: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
      },
      nonceAnalysis: undefined,
      correlatorAnalysis: undefined,
    });
    assert.equal(result.deployRecommendation, 'block');
    assert.ok(result.reasons.some(r => r.rule === 'critical-security-finding'));
  });

  it('warns when mint has missing auth but max-supply is asserted', () => {
    const result = assessPolicy({
      profile: baseProfile({ valuePosture: 'mints' }),
      valueInventory: baseInventory({
        mintOperations: [{
          primitive: 'mintShieldedToken',
          circuit: 'mint',
          location: { file: '/c.compact' },
          authorizedBy: 'missing',
        }],
        valueAtRiskSummary: { estimatedClass: 'shielded-token', isUnboundedMint: false, isValueHolding: true },
      }),
      security: undefined,
      nonceAnalysis: undefined,
      correlatorAnalysis: undefined,
    });
    assert.equal(result.deployRecommendation, 'warn');
    assert.ok(result.reasons.some(r => r.rule === 'mint-with-missing-auth-bounded'));
  });

  it('warns on high-severity security findings', () => {
    const result = assessPolicy({
      profile: baseProfile(),
      valueInventory: baseInventory(),
      security: {
        findings: [{
          type: 'access-control',
          severity: 'high',
          title: 'Missing authorization check: foo',
          description: '',
          recommendation: '',
          impact: '',
        }],
        riskScore: 50,
        summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
      },
      nonceAnalysis: undefined,
      correlatorAnalysis: undefined,
    });
    assert.equal(result.deployRecommendation, 'warn');
    assert.ok(result.reasons.some(r => r.rule === 'high-severity-security-findings'));
  });

  it('warns on unacknowledged correlators in a privacy-claiming contract', () => {
    const ca: CorrelatorAnalysis = {
      schemaVersion: '1.0.0',
      findings: [{
        id: 'corr-test',
        severity: 'high',
        witnessOrigin: { kind: 'witness-return-value', function: 'secret', location: { file: '/c.compact' } },
        linkedDisclosureSites: [],
        exposureStructure: { sameFinalExposure: true, blinderPresent: false, stableIdentifierPresent: true, exposureLabel: 'x' },
        linkabilitySummary: '',
        intentCheck: { docstringSaysCorrelatable: null, annotationPresent: false },
        recommendation: '',
        autoDismissible: false,
      }],
    };
    const result = assessPolicy({
      profile: baseProfile({ privacyPosture: 'strong' }),
      valueInventory: baseInventory(),
      security: undefined,
      nonceAnalysis: undefined,
      correlatorAnalysis: ca,
    });
    assert.equal(result.deployRecommendation, 'warn');
    assert.ok(result.reasons.some(r => r.rule === 'unacknowledged-correlators-on-private-contract'));
  });

  it('does NOT warn on correlators when @disclose-intent is set', () => {
    const ca: CorrelatorAnalysis = {
      schemaVersion: '1.0.0',
      findings: [{
        id: 'corr-test',
        severity: 'info',
        witnessOrigin: { kind: 'witness-return-value', function: 'secret', location: { file: '/c.compact' } },
        linkedDisclosureSites: [],
        exposureStructure: { sameFinalExposure: true, blinderPresent: false, stableIdentifierPresent: true, exposureLabel: 'x' },
        linkabilitySummary: '',
        intentCheck: { docstringSaysCorrelatable: null, annotationPresent: true, annotationTag: 'intentional-correlator' },
        recommendation: '',
        autoDismissible: true,
      }],
    };
    const result = assessPolicy({
      profile: baseProfile({ privacyPosture: 'strong' }),
      valueInventory: baseInventory(),
      security: undefined,
      nonceAnalysis: undefined,
      correlatorAnalysis: ca,
    });
    assert.equal(result.deployRecommendation, 'ok');
    assert.equal(result.reasons.length, 0);
  });

  it('warns when value-handling contract has permissionless authority', () => {
    const result = assessPolicy({
      profile: baseProfile({ valuePosture: 'holds', authorityModel: 'permissionless' }),
      valueInventory: baseInventory({
        valueAtRiskSummary: { estimatedClass: 'shielded-token', isUnboundedMint: false, isValueHolding: true },
      }),
      security: undefined,
      nonceAnalysis: undefined,
      correlatorAnalysis: undefined,
    });
    assert.equal(result.deployRecommendation, 'warn');
    assert.ok(result.reasons.some(r => r.rule === 'permissionless-value-contract'));
  });

  it('picks the worst severity across multiple rules', () => {
    const result = assessPolicy({
      profile: baseProfile({ valuePosture: 'mints', authorityModel: 'permissionless' }),
      valueInventory: baseInventory({
        mintOperations: [{
          primitive: 'mintShieldedToken',
          circuit: 'mint',
          location: { file: '/c.compact' },
          authorizedBy: 'missing',
        }],
        valueAtRiskSummary: { estimatedClass: 'shielded-token', isUnboundedMint: true, isValueHolding: true },
      }),
      security: undefined,
      nonceAnalysis: undefined,
      correlatorAnalysis: undefined,
    });
    // Both block and warn rules fire; recommendation is the worst (block).
    assert.equal(result.deployRecommendation, 'block');
    assert.ok(result.reasons.some(r => r.severity === 'block'));
    assert.ok(result.reasons.some(r => r.severity === 'warn'));
  });
});
