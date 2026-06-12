/**
 * Policy assessment (phase 4).
 *
 * Derives a `deploy_recommendation` (block | warn | ok) from the
 * lens (ContractProfile, ValueInventory) and the findings
 * (SecurityAnalysisResult, NonceAnalysis, CorrelatorAnalysis). Each
 * triggered rule contributes a reason; the worst-severity reason
 * sets the recommendation.
 *
 * The rules below are intentionally conservative: they fire on
 * concrete combinations of profile and finding, not on isolated
 * findings. Finding severities themselves are NOT upgraded — the
 * policy block is separate from the per-finding severity ranking.
 *
 * Future work: load rules from a config file so teams can override
 * the defaults (e.g., a demo project may want to downgrade
 * "permissionless + holds" from warn to ok).
 */

import { SecurityAnalysisResult } from './security-analyzer.js';
import {
  ContractProfile,
  CorrelatorAnalysis,
  DeployRecommendation,
  NonceAnalysis,
  PolicyAssessment,
  PolicyReason,
  ValueInventory,
} from './types.js';

export interface PolicyAssessorInput {
  profile: ContractProfile;
  valueInventory: ValueInventory;
  security: SecurityAnalysisResult | undefined;
  nonceAnalysis: NonceAnalysis | undefined;
  correlatorAnalysis: CorrelatorAnalysis | undefined;
}

const RANK: Record<DeployRecommendation, number> = { block: 2, warn: 1, ok: 0 };

export function assessPolicy(input: PolicyAssessorInput): PolicyAssessment {
  const reasons: PolicyReason[] = [];

  // ---- BLOCK rules ----

  // R1. Unbounded mint. value-handling contract that can mint with no
  // authorization check and no max-supply assertion. Hard block.
  if (input.valueInventory.valueAtRiskSummary.isUnboundedMint) {
    reasons.push({
      rule: 'unbounded-mint',
      severity: 'block',
      message: 'Contract mints tokens via at least one circuit whose access control is missing or disabled, and no max-supply assertion guards the mint. Any caller can mint arbitrary amounts.',
    });
  }

  // R2. Critical-severity security findings (excluding info/acknowledged).
  const criticalFindings = (input.security?.findings ?? []).filter(f => f.severity === 'critical');
  for (const f of criticalFindings) {
    // Skip "acknowledged" findings (they're at info severity anyway, but
    // belt-and-suspenders).
    if (f.title.includes('acknowledged')) continue;
    reasons.push({
      rule: 'critical-security-finding',
      severity: 'block',
      message: `Critical: ${f.title}`,
    });
  }

  // R3. Critical nonce findings (constant-return witness in a
  // value-holding contract).
  const criticalNonce = (input.nonceAnalysis?.findings ?? []).filter(
    f => f.severity === 'critical',
  );
  if (criticalNonce.length > 0 && input.valueInventory.valueAtRiskSummary.isValueHolding) {
    reasons.push({
      rule: 'critical-nonce-in-value-contract',
      severity: 'block',
      message: `${criticalNonce.length} critical nonce hygiene finding(s) on a value-holding contract. Constant-return witnesses make commitments deterministic; the commitment opening is unrecoverable and unlinkability is defeated.`,
    });
  }

  // ---- WARN rules ----

  // W1. Mints with missing authorization, but max-supply is asserted
  // (so it's not unbounded). Still risky.
  const mintAuthMissing = input.valueInventory.mintOperations.some(m => m.authorizedBy === 'missing');
  if (mintAuthMissing && !input.valueInventory.valueAtRiskSummary.isUnboundedMint) {
    reasons.push({
      rule: 'mint-with-missing-auth-bounded',
      severity: 'warn',
      message: 'A mint operation has no recognised authorization guard, though a max-supply assert is present. Confirm the supply ceiling is the intended trust boundary.',
    });
  }

  // W2. High-severity security findings.
  const highSecurity = (input.security?.findings ?? []).filter(f => f.severity === 'high');
  if (highSecurity.length > 0) {
    const titles = highSecurity.slice(0, 3).map(f => f.title).join('; ');
    const more = highSecurity.length > 3 ? ` (and ${highSecurity.length - 3} more)` : '';
    reasons.push({
      rule: 'high-severity-security-findings',
      severity: 'warn',
      message: `${highSecurity.length} high-severity security finding(s): ${titles}${more}`,
    });
  }

  // W3. High-severity nonce findings (missing-counter-increment etc.).
  const highNonce = (input.nonceAnalysis?.findings ?? []).filter(f => f.severity === 'high');
  if (highNonce.length > 0) {
    reasons.push({
      rule: 'high-severity-nonce-findings',
      severity: 'warn',
      message: `${highNonce.length} high-severity nonce hygiene finding(s). Review the linked commitments to confirm openability.`,
    });
  }

  // W4. Correlators with no intent annotations on a privacy-claiming contract.
  const correlators = input.correlatorAnalysis?.findings ?? [];
  const unacknowledgedHighOrMedium = correlators.filter(
    c => (c.severity === 'high' || c.severity === 'medium') && !c.intentCheck.annotationPresent,
  );
  const claimsPrivacy = input.profile.privacyPosture === 'strong'
    || input.profile.privacyPosture === 'strong-with-disclosures';
  if (unacknowledgedHighOrMedium.length > 0 && claimsPrivacy) {
    reasons.push({
      rule: 'unacknowledged-correlators-on-private-contract',
      severity: 'warn',
      message: `${unacknowledgedHighOrMedium.length} cross-circuit correlator(s) found on a contract claiming privacy posture "${input.profile.privacyPosture}". Either add per-event blinders or annotate the affected circuits with \`// @disclose-intent: <tag>\`.`,
    });
  }

  // W5. Permissionless authority model on a value-handling contract.
  if (input.profile.authorityModel === 'permissionless'
      && (input.profile.valuePosture === 'holds'
          || input.profile.valuePosture === 'mints'
          || input.profile.valuePosture === 'bridges')) {
    reasons.push({
      rule: 'permissionless-value-contract',
      severity: 'warn',
      message: `Contract has value posture "${input.profile.valuePosture}" but authority model is "permissionless". Any caller can invoke value-handling circuits. Confirm this matches the threat model.`,
    });
  }

  // ---- Compute final recommendation ----
  const worst = reasons.reduce<DeployRecommendation>(
    (acc, r) => (RANK[r.severity] > RANK[acc] ? r.severity : acc),
    'ok',
  );

  return {
    schemaVersion: '1.0.0',
    deployRecommendation: worst,
    reasons,
  };
}
