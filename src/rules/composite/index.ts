import type {
  AnalyzeOptions,
  CompositeRule,
  MessageMetrics,
  MetricsDependencies,
  Signal,
} from "../../types.js";
import { messageScopedMetrics } from "../index.js";
import { unauthenticatedFromSpoofRule } from "./unauthenticatedFromSpoof.js";
import { publicMailboxSpoofingCandidateRule } from "./publicMailboxSpoofingCandidate.js";
import { authenticatedDisplayNameSpoofRule } from "./authenticatedDisplayNameSpoof.js";
import { unsecuredDeepSubdomainCandidateRule } from "./unsecuredDeepSubdomainCandidate.js";
import { deepRandomFromSubdomainRule } from "./deepRandomFromSubdomain.js";
import { brandDivergencePhishingRule } from "./brandDivergencePhishing.js";
import { ownDomainSpoofCandidateRule } from "./ownDomainSpoofCandidate.js";
import { dkimFailWithAlignedPassRule } from "./dkimFailWithAlignedPass.js";
import { dkimAlignedLexicalMitigationRule } from "./dkimAlignedLexicalMitigation.js";
import { alignedAuthenticationConfirmedRule } from "./alignedAuthenticationConfirmed.js";

export { unauthenticatedFromSpoofRule } from "./unauthenticatedFromSpoof.js";
export { publicMailboxSpoofingCandidateRule } from "./publicMailboxSpoofingCandidate.js";
export { authenticatedDisplayNameSpoofRule } from "./authenticatedDisplayNameSpoof.js";
export { unsecuredDeepSubdomainCandidateRule } from "./unsecuredDeepSubdomainCandidate.js";
export { deepRandomFromSubdomainRule } from "./deepRandomFromSubdomain.js";
export { brandDivergencePhishingRule } from "./brandDivergencePhishing.js";
export {
  ownDomainSpoofCandidateRule,
  OWN_ACCOUNT_DOMAINS_CONTEXT_KEY,
} from "./ownDomainSpoofCandidate.js";
export { dkimFailWithAlignedPassRule } from "./dkimFailWithAlignedPass.js";
export { dkimAlignedLexicalMitigationRule } from "./dkimAlignedLexicalMitigation.js";
export { alignedAuthenticationConfirmedRule } from "./alignedAuthenticationConfirmed.js";

/**
 * The built-in composite (Layer 4) rule set.
 *
 * This is the composite analogue of defaultRules: the migration surface for
 * porting further Thunderbird composite rules. It is intentionally *not* part of
 * the default base pipeline — analyzeMessage emits only base signals unless a
 * caller opts in by passing composite rules — so the core's default output stays
 * the conservative, per-metric layer and the cross-cutting composites are an
 * explicit choice the consuming add-on makes.
 *
 * Order is stable but carries no policy meaning; composites are observations, not
 * a ranked verdict. The risk-observation composites (the spoof shapes, the deep-
 * subdomain candidates, the brand-divergence and own-domain candidates) precede the
 * mitigations (the DKIM-aligned offsets) and the benign affirmation, so a reader
 * scanning the emitted signals sees risk observations before the "all clear". Each
 * composite reads metrics (and, where noted, the base signals), not the other
 * composites' output, so the ordering does not change any result.
 */
export const defaultCompositeRules: readonly CompositeRule[] = [
  unauthenticatedFromSpoofRule,
  publicMailboxSpoofingCandidateRule,
  authenticatedDisplayNameSpoofRule,
  unsecuredDeepSubdomainCandidateRule,
  deepRandomFromSubdomainRule,
  brandDivergencePhishingRule,
  ownDomainSpoofCandidateRule,
  dkimFailWithAlignedPassRule,
  dkimAlignedLexicalMitigationRule,
  alignedAuthenticationConfirmedRule,
];

/**
 * Run a composite rule set over already-extracted metrics and the base signals
 * those metrics produced.
 *
 * Composite rules read both the metrics and the lower-layer `signals`, so the
 * caller must pass the base signals produced under the same `options` — exactly
 * what analyzeMessage does when it threads runRules' output into here. Passing
 * mismatched trust (metrics/signals from one option set, options from another)
 * would let a composite read a forged header as authenticated; the contract is
 * the caller's to keep, mirroring runRules.
 *
 * The `authentication` projection is rebuilt here from the current options'
 * trust via messageScopedMetrics, identical to how runRules builds its
 * message-scoped view. This keeps a split-API caller — extractMetrics without
 * trust, then declare trustedAuthservIds at rule time — seeing
 * anyAuthAligned/dmarcPass consistent with the base signals it passes in, rather
 * than the trust baked into metrics.authentication at extraction.
 *
 * The optional `deps` carries the same PSL resolver analyzeMessage used, so the
 * recomputed projection's organizational (PSL-aware) alignment matches the one
 * extraction produced. Crucially, when a split-API caller passes neither a
 * rule-time resolver nor a trust override, messageScopedMetrics preserves the
 * already-extracted organizational block instead of downgrading it to the
 * exact-domain fallback — so a composite rule reading
 * authentication.organizational.anyAuthAligned still sees the resolver-derived
 * value, matching runRules.
 */
export function runCompositeRules(
  metrics: MessageMetrics,
  signals: readonly Signal[],
  options: AnalyzeOptions = {},
  rules: readonly CompositeRule[] = defaultCompositeRules,
  deps?: MetricsDependencies,
): Signal[] {
  const messageMetrics = messageScopedMetrics(metrics, options, deps);

  const composite: Signal[] = [];
  for (const rule of rules) {
    composite.push(...rule.evaluate({ metrics: messageMetrics, signals, options }));
  }
  return composite;
}
