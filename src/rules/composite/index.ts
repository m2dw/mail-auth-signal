import type {
  AnalyzeOptions,
  CompositeRule,
  MessageMetrics,
  Signal,
} from "../../types.js";
import { collectAuthenticationAlignment } from "../../metrics.js";
import { resolveHeaderTrust } from "../trust.js";
import { unauthenticatedFromSpoofRule } from "./unauthenticatedFromSpoof.js";
import { publicMailboxSpoofingCandidateRule } from "./publicMailboxSpoofingCandidate.js";
import { authenticatedDisplayNameSpoofRule } from "./authenticatedDisplayNameSpoof.js";
import { alignedAuthenticationConfirmedRule } from "./alignedAuthenticationConfirmed.js";

export { unauthenticatedFromSpoofRule } from "./unauthenticatedFromSpoof.js";
export { publicMailboxSpoofingCandidateRule } from "./publicMailboxSpoofingCandidate.js";
export { authenticatedDisplayNameSpoofRule } from "./authenticatedDisplayNameSpoof.js";
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
 * a ranked verdict. The two spoof composites precede the benign affirmation so a
 * reader scanning the emitted signals sees risk observations before the
 * "all clear", though alignedAuthenticationConfirmedRule reads metrics (not the
 * other composites' output) so the ordering does not change any result.
 */
export const defaultCompositeRules: readonly CompositeRule[] = [
  unauthenticatedFromSpoofRule,
  publicMailboxSpoofingCandidateRule,
  authenticatedDisplayNameSpoofRule,
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
 * The `authentication` projection is recomputed here from the current options'
 * trust (via collectAuthenticationAlignment + resolveHeaderTrust), identical to
 * how runRules builds its message-scoped view. This keeps a split-API caller —
 * extractMetrics without trust, then declare trustedAuthservIds at rule time —
 * seeing anyAuthAligned/dmarcPass consistent with the base signals it passes in,
 * rather than the trust baked into metrics.authentication at extraction.
 */
export function runCompositeRules(
  metrics: MessageMetrics,
  signals: readonly Signal[],
  options: AnalyzeOptions = {},
  rules: readonly CompositeRule[] = defaultCompositeRules,
): Signal[] {
  const authentication = collectAuthenticationAlignment(
    metrics.authenticationResults,
    metrics.fromDomain,
    (header) => resolveHeaderTrust(header, options),
  );
  const messageMetrics: MessageMetrics = { ...metrics, authentication };

  const composite: Signal[] = [];
  for (const rule of rules) {
    composite.push(...rule.evaluate({ metrics: messageMetrics, signals, options }));
  }
  return composite;
}
