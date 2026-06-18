import type { CompositeRule, Signal } from "../../types.js";

/**
 * Composite (false-positive mitigation): an affirmative "this message's From
 * domain is fully accounted for" signal, emitted only when the message both
 * authenticates as its visible From domain and shows no identity disagreement.
 *
 * Why a mitigation rule exists, and why it is safe. A caller scoring the base
 * signals sees only *negative* hints; it has no positive marker for "I verified
 * this and it is clean", which it needs to confidently *lower* a score (e.g.
 * keep well-authenticated mail out of a Review queue). The danger with any such
 * suppress/allow rule — called out in this repo's review guidance — is that an
 * attacker could intentionally satisfy it to launder a spoof. This rule is built
 * so they cannot:
 *
 *   - trustedHeaderCount > 0 AND anyAuthAligned === true: the affirmation gates on
 *     a *real, aligned, trusted, passing* SPF or DKIM identifier for the visible
 *     From domain. That is cryptographic (DKIM) or path (SPF) proof of authority
 *     over the From domain. A spoofer of someone else's domain cannot produce it
 *     — that is the entire premise of SPF/DKIM/DMARC — so they cannot make their
 *     forgery wear this badge. The only way to trigger it is to actually be the
 *     From domain.
 *   - no base "auth-failure" and no base "consistency" signal: even with aligned
 *     auth, the message must additionally have zero authentication failures and
 *     zero identifier mismatches. A partially-aligned message (one aligned DKIM
 *     but a divergent Reply-To/Return-Path/Message-ID, or a co-occurring failed
 *     method) is *not* confirmed clean and must not be suppressed.
 *   - no authenticated display-name spoof shape: a display name addressing a
 *     different domain (see authenticatedDisplayNameSpoofRule) is suspicious even
 *     when auth aligns, so its presence withholds the affirmation. Checked from
 *     metrics directly so ordering relative to that composite does not matter.
 *
 * Severity info: it is the absence of risk, not a risk. It carries
 * `contributingSignals: []` for shape parity with the other composites (its
 * justification is the *absence* of contributing signals, by construction).
 *
 * The core still forms no policy: emitting this never tells the caller to allow
 * or deliver anything. It only states, in one place, that the authentication and
 * consistency layers all came back clean for the visible From — the caller
 * decides what weight that earns.
 */
export const alignedAuthenticationConfirmedRule: CompositeRule = {
  key: "composite.alignedAuthenticationConfirmed",
  description:
    "The visible From domain has aligned, trusted authentication and no authentication or consistency signal disagrees.",
  evaluate({ metrics, signals }): Signal[] {
    const { authentication } = metrics;
    if (authentication.trustedHeaderCount === 0) return [];
    if (authentication.anyAuthAligned !== true) return [];

    // Any authentication failure or identity mismatch withholds the affirmation.
    const hasRiskSignal = signals.some(
      (signal) => signal.category === "auth-failure" || signal.category === "consistency",
    );
    if (hasRiskSignal) return [];

    // A misleading display name is suspicious even with aligned auth (see
    // authenticatedDisplayNameSpoofRule); read it from metrics so this rule does
    // not depend on composite evaluation order.
    const { displayName } = metrics.senderIdentity;
    if (displayName.containsEmail && displayName.embeddedDomainMatchesFromDomain === false) {
      return [];
    }

    return [
      {
        key: "composite.alignedAuthenticationConfirmed",
        category: "composite",
        severity: "info",
        message:
          "Visible From domain has aligned, trusted authentication with no conflicting signal.",
        data: {
          fromDomain: metrics.fromDomain,
          anyAlignedSpfPass: authentication.anyAlignedSpfPass,
          anyAlignedDkimPass: authentication.anyAlignedDkimPass,
          dmarcPass: authentication.dmarcPass,
          contributingSignals: [],
        },
      },
    ];
  },
};
