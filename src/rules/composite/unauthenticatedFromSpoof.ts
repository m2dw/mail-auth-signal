import type { CompositeRule, Signal } from "../../types.js";

/**
 * Composite: a From-domain spoof that the message's own authentication cannot
 * back up.
 *
 * Attacker model — direct domain impersonation. The attacker puts a brand they
 * do not control in the visible From (`From: Brand <notice@brand.example>`) to
 * borrow its trust. They cannot produce aligned, trusted, passing SPF or DKIM
 * for `brand.example`, and the identifiers they *do* control (the envelope
 * sender, the Message-ID host, a Reply-To pointing back at their own infra) name
 * a different domain. Either tell alone is weak — a legitimate forwarder can
 * fail SPF, and a benign sender can use a list/ESP Message-ID — but the
 * *combination* of "no aligned authentication vouches for the From" and "another
 * sender identifier disagrees with the From" is the spoof shape. This composite
 * fires only when both hold, turning two individually noisy hints into one
 * high-confidence observation.
 *
 * Why these guards (false-positive control):
 *   - trustedHeaderCount > 0: the verdict needs a basis. With no trusted
 *     Authentication-Results header we never evaluated anything, so anyAuthAligned
 *     is vacuously false and a mismatch could be perfectly benign mail we simply
 *     could not check. The missing/untrusted base signals cover that case; this
 *     composite stays silent rather than guess.
 *   - anyAuthAligned === false: a message with even one aligned, trusted, passing
 *     SPF or DKIM identifier for the From domain is, by DMARC's own logic,
 *     authenticated as that domain — so a forwarder that fails SPF but keeps an
 *     aligned DKIM signature does not trip this. Only the genuinely
 *     unauthenticated From reaches here.
 *   - at least one base "consistency" signal: a misconfigured-but-honest sender
 *     whose own identifiers all still name the From domain (it just failed to
 *     authenticate) produces auth-failure signals but no consistency mismatch, so
 *     it is left to the base auth.method.failure signals and not escalated to a
 *     spoof verdict here.
 *
 * Not attacker-triggerable as a false positive against a third party: the only
 * way to *suppress* this signal is to authenticate the From domain (which a
 * spoofer of someone else's domain cannot) or to make every identifier agree with
 * the From (which, for a domain they do not control, means actually being that
 * domain). An attacker can only trigger it on their own spoof.
 *
 * Severity high: it combines a failure to authenticate with positive evidence of
 * a divergent identity. It remains an observation, not an action — the caller
 * still owns the Junk/Review/threshold decision.
 */
export const unauthenticatedFromSpoofRule: CompositeRule = {
  key: "composite.unauthenticatedFromSpoof",
  description:
    "The visible From domain has no aligned, trusted authentication and another sender identifier disagrees with it.",
  evaluate({ metrics, signals }): Signal[] {
    const { authentication } = metrics;
    // No trusted header means nothing was actually evaluated; do not manufacture
    // a verdict from an unverifiable message.
    if (authentication.trustedHeaderCount === 0) return [];
    // An aligned, trusted, passing identifier authenticates the From domain.
    if (authentication.anyAuthAligned !== false) return [];

    const consistencyKeys = signals
      .filter((signal) => signal.category === "consistency")
      .map((signal) => signal.key);
    // Without a divergent identifier this is an honest authentication failure,
    // not evidence of impersonation; leave it to the base auth-failure signals.
    if (consistencyKeys.length === 0) return [];

    const authFailureKeys = signals
      .filter((signal) => signal.category === "auth-failure")
      .map((signal) => signal.key);
    // Deduplicate while preserving first-seen order so the contributing list is
    // stable across messages that repeat a key (e.g. several failed methods).
    const contributingSignals = [...new Set([...authFailureKeys, ...consistencyKeys])];

    return [
      {
        key: "composite.unauthenticatedFromSpoof",
        category: "composite",
        severity: "high",
        message:
          "Visible From domain is not backed by aligned authentication and another sender identifier disagrees with it.",
        data: {
          fromDomain: metrics.fromDomain,
          anyAuthAligned: authentication.anyAuthAligned,
          dmarcPass: authentication.dmarcPass,
          contributingSignals,
        },
      },
    ];
  },
};
