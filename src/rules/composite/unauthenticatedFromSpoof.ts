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
 *   - a parseable From domain (metrics.fromDomain !== null): the whole premise is
 *     a *visible-From* spoof, so there must be a visible From to spoof. Without
 *     one, the From-comparison consistency signals (returnPath/smtpMailfrom/dkim/
 *     dmarc/replyTo/messageId mismatch) are all silent — they compare against From
 *     and report null when it is absent — and the only consistency signal that can
 *     still fire is envelopeSender.domainDisagreement, which compares Return-Path
 *     to smtp.mailfrom and never to From. Accepting that as the spoof tell would
 *     emit a high verdict with fromDomain:null for malformed/system mail whose two
 *     envelope views merely disagree, with nothing impersonating a visible sender.
 *     Requiring a From keeps the consistency evidence anchored to it: once From is
 *     present, an envelope-sender disagreement also implies a Return-Path or
 *     smtp.mailfrom domain that mismatches From, so a real From-comparison signal
 *     is always present alongside it.
 *   - trustedHeaderCount > 0: the verdict needs a basis. With no trusted
 *     Authentication-Results header we never evaluated anything, so anyAuthAligned
 *     is vacuously false and a mismatch could be perfectly benign mail we simply
 *     could not check. The missing/untrusted base signals cover that case; this
 *     composite stays silent rather than guess.
 *   - at least one trusted SPF/DKIM/DMARC result: a trusted header can carry only
 *     results that are not sender authentication (e.g. arc=pass), which still
 *     leaves anyAuthAligned vacuously false. Without this guard a message we never
 *     evaluated for SPF/DKIM/DMARC would read as a confirmed unauthenticated From,
 *     so "not aligned" is only treated as evidence once a sender-auth check has
 *     actually run.
 *   - anyAuthAligned === false: a message with even one aligned, trusted, passing
 *     SPF or DKIM identifier for the From domain is, by DMARC's own logic,
 *     authenticated as that domain — so a forwarder that fails SPF but keeps an
 *     aligned DKIM signature does not trip this. Only the genuinely
 *     unauthenticated From reaches here.
 *   - at least one *authoritative* divergent identifier: a misconfigured-but-honest
 *     sender whose own identifiers all still name the From domain (it just failed to
 *     authenticate) produces auth-failure signals but no consistency mismatch, so it
 *     is left to the base auth.method.failure signals. Crucially, the mismatch must
 *     be one an upstream attacker cannot forge: a message-header mismatch (Message-ID,
 *     Reply-To, Return-Path), the trusted-only DMARC header.from mismatch, or an SPF
 *     smtp.mailfrom / passing-DKIM header.d mismatch carried by a *trusted* header.
 *     The base smtpMailfrom/dkim/envelopeSender consistency signals read every AR
 *     header, trusted or not, so an injected untrusted `dkim=pass header.d=evil.test`
 *     or `spf ... smtp.mailfrom=evil.test` is not accepted on its own — otherwise an
 *     attacker could pin a forged mismatch onto an honest failure and escalate it.
 *
 * Not attacker-triggerable as a false positive against a third party: the only
 * way to *suppress* this signal is to authenticate the From domain (which a
 * spoofer of someone else's domain cannot) or to make every identifier agree with
 * the From (which, for a domain they do not control, means actually being that
 * domain). And it cannot be *manufactured* against an honest sender by injecting a
 * forge-able Authentication-Results header, because only trusted AR-derived or
 * message-header mismatches qualify as evidence. An attacker can only trigger it on
 * their own spoof.
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
    const { authentication, fromDomain } = metrics;
    // A visible-From spoof needs a visible From. With no parseable From domain the
    // From-comparison consistency signals cannot fire, and the only consistency
    // signal that can — envelopeSender.domainDisagreement — never compares to From,
    // so without this guard malformed/system mail with a disagreeing envelope would
    // emit a high verdict carrying fromDomain:null.
    if (fromDomain === null) return [];
    // No trusted header means nothing was actually evaluated; do not manufacture
    // a verdict from an unverifiable message.
    if (authentication.trustedHeaderCount === 0) return [];
    // A trusted header is not enough on its own: it may carry only results that are
    // not sender authentication (e.g. arc=pass), which leaves anyAuthAligned
    // vacuously false. Require at least one trusted SPF/DKIM/DMARC result so "not
    // aligned" reflects a sender-auth check that actually ran on this message,
    // rather than treating an unevaluated message as a confirmed unauthenticated
    // spoof.
    const hasTrustedSenderAuth =
      authentication.spfResults.some((result) => result.trusted) ||
      authentication.dkimResults.some((result) => result.trusted) ||
      authentication.dmarcResults.some((result) => result.trusted);
    if (!hasTrustedSenderAuth) return [];
    // An aligned, trusted, passing identifier authenticates the From domain.
    if (authentication.anyAuthAligned !== false) return [];

    const consistencyKeys = signals
      .filter((signal) => signal.category === "consistency")
      .map((signal) => signal.key);

    // The divergent-identifier evidence must be authoritative — something an
    // upstream attacker cannot forge by injecting their own Authentication-Results
    // header. Two kinds qualify:
    //   - message-header mismatches (Message-ID, Reply-To, Return-Path) and the
    //     trusted-only DMARC header.from mismatch, none of which are AR-forgeable; and
    //   - an SPF smtp.mailfrom or a passing DKIM header.d that disagrees with From
    //     carried by a *trusted* Authentication-Results header.
    // The base smtpMailfrom/dkim/envelopeSender consistency signals are derived from
    // every AR header, trusted or not, so an injected untrusted `dkim=pass
    // header.d=evil.test` or `spf ... smtp.mailfrom=evil.test` would otherwise let an
    // attacker manufacture a mismatch and escalate an honest auth failure or
    // misconfiguration to a high spoof. Re-checking trust at the source for those
    // AR-derived tells closes that path while still accepting genuine disagreement.
    const authoritativeConsistencyKeys = new Set([
      "messageId.domainMismatch",
      "replyTo.domainMismatch",
      "returnPath.domainMismatch",
      "dmarc.headerFromMismatch",
    ]);
    const hasMessageHeaderMismatch = consistencyKeys.some((key) =>
      authoritativeConsistencyKeys.has(key),
    );
    const hasTrustedSpfMismatch = authentication.spfResults.some(
      (result) =>
        result.trusted && result.smtpMailfrom !== null && result.smtpMailfrom !== fromDomain,
    );
    const hasTrustedDkimMismatch = authentication.dkimResults.some(
      (result) =>
        result.trusted &&
        result.result === "pass" &&
        result.headerD !== null &&
        result.headerD !== fromDomain,
    );
    // Without an authoritative divergent identifier this is an honest
    // authentication failure (or a mismatch only a forged upstream header asserts),
    // not evidence of impersonation; leave it to the base auth-failure signals.
    if (!hasMessageHeaderMismatch && !hasTrustedSpfMismatch && !hasTrustedDkimMismatch) {
      return [];
    }

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
          fromDomain,
          anyAuthAligned: authentication.anyAuthAligned,
          dmarcPass: authentication.dmarcPass,
          contributingSignals,
        },
      },
    ];
  },
};
