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
 *   - not aligned under the PSL-aware (organizational) view: a message with even
 *     one aligned, trusted, passing SPF or DKIM identifier for the From domain is,
 *     by DMARC's own logic, authenticated as that domain — so a forwarder that
 *     fails SPF but keeps an aligned DKIM signature does not trip this. This honors
 *     organizational (relaxed) alignment as the practical default: a From subdomain
 *     whose trusted, passing identifier sits on the same registrable domain (From
 *     `news.example.co.jp`, DKIM `header.d=example.co.jp`, with a caller-supplied
 *     resolver) is DMARC-relaxed authenticated even though the exact-domain
 *     anyAuthAligned reads the subdomain difference as unaligned. Without it the
 *     rule would emit a spoof on legitimate relaxed-aligned subdomain mail, because
 *     the exact SPF/DKIM mismatch consistency signals remain present. When no
 *     resolver is supplied the organizational view degrades to exact comparison, so
 *     this is a strict superset of the exact check and never suppresses a genuine
 *     spoof. Only the genuinely unauthenticated From reaches here.
 *   - no aligned trusted DMARC pass: a trusted Authentication-Results header can
 *     report only an aggregate DMARC verdict (`dmarc=pass header.from=brand.example`)
 *     with no SPF/DKIM method lines, which leaves anyAuthAligned vacuously false even
 *     though the trusted verifier confirmed DMARC — and therefore an aligned SPF or
 *     DKIM identifier — passed for the visible From. Treating that as unauthenticated
 *     would let any benign identifier mismatch (e.g. a different Message-ID host) emit
 *     a high spoof on mail the verifier explicitly vouched for. A trusted DMARC pass
 *     whose header.from shares a registrable domain with the visible From therefore also
 *     short-circuits the rule (organizational.dmarcPassAligned) — the same PSL-aware
 *     comparison as the alignment guard, so a `dmarc=pass header.from=example.co.jp` for
 *     a From of `news.example.co.jp` is honored, and with no resolver it degrades to
 *     exact comparison. Only a pass for the same organization counts: a trusted pass for
 *     a *different* registrable domain is itself a spoof tell (dmarc.headerFromMismatch),
 *     not authentication of the visible From, and an untrusted DMARC pass is forge-able.
 *     An attacker
 *     spoofing a domain they do not control cannot make the trusted verifier emit an
 *     aligned DMARC pass for it, so this suppression is not attacker-triggerable.
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
    // Honor the PSL-aware (organizational) view as the practical default so a
    // DMARC-relaxed aligned subdomain (From news.example.co.jp authenticated by an
    // identifier on example.co.jp under a supplied resolver) is treated as
    // authenticated, not spoofed — even though the exact-domain check below still
    // reads the subdomain difference as unaligned and the exact SPF/DKIM mismatch
    // consistency signals remain present. With no resolver the organizational view
    // degrades to exact comparison, so this never suppresses a genuine spoof.
    if (authentication.anyAuthAligned !== false) return [];
    if (authentication.organizational.anyAuthAligned) return [];
    // A trusted verifier's DMARC pass for the visible From's *organization* also
    // authenticates that From, even when the same header omits the SPF/DKIM method
    // lines anyAuthAligned is computed from (a bare `dmarc=pass header.from=From`
    // aggregate leaves anyAuthAligned vacuously false). DMARC passes only when an
    // aligned SPF or DKIM identifier satisfied the From domain's policy, so this is
    // not an unauthenticated From. organizational.dmarcPassAligned applies the same
    // PSL-aware (relaxed) comparison as the alignment check above, so a trusted
    // `dmarc=pass header.from=example.co.jp` for a From of `news.example.co.jp`
    // suppresses the spoof; with no resolver it degrades to exact comparison. A
    // trusted pass for a *different* registrable domain is the dmarc.headerFromMismatch
    // spoof tell rather than authentication, and an untrusted pass is forge-able —
    // both excluded because dmarcPassAligned counts only trusted, organizationally
    // aligned passes.
    if (authentication.organizational.dmarcPassAligned) return [];

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

    // The trace must name only the lower-layer signals this rule actually accepted
    // as evidence, not every signal of the right category. A forge-able untrusted
    // Authentication-Results header can produce a base auth-failure (its own claimed
    // fail) or consistency mismatch (e.g. dkim.domainMismatch from an injected
    // `dkim=pass header.d=evil.test`) that the gates above explicitly rejected;
    // reporting those keys would point the rationale at signals that did not justify
    // the high composite, misleading a caller displaying or auditing it.
    //
    // Auth-failure: keep only trusted failures. An untrusted failure is the
    // attacker's own assertion and never part of the basis (the unauthenticated leg
    // rests on a trusted sender-auth check, not on a forge-able one).
    const trustedAuthFailureKeys = signals
      .filter((signal) => signal.category === "auth-failure" && signal.data?.trusted === true)
      .map((signal) => signal.key);
    // Consistency: keep only the mismatches that qualified as authoritative evidence
    // above — the non-AR-forgeable message-header / DMARC keys, plus the
    // trusted-header SPF/DKIM mismatches (their base signals are derived from every
    // header, so include them only when a *trusted* result actually disagreed).
    const acceptedConsistencyKeys = consistencyKeys.filter(
      (key) =>
        authoritativeConsistencyKeys.has(key) ||
        (key === "smtpMailfrom.domainMismatch" && hasTrustedSpfMismatch) ||
        (key === "dkim.domainMismatch" && hasTrustedDkimMismatch),
    );
    // Deduplicate while preserving first-seen order so the contributing list is
    // stable across messages that repeat a key (e.g. several failed methods).
    const contributingSignals = [
      ...new Set([...trustedAuthFailureKeys, ...acceptedConsistencyKeys]),
    ];

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
