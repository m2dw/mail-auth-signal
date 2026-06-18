import type { CompositeRule, Signal } from "../../types.js";

/**
 * Composite (candidate): a visible From at a known public mailbox provider that
 * the message's own authentication does not back up.
 *
 * Attacker model — borrowing a consumer mailbox brand. The attacker puts a major
 * public mailbox domain in the visible From (`From: someone@outlook.com`) to look
 * like ordinary personal mail, while the real infrastructure is elsewhere — a
 * different Return-Path, a Message-ID under another provider, failed DMARC/SPF.
 * The logged real-world shape was From `outlook.com` with Return-Path `icloud.com`
 * and a Message-ID under `yahoo.co.jp`, all failing authentication.
 *
 * Why public-mailbox membership sharpens "not aligned" into a candidate. The
 * catalog (see defaultPublicMailboxProviders) lists consumer mailbox domains that
 * publish enforcing DMARC and send only through their own infrastructure, so
 * genuine mail from them *always* presents an aligned, trusted, passing SPF or
 * DKIM identifier for the From domain. A visible From at one of these domains with
 * no aligned authentication therefore contradicts how the domain actually sends —
 * a meaningful spoof candidate on its own, without needing a second divergent
 * identifier the way the generic unauthenticatedFromSpoof composite does. (It is a
 * *candidate*, not a confirmation: a forwarder that breaks both SPF and DKIM on
 * genuine consumer mail lands here too, which is why severity is medium and the
 * Review/Junk/ignore decision stays with the caller.)
 *
 * Guards (false-positive control, mirroring the other From-spoof composites so the
 * same trust discipline applies):
 *   - fromDomainIsPublicMailboxProvider === true: the whole premise is a public
 *     mailbox From, so a non-catalog ordinary domain never reaches here. Catalog
 *     membership is computed by extractMetrics from the bundled (or caller-
 *     overridden) catalog with no external brand/word list.
 *   - trustedHeaderCount > 0 AND at least one trusted SPF/DKIM/DMARC result: "not
 *     aligned" must reflect a sender-auth check that actually ran. With no trusted
 *     header (or a trusted header carrying only non-sender-auth results like
 *     arc=pass) anyAuthAligned is vacuously false, and flagging that would fire on
 *     ordinary public-mailbox mail we simply could not verify. The
 *     missing/untrusted base signals cover that case; this stays silent.
 *   - anyAuthAligned === false: a message with even one aligned, trusted, passing
 *     SPF or DKIM identifier for the From domain is authenticated as that domain
 *     (DMARC's own logic), so a forwarder that fails SPF but keeps an aligned DKIM
 *     signature does not trip this.
 *   - no aligned trusted DMARC pass for the visible From: a trusted verifier can
 *     report a bare `dmarc=pass header.from=From` aggregate with no SPF/DKIM method
 *     lines, leaving anyAuthAligned vacuously false even though an aligned
 *     identifier satisfied the From's DMARC policy. That is authenticated mail, so
 *     it is suppressed — only a pass whose header.from equals the visible From
 *     counts (a pass for a *different* header.from is itself the
 *     dmarc.headerFromMismatch spoof tell, and an untrusted pass is forge-able).
 *
 * Not attacker-triggerable against a third party. The only way to *suppress* this
 * is to present aligned, trusted authentication for the public-mailbox From, which
 * a spoofer of a domain they do not control cannot do. It cannot be *manufactured*
 * against honest public-mailbox mail by injecting a forge-able Authentication-
 * Results header either: anyAuthAligned and the aligned-DMARC-pass check count only
 * trusted, passing results, so a self-stamped header neither makes a spoof read as
 * aligned nor flips honest aligned mail to unaligned. An attacker can only raise it
 * on their own spoof.
 *
 * Severity medium: a single-identifier candidate (public-mailbox From plus missing
 * alignment), weaker than the high-confidence unauthenticatedFromSpoof which also
 * requires a divergent authoritative identifier. It stays an observation; the
 * caller owns the threshold and action. `contributingSignals` names the trusted
 * auth-failure signals that evidenced the missing alignment (it may be empty when
 * the From domain simply published no passing result — e.g. `dmarc=none` — yet the
 * absence of any aligned trusted pass is itself the basis).
 */
export const publicMailboxSpoofingCandidateRule: CompositeRule = {
  key: "composite.publicMailboxSpoofingCandidate",
  description:
    "The visible From is a known public mailbox provider domain with no aligned, trusted authentication.",
  evaluate({ metrics, signals }): Signal[] {
    const { authentication, fromDomain, senderIdentity } = metrics;
    // Premise: a public mailbox provider From. Non-catalog ordinary domains and a
    // null From never reach the rest of the rule.
    if (!senderIdentity.fromDomainIsPublicMailboxProvider) return [];
    // No trusted header means nothing was actually evaluated; do not manufacture a
    // candidate from unverifiable mail.
    if (authentication.trustedHeaderCount === 0) return [];
    // Require at least one trusted SPF/DKIM/DMARC result so "not aligned" reflects a
    // sender-auth check that ran, not a trusted header carrying only arc=pass.
    const hasTrustedSenderAuth =
      authentication.spfResults.some((result) => result.trusted) ||
      authentication.dkimResults.some((result) => result.trusted) ||
      authentication.dmarcResults.some((result) => result.trusted);
    if (!hasTrustedSenderAuth) return [];
    // An aligned, trusted, passing identifier authenticates the public-mailbox From.
    if (authentication.anyAuthAligned !== false) return [];
    // A trusted DMARC pass for the *visible* From also authenticates it, even as a
    // bare aggregate with no SPF/DKIM method lines (which leaves anyAuthAligned
    // vacuously false). Only a pass whose header.from equals the From counts.
    const hasAlignedTrustedDmarcPass = authentication.dmarcResults.some(
      (result) =>
        result.trusted &&
        result.result === "pass" &&
        result.headerFrom !== null &&
        result.headerFrom === fromDomain,
    );
    if (hasAlignedTrustedDmarcPass) return [];

    // Basis trace: the trusted auth-failure signals that evidence the missing
    // alignment. An untrusted failure is the attacker's own assertion and is never
    // part of the basis. May be empty (e.g. dmarc=none emits no failure) — the
    // absence of any aligned trusted pass is itself sufficient evidence.
    const contributingSignals = [
      ...new Set(
        signals
          .filter((signal) => signal.category === "auth-failure" && signal.data?.trusted === true)
          .map((signal) => signal.key),
      ),
    ];

    return [
      {
        key: "composite.publicMailboxSpoofingCandidate",
        category: "composite",
        severity: "medium",
        message:
          "Visible From is a public mailbox provider domain but the message has no aligned, trusted authentication.",
        data: {
          fromDomain,
          publicMailboxProviderId: senderIdentity.publicMailboxProviderId,
          anyAuthAligned: authentication.anyAuthAligned,
          dmarcPass: authentication.dmarcPass,
          contributingSignals,
        },
      },
    ];
  },
};
