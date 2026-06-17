import type { Rule } from "../types.js";

/**
 * Flags messages whose Reply-To domain differs from the From domain.
 *
 * Attacker pattern: a spoofer (classically business-email-compromise and
 * reply-chain fraud) displays a recognizable party in From but sets Reply-To to
 * a domain they control, so a recipient who hits "Reply" silently routes the
 * answer — wire instructions, credentials, a conversation — to the attacker
 * rather than the apparent sender. Because Reply-To steers replies away from the
 * From address, a domain that disagrees with the claimed From domain is a
 * consistency hint that the visible sender is not who would receive the reply.
 *
 * False-positive note: a divergent Reply-To is also routine and legitimate.
 * Marketing and transactional mail is frequently sent from one domain (or an
 * ESP) while replies are steered to a support, helpdesk, or list domain; a
 * person may send as a corporate address but ask for replies at a personal one.
 * The signal is therefore low severity and exists only as a consistency hint,
 * never a verdict; the caller correlates it with authentication results and its
 * own policy before acting.
 *
 * Noise control for missing/malformed input: the comparison is skipped entirely
 * (replyToDomainMatchesFromDomain === null) when there is nothing to compare —
 * a missing From, a missing Reply-To, or a Reply-To whose mailboxes the parser
 * could not resolve to a real dotted domain. A missing Reply-To by itself
 * therefore emits no signal at all rather than a noisy, low-confidence one. When
 * Reply-To carries several mailboxes (or appears in several headers), a single
 * domain that differs from From is enough to flag, since that lone divergent
 * reply target is exactly the attacker pattern above.
 */
export const replyToDomainMismatchRule: Rule = {
  key: "replyTo.domainMismatch",
  description: "A Reply-To domain does not match the From domain.",
  evaluate({ metrics }) {
    if (metrics.replyToDomainMatchesFromDomain !== false) return [];
    const mismatchedDomains = metrics.replyToDomains.filter(
      (domain) => domain !== metrics.fromDomain,
    );
    return [
      {
        key: "replyTo.domainMismatch",
        severity: "low",
        message: "Reply-To domain differs from the From domain.",
        data: {
          fromDomain: metrics.fromDomain,
          replyToDomains: metrics.replyToDomains,
          mismatchedDomains,
        },
      },
    ];
  },
};
