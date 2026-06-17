import type { Rule } from "../types.js";

/**
 * Flags messages whose Return-Path (envelope reverse-path) domain differs from
 * the From domain.
 *
 * Attacker pattern: a spoofer displays a recognizable party in From but the
 * envelope sender — the reverse-path bounces and SMTP-level identity attach to —
 * is a domain they control. Because the Return-Path is the address that actually
 * accepted responsibility for delivery, a domain that disagrees with the claimed
 * From is a consistency hint that the visible sender is not the true originator.
 *
 * False-positive note: a divergent Return-Path is also routine and legitimate.
 * ESPs and bulk senders almost always use a bounce/VERP domain (or a subdomain)
 * distinct from the brand in From, and forwarders rewrite the reverse-path to
 * their own domain. The comparison is exact, so even a subdomain of From counts
 * as a mismatch. The signal is therefore low severity and exists only as a
 * consistency hint, never a verdict; the caller correlates it with SPF/DKIM/DMARC
 * results (smtp.mailfrom alignment in particular) and its own policy before
 * acting.
 *
 * Noise control for missing/malformed input: the comparison is skipped entirely
 * (returnPathDomainMatchesFromDomain === null) when there is nothing to compare
 * — a missing From, a missing Return-Path, a null reverse-path (`<>`, a bounce),
 * or a Return-Path the parser could not resolve to a real dotted domain. A
 * missing or null Return-Path therefore emits no signal at all rather than a
 * noisy, low-confidence one.
 */
export const returnPathDomainMismatchRule: Rule = {
  key: "returnPath.domainMismatch",
  description: "The Return-Path domain does not match the From domain.",
  evaluate({ metrics }) {
    if (metrics.returnPathDomainMatchesFromDomain !== false) return [];
    // The match is false only when both domains resolved and differ, so the
    // single Return-Path domain is the lone divergent one. Reported as a
    // mismatchedDomains array too, so every consistency signal carries the same
    // divergent-domain field shape regardless of how many domains it compares.
    const mismatchedDomains = metrics.returnPathDomain === null ? [] : [metrics.returnPathDomain];
    return [
      {
        key: "returnPath.domainMismatch",
        category: "consistency",
        severity: "low",
        message: "Return-Path domain differs from the From domain.",
        data: {
          fromDomain: metrics.fromDomain,
          returnPathDomain: metrics.returnPathDomain,
          mismatchedDomains,
        },
      },
    ];
  },
};
