import type { Rule } from "../types.js";

/**
 * Flags messages whose Message-ID domain differs from the From domain.
 *
 * False-positive note: a mismatch is common and legitimate — mailing lists,
 * ESPs, and forwarders routinely stamp Message-IDs from their own domain. The
 * signal is therefore low severity and exists only as a consistency hint; the
 * comparison is skipped entirely when either domain is absent (match === null).
 */
export const messageIdDomainMismatchRule: Rule = {
  key: "messageId.domainMismatch",
  description: "The Message-ID domain does not match the From domain.",
  evaluate({ metrics }) {
    if (metrics.messageIdDomainMatchesFromDomain !== false) return [];
    return [
      {
        key: "messageId.domainMismatch",
        severity: "low",
        message: "Message-ID domain differs from the From domain.",
        data: {
          fromDomain: metrics.fromDomain,
          messageIdDomain: metrics.messageIdDomain,
        },
      },
    ];
  },
};
