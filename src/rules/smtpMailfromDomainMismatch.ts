import type { Rule } from "../types.js";

/**
 * Flags messages whose SPF `smtp.mailfrom` domain differs from the From domain.
 *
 * Attacker pattern: the same envelope-sender spoof the Return-Path rule targets,
 * seen instead through the SPF-authenticated envelope-from recorded in
 * Authentication-Results. A recognizable brand in From paired with an
 * attacker-controlled MAIL FROM domain is classic direct-domain spoofing; this
 * is the mechanical basis for DMARC's SPF-alignment check.
 *
 * False-positive note: a divergent smtp.mailfrom is also routine and legitimate.
 * Forwarders and mailing lists re-send under their own envelope (the very reason
 * SPF softfails on forwarded mail), and ESPs send brand mail under a bounce
 * domain. The comparison is exact, so a subdomain of From also counts as a
 * mismatch. The signal is therefore low severity and exists only as a
 * consistency hint, never a verdict; the caller correlates it with the actual
 * SPF/DMARC results and its own policy before acting.
 *
 * Trust caveat: smtp.mailfrom is read from every Authentication-Results header,
 * including untrusted (forge-able) ones, so this signal is a hint, not proof —
 * untrustedAuthservIdRule separately flags headers from unknown authserv-ids so
 * the caller can discount them.
 *
 * Noise control for missing/malformed input: the comparison is skipped entirely
 * (smtpMailfromDomainMatchesFromDomain === null) when there is nothing to
 * compare — a missing From, no SPF result, or a smtp.mailfrom (including a null
 * `<>`) the parser could not resolve to a real dotted domain. A missing SPF
 * smtp.mailfrom therefore emits no signal at all. When several headers carry
 * smtp.mailfrom values, a single domain that differs from From is enough to
 * flag, since one divergent envelope sender is the attacker pattern above.
 */
export const smtpMailfromDomainMismatchRule: Rule = {
  key: "smtpMailfrom.domainMismatch",
  description: "An SPF smtp.mailfrom domain does not match the From domain.",
  evaluate({ metrics }) {
    if (metrics.smtpMailfromDomainMatchesFromDomain !== false) return [];
    const mismatchedDomains = metrics.smtpMailfromDomains.filter(
      (domain) => domain !== metrics.fromDomain,
    );
    return [
      {
        key: "smtpMailfrom.domainMismatch",
        category: "consistency",
        severity: "low",
        message: "SPF smtp.mailfrom domain differs from the From domain.",
        data: {
          fromDomain: metrics.fromDomain,
          smtpMailfromDomains: metrics.smtpMailfromDomains,
          mismatchedDomains,
        },
      },
    ];
  },
};
