import type { Rule } from "../types.js";

/**
 * Flags messages whose passing DKIM signing domain (`header.d`) differs from the
 * From domain.
 *
 * Attacker pattern: a spoofer puts a recognizable brand in From but the message
 * is DKIM-signed by a domain they control. The signature verifies — DKIM only
 * proves the signing domain authorized the content, not that it owns the From —
 * so an unaligned but passing DKIM is the classic shape DMARC's DKIM-alignment
 * check exists to catch: authenticated mail that is nonetheless not vouched for
 * by the visible sender's domain.
 *
 * Pass-only by construction: this rule reads dkimDomains, which the metric layer
 * populates exclusively from DKIM results that passed. A failed, temperror,
 * permerror, neutral, or none DKIM signature authenticates nothing, so its
 * header.d never enters the comparison — a broken signature claiming header.d =
 * the From domain must not read as alignment, and a broken signature claiming an
 * attacker domain must not manufacture a mismatch. authMethodFailureRule
 * separately surfaces the failure itself.
 *
 * False-positive note: a divergent passing header.d is also routine and
 * legitimate. ESPs and platforms commonly sign brand mail with their own domain
 * or a subdomain, and a message may legitimately carry several DKIM signatures
 * (e.g. the author domain plus a forwarder/list). The comparison is exact, so a
 * subdomain of From also counts as a mismatch. The signal is therefore low
 * severity and exists only as a consistency hint, never a verdict; the caller
 * correlates it with the actual DKIM/DMARC results and its own policy — including
 * whether at least one signature *did* align — before acting.
 *
 * Trust caveat: header.d is read from every Authentication-Results header,
 * including untrusted (forge-able) ones, so this signal is a hint, not proof —
 * untrustedAuthservIdRule separately flags headers from unknown authserv-ids so
 * the caller can discount them.
 *
 * Noise control for missing/malformed input: the comparison is skipped entirely
 * (dkimDomainMatchesFromDomain === null) when there is nothing to compare — a
 * missing From, no passing DKIM result, or a header.d the parser could not
 * resolve to a real dotted domain. A missing or failed DKIM therefore emits no
 * signal at all. When several signatures carry header.d values, a single domain
 * that differs from From is enough to flag, since one divergent signing domain
 * is the attacker pattern above.
 */
export const dkimDomainMismatchRule: Rule = {
  key: "dkim.domainMismatch",
  description: "A passing DKIM header.d signing domain does not match the From domain.",
  evaluate({ metrics }) {
    if (metrics.dkimDomainMatchesFromDomain !== false) return [];
    const mismatchedDomains = metrics.dkimDomains.filter(
      (domain) => domain !== metrics.fromDomain,
    );
    return [
      {
        key: "dkim.domainMismatch",
        severity: "low",
        message: "DKIM header.d signing domain differs from the From domain.",
        data: {
          fromDomain: metrics.fromDomain,
          dkimDomains: metrics.dkimDomains,
          mismatchedDomains,
        },
      },
    ];
  },
};
