import { isTrustedAuthservId } from "../parseAuthenticationResults.js";
import type { Rule } from "../types.js";

/**
 * Flags Authentication-Results headers stamped by an authserv-id the caller did
 * not declare as trusted.
 *
 * Attacker note: anyone can forge an Authentication-Results header upstream, so
 * results from an unknown authserv-id must not be treated as authoritative.
 * This rule only reports the mismatch; the caller's trustedAuthservIds list is
 * the sole source of truth for which ids are believed.
 *
 * Trust is recomputed here from options.trustedAuthservIds rather than read from
 * the metrics' baked-in header.trusted flag, so callers using the separated API
 * (extract metrics once, then runRules with caller policy) get rules that honor
 * the trustedAuthservIds they pass to runRules — per the RuleContext contract.
 */
export const untrustedAuthservIdRule: Rule = {
  key: "authResults.untrustedAuthservId",
  description: "An Authentication-Results header came from an untrusted authserv-id.",
  evaluate({ metrics, options }) {
    const trustedAuthservIds = options.trustedAuthservIds ?? [];
    return metrics.authenticationResults
      .filter((header) => !isTrustedAuthservId(header.authservId, trustedAuthservIds))
      .map((header) => ({
        key: "authResults.untrustedAuthservId",
        severity: "low" as const,
        message: "Authentication-Results header was produced by an untrusted authserv-id.",
        data: { authservId: header.authservId },
      }));
  },
};
