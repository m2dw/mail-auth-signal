import type { Rule } from "../types.js";

/**
 * Flags Authentication-Results headers stamped by an authserv-id the caller did
 * not declare as trusted.
 *
 * Attacker note: anyone can forge an Authentication-Results header upstream, so
 * results from an unknown authserv-id must not be treated as authoritative.
 * This rule only reports the mismatch; the caller's trustedAuthservIds list is
 * the sole source of truth for which ids are believed.
 */
export const untrustedAuthservIdRule: Rule = {
  key: "authResults.untrustedAuthservId",
  description: "An Authentication-Results header came from an untrusted authserv-id.",
  evaluate({ metrics }) {
    return metrics.authenticationResults
      .filter((header) => !header.trusted)
      .map((header) => ({
        key: "authResults.untrustedAuthservId",
        severity: "low" as const,
        message: "Authentication-Results header was produced by an untrusted authserv-id.",
        data: { authservId: header.authservId },
      }));
  },
};
