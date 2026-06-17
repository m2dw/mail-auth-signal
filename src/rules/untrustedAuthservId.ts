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
 * Trust resolution honors the RuleContext contract without diverging from
 * analyzeMessage: when the caller passes trustedAuthservIds to runRules, trust
 * is recomputed from that list (callers using the separated API can declare
 * trust at rule time). When trustedAuthservIds is omitted, the metrics' baked-in
 * header.trusted flag is used instead, so runRules(extractMetrics(input)) with
 * no second argument reports the same trust analyzeMessage(input) did rather
 * than treating every already-trusted header as untrusted.
 */
export const untrustedAuthservIdRule: Rule = {
  key: "authResults.untrustedAuthservId",
  scope: "header",
  description: "An Authentication-Results header came from an untrusted authserv-id.",
  evaluate({ metrics, options }) {
    const overrideTrustedIds = options.trustedAuthservIds;
    return metrics.authenticationResults
      .filter((header) =>
        overrideTrustedIds === undefined
          ? !header.trusted
          : !isTrustedAuthservId(header.authservId, overrideTrustedIds),
      )
      .map((header) => ({
        key: "authResults.untrustedAuthservId",
        severity: "low" as const,
        message: "Authentication-Results header was produced by an untrusted authserv-id.",
        data: { authservId: header.authservId },
      }));
  },
};
