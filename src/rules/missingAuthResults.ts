import type { Rule } from "../types.js";

/**
 * Flags messages that carry no Authentication-Results header at all.
 *
 * False-positive note: a missing header is not proof of abuse — it often just
 * means the caller's mail system did not stamp one, or the caller passed an
 * incomplete header set. The signal is therefore informational-to-medium and
 * the caller decides whether absence matters for its trust model.
 */
export const missingAuthResultsRule: Rule = {
  key: "auth.results.missing",
  description: "No Authentication-Results header was present on the message.",
  evaluate({ metrics }) {
    if (metrics.authenticationResults.length > 0) return [];
    return [
      {
        key: "auth.results.missing",
        category: "absence",
        severity: "medium",
        message: "No Authentication-Results header was found.",
      },
    ];
  },
};
