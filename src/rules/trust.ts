import { isTrustedAuthservId } from "../parseAuthenticationResults.js";
import type { AnalyzeOptions, AuthenticationResultsHeader } from "../types.js";

/**
 * Resolve whether an Authentication-Results header should be treated as
 * authoritative for the current evaluation.
 *
 * This honors the RuleContext contract without diverging from analyzeMessage:
 *
 *   - When the caller passes trustedAuthservIds (e.g. directly to runRules),
 *     trust is recomputed from that list so callers using the separated API can
 *     declare trust at rule time.
 *   - When trustedAuthservIds is omitted, the metrics' baked-in header.trusted
 *     flag is used instead, so runRules(extractMetrics(input)) with no second
 *     argument reports the same trust analyzeMessage(input) did rather than
 *     treating every already-trusted header as untrusted.
 *
 * Centralizing this keeps every Authentication-Results rule resolving trust the
 * same way, which matters because trust drives whether a forged header's claims
 * are believed at all.
 */
export function resolveHeaderTrust(
  header: AuthenticationResultsHeader,
  options: AnalyzeOptions,
): boolean {
  const overrideTrustedIds = options.trustedAuthservIds;
  return overrideTrustedIds === undefined
    ? header.trusted
    : isTrustedAuthservId(header.authservId, overrideTrustedIds);
}
