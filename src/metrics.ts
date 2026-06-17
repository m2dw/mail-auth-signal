import { domainsExactlyMatch, extractDomainFromMailbox, extractDomainFromMessageId } from "./domains.js";
import { getFirstHeaderValue, getHeaderValues, normalizeHeaders } from "./normalizeHeaders.js";
import { parseAuthenticationResults } from "./parseAuthenticationResults.js";
import type { AnalyzeInput, MessageMetrics } from "./types.js";

/**
 * Extract serializable facts from a message, with no interpretation applied.
 *
 * This is the parsing + metric-extraction half of the pipeline, kept separate
 * from rule evaluation so callers (and migrated rules) can inspect, log, or
 * snapshot the raw facts independently of any signals. The result contains no
 * opinions: it is the input every Rule evaluates against.
 */
export function extractMetrics(input: AnalyzeInput): MessageMetrics {
  const headers = normalizeHeaders(input.headers);
  const trustedAuthservIds = input.options?.trustedAuthservIds ?? [];

  const fromDomain = extractDomainFromMailbox(getFirstHeaderValue(headers, "from"));
  const messageIdDomain = extractDomainFromMessageId(getFirstHeaderValue(headers, "message-id"));
  const messageIdDomainMatchesFromDomain = domainsExactlyMatch(fromDomain, messageIdDomain);
  const authenticationResults = getHeaderValues(headers, "authentication-results").map((raw) =>
    parseAuthenticationResults(raw, trustedAuthservIds),
  );

  return {
    fromDomain,
    messageIdDomain,
    messageIdDomainMatchesFromDomain,
    authenticationResults,
  };
}
