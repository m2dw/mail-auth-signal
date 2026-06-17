import {
  allDomainsMatch,
  domainsExactlyMatch,
  extractDomainFromMailbox,
  extractDomainFromMessageId,
  extractDomainsFromMailboxList,
} from "./domains.js";
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

  // Reply-To is a mailbox-list and may appear more than once; collect every
  // domain across all header instances, preserving order and dropping repeats.
  const replyToDomains = [
    ...new Set(
      getHeaderValues(headers, "reply-to").flatMap(extractDomainsFromMailboxList),
    ),
  ];
  const replyToDomainMatchesFromDomain = allDomainsMatch(fromDomain, replyToDomains);

  const authenticationResults = getHeaderValues(headers, "authentication-results").map((raw) =>
    parseAuthenticationResults(raw, trustedAuthservIds),
  );

  return {
    fromDomain,
    messageIdDomain,
    messageIdDomainMatchesFromDomain,
    replyToDomains,
    replyToDomainMatchesFromDomain,
    authenticationResults,
  };
}
