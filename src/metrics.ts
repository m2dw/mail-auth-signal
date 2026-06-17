import {
  allDomainsMatch,
  domainsExactlyMatch,
  extractDkimSigningDomain,
  extractDomainFromMailbox,
  extractDomainFromMessageId,
  extractDomainsFromMailboxList,
  extractEnvelopeSenderDomain,
  isNullReversePath,
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

  // Return-Path is the envelope reverse-path. Use the first instance (like From
  // and Message-ID); a null reverse-path (`<>`) and a missing header both leave
  // no domain to compare, but the flag keeps them distinguishable for callers.
  const returnPathValue = getFirstHeaderValue(headers, "return-path");
  const returnPathNullReversePath = isNullReversePath(returnPathValue);
  const returnPathDomain = extractEnvelopeSenderDomain(returnPathValue);
  const returnPathDomainMatchesFromDomain = domainsExactlyMatch(fromDomain, returnPathDomain);

  // smtp.mailfrom is the envelope-from SPF authenticated. Collect it from every
  // SPF result across all Authentication-Results headers, preserving order and
  // dropping repeats, so a forwarding chain's multiple values are all visible.
  const smtpMailfromDomains = [
    ...new Set(
      authenticationResults.flatMap((header) =>
        header.methods
          .filter((method) => method.method === "spf")
          .map((method) => extractEnvelopeSenderDomain(method.properties["smtp.mailfrom"] ?? null))
          .filter((domain): domain is string => domain !== null),
      ),
    ),
  ];
  const smtpMailfromDomainMatchesFromDomain = allDomainsMatch(fromDomain, smtpMailfromDomains);

  // The two envelope-sender views (Return-Path and smtp.mailfrom) should agree;
  // a disagreement is an internally inconsistent envelope sender.
  const envelopeSenderDomainsAgree = allDomainsMatch(returnPathDomain, smtpMailfromDomains);

  // header.d is the domain a DKIM signature signs for. Only a passing signature
  // actually authenticates that domain, so failed/error/neutral DKIM results are
  // excluded here — a broken signature's header.d proves nothing and must not
  // read as From-alignment. Collect from every passing DKIM result across all
  // Authentication-Results headers, preserving order and dropping repeats.
  const dkimDomains = [
    ...new Set(
      authenticationResults.flatMap((header) =>
        header.methods
          .filter((method) => method.method === "dkim" && method.result === "pass")
          .map((method) => extractDkimSigningDomain(method.properties["header.d"] ?? null))
          .filter((domain): domain is string => domain !== null),
      ),
    ),
  ];
  const dkimDomainMatchesFromDomain = allDomainsMatch(fromDomain, dkimDomains);

  return {
    fromDomain,
    messageIdDomain,
    messageIdDomainMatchesFromDomain,
    replyToDomains,
    replyToDomainMatchesFromDomain,
    returnPathDomain,
    returnPathNullReversePath,
    returnPathDomainMatchesFromDomain,
    smtpMailfromDomains,
    smtpMailfromDomainMatchesFromDomain,
    envelopeSenderDomainsAgree,
    dkimDomains,
    dkimDomainMatchesFromDomain,
    authenticationResults,
  };
}
