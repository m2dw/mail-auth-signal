import {
  allDomainsMatch,
  domainsExactlyMatch,
  extractDkimSigningDomain,
  extractDmarcHeaderFromDomain,
  extractDomainFromMailbox,
  extractDomainFromMessageId,
  extractDomainsFromMailboxList,
  extractEnvelopeSenderDomain,
  isNullReversePath,
} from "./domains.js";
import { getFirstHeaderValue, getHeaderValues, normalizeHeaders } from "./normalizeHeaders.js";
import { parseAuthenticationResults } from "./parseAuthenticationResults.js";
import type { AnalyzeInput, AuthenticationResultsHeader, MessageMetrics } from "./types.js";

/**
 * Collect the resolvable, normalized DMARC `header.from` domains across the given
 * Authentication-Results headers, in encounter order and deduplicated.
 *
 * Two gates apply, both expressed here so metric extraction and rule evaluation
 * collect the same set the same way:
 *
 *   - Pass only: a non-pass DMARC vouches for nothing, so its header.from is
 *     never treated as a verified From view (neither a false alignment nor a
 *     fabricated mismatch); a failed DMARC is already surfaced elsewhere.
 *   - Trusted only: header.from is not cryptographic, so a forge-able untrusted
 *     header's value is just the attacker's own assertion. Trust is supplied by
 *     the caller via `isTrusted` rather than read from the baked header.trusted
 *     flag, so a rule can recompute trust at evaluation time (e.g. when trust is
 *     declared to runRules after metrics were extracted without it).
 */
export function collectDmarcHeaderFromDomains(
  headers: readonly AuthenticationResultsHeader[],
  isTrusted: (header: AuthenticationResultsHeader) => boolean,
): string[] {
  return [
    ...new Set(
      headers
        .filter(isTrusted)
        .flatMap((header) =>
          header.methods
            .filter((method) => method.method === "dmarc" && method.result === "pass")
            .map((method) => extractDmarcHeaderFromDomain(method.properties["header.from"] ?? null))
            .filter((domain): domain is string => domain !== null),
        ),
    ),
  ];
}

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

  // header.from is the visible-From domain a DMARC verifier evaluated. Collect it
  // from every trusted, passing DMARC result across all headers (see
  // collectDmarcHeaderFromDomains for the pass/trust gates). Trust here uses the
  // baked header.trusted flag — the trust resolved when these metrics were
  // extracted — so analyzeMessage's snapshot stays stable. The dmarc.headerFrom
  // mismatch rule recomputes trust at rule time so callers using the separated
  // API can declare trust to runRules after extracting metrics without it.
  const dmarcHeaderFromDomains = collectDmarcHeaderFromDomains(
    authenticationResults,
    (header) => header.trusted,
  );
  const dmarcHeaderFromMatchesFromDomain = allDomainsMatch(fromDomain, dmarcHeaderFromDomains);

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
    dmarcHeaderFromDomains,
    dmarcHeaderFromMatchesFromDomain,
    authenticationResults,
  };
}
