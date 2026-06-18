import { allDomainsMatch, extractEmbeddedDomains, parseFromMailbox } from "./domains.js";
import type {
  DisplayNameMetrics,
  DomainParts,
  LexicalStats,
  MetricsDependencies,
  SenderIdentityMetrics,
} from "./types.js";

/**
 * Compute codepoint-based lexical statistics for a token (see LexicalStats). No
 * external word list or dictionary is consulted — only structural counts that an
 * attacker cannot launder away by choosing a benign-looking domain.
 */
export function computeLexicalStats(value: string): LexicalStats {
  let length = 0;
  let digitCount = 0;
  let hyphenCount = 0;
  let hasNonAscii = false;
  for (const char of value) {
    length++;
    if (char >= "0" && char <= "9") digitCount++;
    else if (char === "-") hyphenCount++;
    if ((char.codePointAt(0) ?? 0) > 0x7f) hasNonAscii = true;
  }
  return { length, digitCount, hyphenCount, hasNonAscii };
}

/**
 * Decompose a normalized domain into its dot-separated labels (see DomainParts).
 * The label fields need no external data; the registrable-domain fields are
 * populated only when a resolver is supplied (the core bundles no PSL data).
 */
export function computeDomainParts(
  domain: string,
  getRegistrableDomain?: (domain: string) => string | null,
): DomainParts {
  const labels = domain.split(".");
  let registrableDomain: string | null = null;
  let subdomainDepth: number | null = null;
  if (getRegistrableDomain) {
    const resolved = getRegistrableDomain(domain);
    if (resolved) {
      registrableDomain = resolved;
      // Labels above the registrable boundary. Clamp at 0 so a resolver returning
      // a value with more labels than `domain` (an inconsistent resolver) can
      // never produce a negative depth.
      subdomainDepth = Math.max(0, labels.length - resolved.split(".").length);
    }
  }
  return {
    domain,
    labels,
    labelCount: labels.length,
    topLabel: labels[labels.length - 1] ?? domain,
    registrableDomain,
    subdomainDepth,
  };
}

/**
 * Build the sender-identity metrics (see SenderIdentityMetrics) from the raw From
 * header value, the already-extracted canonical From domain, the Message-ID
 * domain, and optional runtime dependencies.
 *
 * Pure and serializable: no scoring, no policy. The From domain is taken as an
 * argument (rather than re-parsed) so the local part and the domain decomposition
 * stay consistent with MessageMetrics.fromDomain.
 */
export function computeSenderIdentity(
  fromValue: string | null,
  fromDomain: string | null,
  messageIdDomain: string | null,
  deps?: MetricsDependencies,
): SenderIdentityMetrics {
  const getRegistrableDomain = deps?.getRegistrableDomain;
  const parsed = parseFromMailbox(fromValue);

  const displayText = parsed.displayName;
  const embeddedDomains = extractEmbeddedDomains(displayText);
  const displayName: DisplayNameMetrics = {
    present: displayText !== null,
    text: displayText,
    length: displayText ? [...displayText].length : 0,
    hasNonAscii: displayText ? computeLexicalStats(displayText).hasNonAscii : false,
    containsEmail: embeddedDomains.length > 0,
    embeddedDomains,
    embeddedDomainMatchesFromDomain: allDomainsMatch(fromDomain, embeddedDomains),
  };

  // Pair the local part with the canonical From domain. parseFromMailbox mirrors
  // the fromDomain extractor, so when a From domain is present its local part
  // belongs to the same address; when From has no parseable domain there is no
  // address to read a local part from.
  const localPart = fromDomain !== null ? parsed.localPart : null;

  const messageIdRegistrableDomainMatchesFromDomain = ((): boolean | null => {
    if (!getRegistrableDomain || fromDomain === null || messageIdDomain === null) return null;
    const fromRegistrable = getRegistrableDomain(fromDomain);
    const messageIdRegistrable = getRegistrableDomain(messageIdDomain);
    if (!fromRegistrable || !messageIdRegistrable) return null;
    return fromRegistrable === messageIdRegistrable;
  })();

  return {
    displayName,
    localPart,
    localPartLexical: localPart !== null ? computeLexicalStats(localPart) : null,
    fromDomainLexical: fromDomain !== null ? computeLexicalStats(fromDomain) : null,
    fromDomainParts:
      fromDomain !== null ? computeDomainParts(fromDomain, getRegistrableDomain) : null,
    messageIdDomainParts:
      messageIdDomain !== null ? computeDomainParts(messageIdDomain, getRegistrableDomain) : null,
    messageIdRegistrableDomainMatchesFromDomain,
  };
}
