export function extractDomainFromMailbox(value: string | null): string | null {
  if (!value) return null;

  // The captured domain excludes '@' so a malformed multi-'@' address does not
  // yield a bogus domain that could trigger a spurious consistency signal.
  const angleMatch = /<[^<>@\s]+@([^<>@\s]+)>/.exec(value);
  const domain = angleMatch?.[1] ?? /[^<>@\s]+@([^<>@\s,;]+)/.exec(value)?.[1];
  return normalizeDomain(domain ?? null);
}

export function extractDomainFromMessageId(value: string | null): string | null {
  if (!value) return null;

  // Anchor on the final '@' and exclude '@' from the domain so a malformed
  // multi-'@' Message-ID resolves to its real trailing domain rather than a
  // bogus value spanning the extra '@'.
  const domain = /@([^>@\s]+)>?\s*$/.exec(value.trim())?.[1];
  return normalizeDomain(domain ?? null);
}

export function domainsExactlyMatch(left: string | null, right: string | null): boolean | null {
  if (!left || !right) return null;
  return left === right;
}

/**
 * Extract every resolvable domain from a mailbox-list value (RFC 5322
 * mailbox-list, the syntax of headers like Reply-To and To).
 *
 * The list is split on commas — the mailbox separator — and each fragment is
 * run through the hardened single-mailbox extractor. Fragments with no
 * parseable address (e.g. the leading half of a quoted display name that itself
 * contains a comma, like `"Doe, John" <john@example.com>`) simply yield no
 * domain and are dropped, so a comma inside a display name cannot fabricate a
 * bogus domain. Duplicates are intentionally kept; callers dedupe if they want
 * a set. Returns an empty array when the value is absent or yields no domain.
 */
export function extractDomainsFromMailboxList(value: string | null): string[] {
  if (!value) return [];
  const domains: string[] = [];
  for (const part of value.split(",")) {
    const domain = extractDomainFromMailbox(part);
    if (domain) domains.push(domain);
  }
  return domains;
}

/**
 * Whether every domain in `domains` exactly equals `reference`.
 *
 * Returns null — meaning "no comparison was possible" — when `reference` is
 * absent or `domains` is empty, so a missing From or a missing/unparseable
 * mailbox-list produces no consistency verdict (and therefore no signal) rather
 * than a noisy false one. Otherwise returns true only when all domains match;
 * a single differing domain (e.g. one extra Reply-To mailbox at an attacker
 * domain) makes the result false.
 */
export function allDomainsMatch(reference: string | null, domains: string[]): boolean | null {
  if (!reference || domains.length === 0) return null;
  return domains.every((domain) => domain === reference);
}

function normalizeDomain(value: string | null): string | null {
  if (!value) return null;
  const trimmed = value.trim().replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  if (!trimmed || !trimmed.includes(".")) return null;
  return trimmed;
}

