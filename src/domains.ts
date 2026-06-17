export function extractDomainFromMailbox(value: string | null): string | null {
  if (!value) return null;

  // Strip RFC 5322 comments first. A valid mailbox can carry a comment before a
  // bare addr-spec, e.g. `(billing@evil.test, Alice) alice@example.com`; without
  // removing it the fallback regex would scan from the start and pull the
  // attacker domain out of the comment instead of the real reply target.
  const withoutComments = stripComments(value);

  // The captured domain excludes '@' so a malformed multi-'@' address does not
  // yield a bogus domain that could trigger a spurious consistency signal.
  const angleMatch = /<[^<>@\s]+@([^<>@\s]+)>/.exec(withoutComments);
  const domain = angleMatch?.[1] ?? /[^<>@\s]+@([^<>@\s,;]+)/.exec(withoutComments)?.[1];
  return normalizeDomain(domain ?? null);
}

/**
 * Remove RFC 5322 comments (`(...)`) from a mailbox value. Comments may nest and
 * may contain backslash escapes, and parentheses inside a quoted string are
 * literal rather than comment delimiters, so all three are tracked here. The
 * stripped text is only used for domain extraction, so collapsing each comment
 * to nothing is fine — no real addr-spec lives inside a comment.
 */
function stripComments(value: string): string {
  let result = "";
  let inQuotes = false;
  let commentDepth = 0;
  for (let i = 0; i < value.length; i++) {
    const char = value[i];
    if (inQuotes) {
      if (char === "\\" && i + 1 < value.length) {
        result += char + value[++i];
        continue;
      }
      if (char === '"') inQuotes = false;
      result += char;
      continue;
    }
    if (commentDepth > 0) {
      if (char === "\\" && i + 1 < value.length) {
        i++;
        continue;
      }
      if (char === "(") commentDepth++;
      else if (char === ")") commentDepth--;
      continue;
    }
    if (char === '"') {
      inQuotes = true;
      result += char;
      continue;
    }
    if (char === "(") {
      commentDepth++;
      continue;
    }
    result += char;
  }
  return result;
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
 * The list is split on the mailbox separator comma, but commas inside a
 * quoted string (`"..."`) or an angle-addr (`<...>`) are not separators and
 * must not split the list. Without this, a display name that contains both an
 * email-like fragment and a comma — e.g. `"billing@evil.test, Alice"
 * <alice@example.com>` — would be split into `"billing@evil.test` and
 * ` Alice" <alice@example.com>`, and the hardened single-mailbox extractor
 * would pull `evil.test` out of the display-name fragment, fabricating a bogus
 * mismatch domain even though the only real reply target is alice@example.com.
 *
 * Each top-level fragment is then run through the hardened single-mailbox
 * extractor. Fragments with no parseable address simply yield no domain and are
 * dropped. Duplicates are intentionally kept; callers dedupe if they want a
 * set. Returns an empty array when the value is absent or yields no domain.
 */
export function extractDomainsFromMailboxList(value: string | null): string[] {
  if (!value) return [];
  const domains: string[] = [];
  for (const part of splitMailboxList(value)) {
    const domain = extractDomainFromMailbox(part);
    if (domain) domains.push(domain);
  }
  return domains;
}

/**
 * Split a mailbox-list on top-level commas only, treating commas inside a
 * quoted string, an angle-addr, or an RFC 5322 comment as ordinary characters.
 * Backslash escapes inside a quoted string or a comment are honored so an
 * escaped quote or parenthesis does not prematurely close the construct.
 *
 * Comments matter because a value like `(billing@evil.test, Alice)
 * <alice@example.com>` carries a comma inside the comment before the real
 * address. Treating that comma as a separator would split off
 * `(billing@evil.test` and let the single-mailbox extractor fabricate
 * `evil.test`, producing a bogus mismatch even though the only reply target is
 * alice@example.com. Comments can nest, so depth is tracked rather than a flag.
 */
function splitMailboxList(value: string): string[] {
  const parts: string[] = [];
  let current = "";
  let inQuotes = false;
  let inAngle = false;
  let commentDepth = 0;
  for (let i = 0; i < value.length; i++) {
    const char = value[i];
    if (inQuotes) {
      if (char === "\\" && i + 1 < value.length) {
        current += char + value[++i];
        continue;
      }
      if (char === '"') inQuotes = false;
      current += char;
      continue;
    }
    if (commentDepth > 0) {
      if (char === "\\" && i + 1 < value.length) {
        current += char + value[++i];
        continue;
      }
      if (char === "(") commentDepth++;
      else if (char === ")") commentDepth--;
      current += char;
      continue;
    }
    if (char === '"') {
      inQuotes = true;
      current += char;
      continue;
    }
    if (char === "(" && !inAngle) {
      commentDepth++;
      current += char;
      continue;
    }
    if (char === "<") inAngle = true;
    else if (char === ">") inAngle = false;
    if (char === "," && !inAngle) {
      parts.push(current);
      current = "";
      continue;
    }
    current += char;
  }
  parts.push(current);
  return parts;
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

