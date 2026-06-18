export function extractDomainFromMailbox(value: string | null): string | null {
  if (!value) return null;

  // Strip RFC 5322 comments first. A valid mailbox can carry a comment before a
  // bare addr-spec, e.g. `(billing@evil.test, Alice) alice@example.com`; without
  // removing it the fallback regex would scan from the start and pull the
  // attacker domain out of the comment instead of the real reply target.
  const withoutComments = stripComments(value);

  // Prefer the first angle-addr *outside* any quoted phrase. A quoted display
  // name may itself contain an address-shaped `<...@...>` fragment (e.g.
  // `"Support <service@paypal.com>" <attacker@evil.test>`); taking that inner
  // fragment would report the brand domain as the real From and mask the spoof.
  // The captured domain excludes '@' so a malformed multi-'@' address does not
  // yield a bogus domain that could trigger a spurious consistency signal.
  const angleMatch = firstAngleAddrOutsideQuotes(withoutComments);
  const domain = angleMatch?.[2] ?? /[^<>@\s]+@([^<>@\s,;]+)/.exec(withoutComments)?.[1];
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

/**
 * Whether a Return-Path value is the RFC 5321 null reverse-path `<>`.
 *
 * A null reverse-path marks a bounce / delivery-status notification: the message
 * intentionally has no envelope sender, so there is no domain to compare against
 * From and the consistency rules must stay silent. Callers (and the metric) use
 * this to tell an explicit `<>` apart from a missing or unparseable Return-Path,
 * since both yield a null domain. Surrounding whitespace is ignored; null input
 * (a missing header) is not a null reverse-path.
 */
export function isNullReversePath(value: string | null): boolean {
  return value !== null && value.trim() === "<>";
}

/**
 * Extract the domain from an envelope-sender value — a Return-Path reverse-path
 * or an SPF `smtp.mailfrom` property.
 *
 * Unlike a From/Reply-To mailbox, an envelope sender may legitimately be a bare
 * domain (`smtp.mailfrom=example.com`), an addr-spec (`bounce@example.com`), or
 * an angle-addr (`<bounce@example.com>`), and the null reverse-path `<>` carries
 * no domain at all. All four are handled here.
 *
 * Hardening mirrors the mailbox extractor: RFC 5322 comments are stripped first
 * so an attacker domain hidden in a comment cannot be pulled out, and a
 * malformed multi-'@' value yields no domain rather than a fabricated one that
 * could trigger a spurious consistency signal. The result is normalized
 * (lower-cased, bracket/trailing-dot stripped, dotless hosts rejected) so casing
 * and formatting never produce a false mismatch. Returns null when the value is
 * absent, a null reverse-path, or yields no real dotted domain.
 */
export function extractEnvelopeSenderDomain(value: string | null): string | null {
  if (!value) return null;
  let candidate = value.trim();
  if (candidate === "<>") return null;

  candidate = stripComments(candidate).trim();
  const angleMatch = /<([^<>]*)>/.exec(candidate);
  if (angleMatch) candidate = (angleMatch[1] ?? "").trim();
  if (!candidate) return null;

  const atCount = (candidate.match(/@/g) ?? []).length;
  if (atCount > 1) return null;
  const domain = atCount === 1 ? candidate.slice(candidate.indexOf("@") + 1) : candidate;
  if (!domain || /[\s@]/.test(domain)) return null;
  return normalizeDomain(domain);
}

/**
 * Extract the signing domain from a DKIM `header.d` value — the `d=` tag a DKIM
 * signature claims, echoed into Authentication-Results as `header.d=...`.
 *
 * Unlike a From/Reply-To mailbox or an envelope sender, header.d is a bare
 * domain with no local part, so this only normalizes and rejects malformed
 * input rather than parsing an addr-spec. Hardening mirrors the other
 * extractors: RFC 5322 comments are stripped first so an attacker domain hidden
 * in a comment cannot be pulled out, and any value carrying a character outside
 * the host charset (letters, digits, dot, hyphen) — an '@', angle bracket,
 * whitespace, or a stray comment paren — is rejected rather than coerced into a
 * fabricated domain that could trigger a spurious consistency signal. The
 * charset check matters because the Authentication-Results property parser can
 * fold a property-shaped comment into the value (e.g. `header.d=example.com
 * (header.d=evil.test)` leaves the trailing `evil.test)`), so accepting only
 * host characters keeps that comment-derived value from masquerading as the
 * signing domain. The result is normalized (lower-cased, bracket/trailing-dot
 * stripped, dotless hosts rejected) so casing and formatting never produce a
 * false mismatch. Returns null when the value is absent or yields no real
 * dotted domain.
 */
export function extractDkimSigningDomain(value: string | null): string | null {
  return extractBareDomain(value);
}

/**
 * Extract the visible-From domain a DMARC verifier evaluated, taken from the
 * `header.from` property echoed into Authentication-Results as `header.from=...`.
 *
 * Like DKIM `header.d`, the DMARC `header.from` is a bare domain with no local
 * part — the receiver's own parse of the RFC 5322 From domain — so this shares
 * the bare-domain extractor: RFC 5322 comments are stripped first so an attacker
 * domain hidden in a comment cannot be pulled out, any value carrying a character
 * outside the host charset (an '@', angle bracket, whitespace, or a stray comment
 * paren) is rejected rather than coerced into a fabricated domain, and the result
 * is normalized (lower-cased, bracket/trailing-dot stripped, dotless hosts
 * rejected) so casing and formatting never produce a false mismatch. Returns null
 * when the value is absent or yields no real dotted domain.
 */
export function extractDmarcHeaderFromDomain(value: string | null): string | null {
  return extractBareDomain(value);
}

/**
 * Shared extractor for Authentication-Results property values that carry a bare
 * host with no local part (DKIM `header.d`, DMARC `header.from`). Both are a
 * plain domain rather than an addr-spec, so this only normalizes and rejects
 * malformed input: comments are stripped, anything outside the host charset
 * (letters, digits, dot, hyphen) is rejected rather than coerced into a
 * fabricated domain that could trigger a spurious consistency signal, and a
 * dotless host is dropped.
 */
function extractBareDomain(value: string | null): string | null {
  if (!value) return null;
  const candidate = stripComments(value).trim();
  if (!candidate || !/^[A-Za-z0-9.-]+$/.test(candidate)) return null;
  return normalizeDomain(candidate);
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

/**
 * Parse a From-style mailbox into its display name, local part, and domain.
 *
 * Domain extraction mirrors extractDomainFromMailbox exactly — RFC 5322 comments
 * are stripped first (so an attacker domain hidden in a comment cannot be pulled
 * out), an angle-addr is preferred, then a bare addr-spec — so the parsed domain
 * here always agrees with the canonical MessageMetrics.fromDomain. The local part
 * is captured from the *same* match, so it stays paired with the domain it
 * actually belongs to rather than being lifted from unrelated text. When the
 * domain does not normalize to a real dotted host, neither a domain nor a local
 * part is reported, so a malformed value never yields a half-parsed address.
 *
 * The display name is the phrase before the angle-addr, with surrounding quotes
 * removed and backslash escapes unfolded. It is returned verbatim (only
 * trimmed/unquoted) so display-name metrics can inspect what a reader would see —
 * including an address-shaped display name like `"service@paypal.com"`.
 */
export function parseFromMailbox(value: string | null): {
  displayName: string | null;
  localPart: string | null;
  domain: string | null;
} {
  if (!value) return { displayName: null, localPart: null, domain: null };

  const withoutComments = stripComments(value);

  // Take the first angle-addr that is *outside* any quoted phrase. A quoted
  // display name may itself contain an address-shaped angle fragment, e.g.
  // `"Support <service@paypal.com>" <attacker@evil.test>`; matching that inner
  // fragment would report the brand address as the real mailbox and hide the
  // very display-name spoof these metrics exist to surface.
  const angleMatch = firstAngleAddrOutsideQuotes(withoutComments);
  let localPartRaw: string | null = null;
  let domainRaw: string | null = null;
  let displayName: string | null = null;

  if (angleMatch) {
    localPartRaw = angleMatch[1] ?? null;
    domainRaw = angleMatch[2] ?? null;
    // Slice at the matched angle-addr, not the first literal "<": a quoted
    // display name may legally contain an earlier "<...>" fragment (e.g.
    // `"Team <notice> service@paypal.com" <attacker@evil.test>`), and cutting at
    // that earlier "<" would truncate the display name and hide an embedded
    // address-shaped spoof from the address-in-display-name metric.
    const lt = angleMatch.index;
    displayName = lt > 0 ? unquoteDisplayName(withoutComments.slice(0, lt)) : null;
  } else {
    const bare = /([^<>@\s]+)@([^<>@\s,;]+)/.exec(withoutComments);
    if (bare) {
      localPartRaw = bare[1] ?? null;
      domainRaw = bare[2] ?? null;
    }
  }

  const domain = normalizeDomain(domainRaw);
  // A local part is only meaningful next to a real domain; if the domain did not
  // normalize to a dotted host, report neither rather than a half-parsed address.
  const localPart = domain && localPartRaw ? localPartRaw : null;
  return { displayName: displayName && displayName.length ? displayName : null, localPart, domain };
}

/**
 * Strip a single layer of surrounding double quotes from a display-name phrase
 * and unfold backslash escapes, then trim. Used only for display-name reporting,
 * never for address extraction.
 */
function unquoteDisplayName(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1).replace(/\\(.)/g, "$1").trim();
  }
  return trimmed;
}

/**
 * Return the first angle-addr (`<local@domain>`) whose opening "<" falls outside
 * any double-quoted phrase, or null when every angle-addr sits inside quotes.
 *
 * RFC 5322 allows a quoted display name to contain almost any character,
 * including an address-shaped `<...@...>` fragment. The real mailbox is always
 * the angle-addr outside the quoted phrase, so an inner fragment must be skipped
 * rather than taken as the first match.
 */
function firstAngleAddrOutsideQuotes(value: string): RegExpExecArray | null {
  const re = /<([^<>@\s]+)@([^<>@\s]+)>/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(value)) !== null) {
    if (!isIndexInsideQuotes(value, match.index)) return match;
  }
  return null;
}

/**
 * Whether the character at `index` lies inside a double-quoted phrase, honoring
 * backslash escapes (`\"` does not close the quote). Used to keep address
 * extraction from reaching into a quoted display name.
 */
function isIndexInsideQuotes(value: string, index: number): boolean {
  let inQuotes = false;
  for (let i = 0; i < index; i++) {
    const ch = value[i];
    if (inQuotes && ch === "\\") {
      i += 1; // skip the escaped character
      continue;
    }
    if (ch === '"') inQuotes = !inQuotes;
  }
  return inQuotes;
}

/**
 * Extract every normalized domain that appears inside an arbitrary text fragment
 * as part of an email-like `local@domain` token — used to surface addresses
 * embedded in a From display name (e.g. `"service@paypal.com"`). Each match's
 * domain is normalized and dotless/unparseable hosts are dropped; duplicates are
 * removed while preserving encounter order. Returns an empty array for null,
 * empty, or address-free text.
 */
export function extractEmbeddedDomains(text: string | null): string[] {
  if (!text) return [];
  const domains: string[] = [];
  // The domain class admits Unicode letters/digits (not just ASCII) so that raw
  // IDN and homoglyph domains in a display name — e.g. `"support@раураl.com"` —
  // are still captured; normalizeDomain handles lowercasing and dotted-host checks.
  const pattern = /[^\s<>@,;"']+@([\p{L}\p{N}.-]+)/gu;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text)) !== null) {
    const domain = normalizeDomain(match[1] ?? null);
    if (domain) domains.push(domain);
  }
  return [...new Set(domains)];
}

function normalizeDomain(value: string | null): string | null {
  if (!value) return null;
  const trimmed = value.trim().replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  if (!trimmed || !trimmed.includes(".")) return null;
  return trimmed;
}

