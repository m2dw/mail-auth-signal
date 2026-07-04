import { computeRandomLookingCandidate } from "./senderIdentity.js";

/**
 * Reusable, data-free vocabulary and shape predicates for disposable-domain
 * detection: the readable "service word" labels an attacker stacks into a deep
 * subdomain, and the two-letter geo/region tokens they hyphenate into a throwaway
 * registrable label (e.g. `official-zh-ayx.com`).
 *
 * These lists are this project's own curated vocabulary, authored for Apache-2.0
 * distribution — they are **not** an imported brand list, spam corpus, or Public
 * Suffix List slice (see the data/license boundary in AGENTS.md / NOTICE). They
 * are intentionally small and structural: a service word is just a common
 * account/transaction noun, and a geo token is a two-letter region or language
 * code. Neither carries a verdict; the composite rules combine them with deep
 * subdomain structure or a machine-generated companion label before surfacing a
 * low-severity candidate, and the caller still owns the threshold and action.
 */

/**
 * Common service / account / transaction words an attacker uses as a *readable*
 * subdomain label so a per-label randomness check does not fire (the deliberately
 * pronounceable half of the disposable-domain shape, as in
 * `accounts.<random>.<throwaway>.test`).
 *
 * Expanded well beyond the add-on's original small set after 2026-07 log analysis
 * (issue #83) showed the narrow dictionary was a reason `deepServiceWordSubdomain`
 * fired zero times. The vocabulary is the transactional / account nouns observed in
 * spam (accounts/events/updates/users/orders/system/form/client/customer/billing/
 * invoice/support/status/notice/portal/payment/ship/auth/promo), plus their obvious
 * singular/plural variants.
 *
 * Deliberately EXCLUDED are ubiquitous mail-infrastructure labels — `mail`,
 * `email`, `secure`, `login`, `admin`, `service`, `info`, `notify` and the like.
 * Legitimate ESPs routinely send from `<random>.mail.<brand>.com`, so combining
 * such a label with the "random companion" requirement would fire on ordinary
 * DKIM-aligned infrastructure and violate the issue's guardrail
 * ("legitimate DKIM-aligned mail with ordinary domains does not fire"). The
 * transactional nouns kept here are far less common as deep-subdomain infra labels,
 * so the deep-subdomain + random-companion shape stays specific to the disposable
 * pattern. Stored lowercased; matching is case-insensitive on an exact label.
 */
export const SERVICE_WORD_SUBDOMAIN_LABELS: ReadonlySet<string> = new Set([
  "account",
  "accounts",
  "events",
  "event",
  "updates",
  "update",
  "user",
  "users",
  "orders",
  "order",
  "system",
  "form",
  "forms",
  "client",
  "clients",
  "customer",
  "customers",
  "billing",
  "invoice",
  "invoices",
  "support",
  "status",
  "notice",
  "notices",
  "portal",
  "payment",
  "payments",
  "ship",
  "shipping",
  "auth",
  "promo",
]);

/**
 * Two-letter region / language tokens abused inside a hyphenated throwaway
 * registrable label (the `zh` in `official-zh-ayx.com`). Restricted to two-letter
 * codes on purpose: bare country/language *words* (`america`, `france`, `global`)
 * appear in legitimate hyphenated brand domains (`bank-of-america.com`,
 * `air-france-klm.com`) and would be false positives, whereas a bare two-letter
 * region code embedded as a middle hyphen segment is a disposable-domain tell.
 * Stored lowercased; matching is case-insensitive on an exact segment.
 */
export const GEO_COMPOUND_TOKENS: ReadonlySet<string> = new Set([
  "zh",
  "en",
  "us",
  "uk",
  "gb",
  "cn",
  "jp",
  "kr",
  "de",
  "fr",
  "es",
  "it",
  "ru",
  "br",
  "in",
  "nl",
  "pl",
  "tr",
  "ca",
  "au",
  "mx",
  "sg",
  "hk",
  "tw",
  "vn",
  "th",
  "id",
  "ph",
  "sa",
  "ae",
  "pt",
  "se",
  "no",
  "fi",
  "dk",
  "ch",
  "at",
  "be",
  "ie",
  "nz",
  "za",
  "ar",
  "cl",
  "co",
  "pe",
  "ua",
  "ro",
  "cz",
  "gr",
  "il",
  "my",
]);

/**
 * The subset of {@link GEO_COMPOUND_TOKENS} that are *also* everyday English words
 * (`us`, `in`, `at`, `be`, `my`, `it`, `no`). These appear naturally inside
 * legitimate hyphenated phrases — `contact-us-now.com`, `made-in-china.com`,
 * `do-it-now.com` — so their mere presence in a hyphenated compound is NOT, on its
 * own, a disposable-domain tell. A geo/token compound therefore only reads as a
 * throwaway on segment count alone when it carries a *bare region code* geo token
 * (one NOT in this set, e.g. `zh`); a compound whose only geo token is a common
 * word still needs a machine-generated companion to qualify. See
 * isGeoTokenCompoundLabel. Stored lowercased; matching is case-insensitive.
 */
export const COMMON_WORD_GEO_TOKENS: ReadonlySet<string> = new Set([
  "us",
  "in",
  "at",
  "be",
  "my",
  "it",
  "no",
]);

/** Whether a single domain label is one of the readable service words. */
export function isServiceWordLabel(label: string): boolean {
  return SERVICE_WORD_SUBDOMAIN_LABELS.has(label.toLowerCase());
}

/** Whether a single hyphen segment is a two-letter geo/region token. */
export function isGeoCompoundToken(segment: string): boolean {
  return GEO_COMPOUND_TOKENS.has(segment.toLowerCase());
}

/**
 * Whether a geo token is *also* a common English word and so cannot, by itself,
 * mark a hyphenated compound as disposable (see COMMON_WORD_GEO_TOKENS).
 */
export function isCommonWordGeoToken(segment: string): boolean {
  return COMMON_WORD_GEO_TOKENS.has(segment.toLowerCase());
}

/**
 * The organizational (registrable) label of a registrable domain — the part left
 * of its public suffix, i.e. everything before the first dot. For
 * `official-zh-ayx.com` this is `official-zh-ayx`; for `foo.co.uk` it is `foo`.
 * Returns the whole input when it has no dot.
 */
export function registrableLabelOf(registrableDomain: string): string {
  const dot = registrableDomain.indexOf(".");
  return dot === -1 ? registrableDomain : registrableDomain.slice(0, dot);
}

/**
 * Split a label into its hyphen-separated segments, dropping empty segments so a
 * leading/trailing/double hyphen does not produce blanks. `official-zh-ayx` →
 * `["official","zh","ayx"]`.
 */
export function hyphenSegments(label: string): string[] {
  return label.split("-").filter((segment) => segment.length > 0);
}

/**
 * Whether a registrable label is a *geo/token compound*: a hyphenated compound
 * carrying a two-letter geo token together with enough additional structure to
 * read as a throwaway rather than a legitimate hyphenated brand or phrase.
 *
 * A machine-generated companion segment is the strongest tell, so the label
 * qualifies whenever a non-geo segment reads as random-looking (`us-a8f3qz9`,
 * `mail-us-a8f3qz9`). Without such a companion, a three-or-more-segment compound
 * qualifies only when it carries a *bare region code* geo token — one that is not
 * also a common English word (`official-zh-ayx`, geo `zh`). This is what the review
 * for issue #83 required: an ordinary hyphenated English phrase whose only geo
 * token doubles as a word (`contact-us-now`, `made-in-china`) must NOT qualify on
 * segment count alone, because it lacks the random/opaque companion the rule is
 * meant to detect. The core forms no verdict; this is a structural candidate flag.
 */
export function isGeoTokenCompoundLabel(label: string): boolean {
  const segments = hyphenSegments(label);
  if (segments.length < 2) return false;
  const geoIndexes = new Set<number>();
  segments.forEach((segment, index) => {
    if (isGeoCompoundToken(segment)) geoIndexes.add(index);
  });
  if (geoIndexes.size === 0) return false;
  // A machine-generated companion segment is the strongest disposable tell.
  const hasRandomCompanion = segments.some(
    (segment, index) => !geoIndexes.has(index) && computeRandomLookingCandidate(segment),
  );
  if (hasRandomCompanion) return true;
  // Without a random companion, three-plus segments only read as throwaway when a
  // *bare region code* geo token is present. A compound whose only geo token is a
  // common English word (contact-us-now, made-in-china) is an ordinary phrase.
  if (segments.length >= 3) {
    return segments.some(
      (segment, index) => geoIndexes.has(index) && !isCommonWordGeoToken(segment),
    );
  }
  return false;
}
