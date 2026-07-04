import { computeJaccard } from "./jaccard.js";
import { computeJaroWinkler } from "./jaroWinkler.js";
import { getRegistrableDomain as builtinGetRegistrableDomain, isUnderPrivateSuffix } from "./psl.js";
import type {
  BrandCatalogEntry,
  BrandMatch,
  DisplayNameBrandInference,
} from "./types.js";

/**
 * Minimum normalized-token letter count for a display name to read as brand-like.
 * Short tokens (initials, two-letter words) match too many catalog brands by
 * accident, so anything shorter is treated as insufficient signal rather than a
 * brand.
 */
export const BRAND_LIKE_MIN_LETTERS = 3;

/**
 * Minimum share of a normalized token that must be ASCII letters for it to read as
 * brand-like. Brand names are overwhelmingly alphabetic; a token that is mostly
 * digits is some other kind of identifier, not a brand to infer.
 */
export const BRAND_LIKE_MIN_LETTER_RATIO = 0.6;

/**
 * Confidence thresholds for accepting a catalog entry as a brand match. An exact
 * normalized-token equality always qualifies; otherwise the Jaro-Winkler score
 * must clear BRAND_MATCH_MIN_JARO_WINKLER **and** the bigram Jaccard score must
 * clear BRAND_MATCH_MIN_JACCARD. Requiring both — prefix-weighted and
 * order-sensitive-substring similarity — keeps a single coincidentally-similar
 * brand from producing a false impersonation claim that an attacker could exploit
 * to frame a benign third party.
 */
export const BRAND_MATCH_MIN_JARO_WINKLER = 0.9;
export const BRAND_MATCH_MIN_JACCARD = 0.5;

/**
 * Minimum length (of the shorter of the display token and the catalog brand) before
 * a *fuzzy* (non-exact) brand match is allowed. On very short tokens the similarity
 * metrics collapse: a 3-letter acronym brand such as "aws" scores above both
 * thresholds against unrelated everyday words that merely end in the same letters
 * ("jaws", "laws", "paws" → jaroWinkler ≈ 0.92, jaccard ≈ 0.67), so fuzzy matching
 * would manufacture a brand — and therefore a brand-divergence accusation — against
 * a benign sender an attacker could deliberately name. Below this length only an
 * *exact* normalized-token equality qualifies, so short brands are still detected
 * when the display name genuinely spells them (display "AWS" → brand "aws") but no
 * longer on coincidental near-spellings. Chosen at 4: the shortest length at which
 * one substituted/added letter no longer dominates the score. Issue #84.
 */
export const BRAND_MATCH_MIN_FUZZY_LENGTH = 4;

/**
 * Fold Latin diacritics to their base letters: decompose to NFD and drop the
 * combining marks (Unicode general category M), so "HERMÈS" -> "HERMES",
 * "café" -> "cafe", "Łódź"-style precomposed accents reduce to their base form.
 * Casing is preserved (callers lower-case separately). Letters with no canonical
 * decomposition (e.g. ß, ø) are left as-is; they simply may not match a folded
 * brand token, which is the safe direction. This is the #59 fix promoted to a
 * reusable, exported helper.
 */
export function foldLatinDiacritics(text: string): string {
  return text.normalize("NFD").replace(/\p{M}+/gu, "");
}

/**
 * Normalize a display name (or a catalog brand) into the token brand matching
 * compares: fold Latin diacritics, lower-case, and strip every character that is
 * not an ASCII letter or digit. Whitespace and punctuation removal collapses both
 * ordinary multi-word names and letter-spacing camouflage ("P a y P a l" ->
 * "paypal") into one matchable token without consulting any bundled brand or word
 * list.
 */
export function normalizeBrandToken(text: string): string {
  return foldLatinDiacritics(text)
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
}

/** Count ASCII letters in an already-normalized (lower-cased) token. */
function countAsciiLetters(token: string): number {
  let count = 0;
  for (const char of token) {
    if (char >= "a" && char <= "z") count++;
  }
  return count;
}

/**
 * Classify the letters of a display name by script so brand inference stays on the
 * Latin script it understands. Only characters in Unicode general category L
 * (letters) are considered; digits, spaces, and punctuation are script-neutral and
 * ignored. Returns whether any Latin letter and any non-Latin letter is present,
 * which the caller maps to the non-latin-script / mixed-script guardrails.
 */
function classifyScript(text: string): { hasLatin: boolean; hasNonLatin: boolean } {
  let hasLatin = false;
  let hasNonLatin = false;
  for (const char of text) {
    if (!/\p{L}/u.test(char)) continue;
    if (/\p{Script=Latin}/u.test(char)) hasLatin = true;
    else hasNonLatin = true;
  }
  return { hasLatin, hasNonLatin };
}

function notApplicable(
  reason: DisplayNameBrandInference["notApplicableReason"],
  brandToken: string | null,
  diacriticsFolded: boolean,
  brandLike: boolean,
  fromRegistrableDomain: string | null,
): DisplayNameBrandInference {
  return {
    applicable: false,
    notApplicableReason: reason,
    brandToken,
    diacriticsFolded,
    brandLike,
    match: null,
    inferredBrandDomains: [],
    fromRegistrableDomain,
    brandDomainMatchesFromDomain: null,
  };
}

/**
 * Find the highest-confidence catalog entry for a normalized brand token, or null
 * when none clears the confidence thresholds. Each entry's brand is normalized the
 * same way as the token (so a catalog need not pre-fold), then scored by exact
 * equality, Jaro-Winkler, and bigram Jaccard. The best entry by `similarity` wins;
 * ties keep the earlier catalog entry (stable, catalog-order precedence).
 */
function findBrandMatch(token: string, catalog: readonly BrandCatalogEntry[]): BrandMatch | null {
  let best: BrandMatch | null = null;
  for (const entry of catalog) {
    const brand = normalizeBrandToken(entry.brand);
    if (brand.length === 0) continue;
    const exact = token === brand;
    const jaroWinkler = exact ? 1 : computeJaroWinkler(token, brand);
    const jaccard = exact ? 1 : computeJaccard(token, brand);
    // Fuzzy matching is only trustworthy once both strings are long enough; on very
    // short tokens the metrics saturate and match unrelated words (see
    // BRAND_MATCH_MIN_FUZZY_LENGTH). Short brands still match on exact equality.
    const fuzzyAllowed = Math.min(token.length, brand.length) >= BRAND_MATCH_MIN_FUZZY_LENGTH;
    const qualifies =
      exact ||
      (fuzzyAllowed &&
        jaroWinkler >= BRAND_MATCH_MIN_JARO_WINKLER &&
        jaccard >= BRAND_MATCH_MIN_JACCARD);
    if (!qualifies) continue;
    const similarity = exact ? 1 : Math.max(jaroWinkler, jaccard);
    if (best === null || similarity > best.similarity) {
      best = {
        brand,
        domains: [...entry.domains].map((domain) => domain.toLowerCase()),
        exact,
        jaroWinkler,
        jaccard,
        similarity,
      };
    }
  }
  return best;
}

/**
 * Decide whether the From domain belongs to a matched brand, comparing at the
 * registrable-domain (organizational) level rather than only against the literal
 * catalog strings.
 *
 * The subtle false positive this closes (issue #84): a brand's real sending domains
 * often span an *organizational family* of registrable domains and sub-brand
 * subdomains — AWS legitimately sends from `amazon.com`, `aws.amazon.com`, and
 * `email.aws.amazon.com`. The From domain is resolved to its registrable domain
 * before comparison, so a catalog that lists the brand as a subdomain (e.g.
 * `aws.amazon.com`) would never match a deeper legitimate From (`amazon.com` or
 * `email.aws.amazon.com`, both resolving to `amazon.com`) and the message would be
 * mislabelled as brand divergence. Folding each catalog domain through the *same*
 * resolver — so a listed `aws.amazon.com` is recognized as the `amazon.com`
 * organization — makes the comparison symmetric and removes the AWS ham false
 * positive without weakening spoof detection: a spoofer on `evil.test` (or a
 * hyphenated look-alike such as `aws-security.com`) resolves to a different
 * registrable domain and still reads as a mismatch.
 *
 * The organizational-family collapse is deliberately *not* applied when the catalog
 * entry is a brand-specific host under a shared/private hosting suffix (e.g.
 * `brand.s3.amazonaws.com`, whose ICANN registrable domain is the shared
 * `amazonaws.com`). Collapsing there would fold every tenant on the provider
 * (`attacker.s3.amazonaws.com`) into the brand and suppress a real spoof; such an
 * entry only matches its exact host or a subdomain of it (handled before the
 * collapse). See `isUnderPrivateSuffix` (issue #84 follow-up).
 *
 * Returns true when the From belongs to the brand, false when it provably does not,
 * and null when the relationship cannot be decided (no resolver and no exact hit),
 * preserving the existing "unknown, not a mismatch" contract for the opt-out path.
 */
function fromBelongsToBrandDomains(
  brandDomains: readonly string[],
  fromDomain: string,
  fromRegistrableDomain: string | null,
  getRegistrableDomain: (domain: string) => string | null,
): boolean | null {
  // Exact From match always counts, even when the resolver returns null — a From
  // that already *is* a listed brand domain needs no PSL resolution.
  if (brandDomains.includes(fromDomain)) return true;

  // Everything below is a registrable-domain comparison; without a resolved From
  // registrable domain we cannot substantiate a subdomain/family relationship and
  // must not assert a mismatch, so the result stays unknown.
  if (fromRegistrableDomain === null) return null;

  for (const brandDomain of brandDomains) {
    // From is a subdomain of a listed brand domain (mail.paypal.com under paypal.com),
    // or its registrable domain is exactly a listed brand domain.
    if (brandDomain === fromRegistrableDomain || fromDomain.endsWith(`.${brandDomain}`)) {
      return true;
    }
    // Same organizational family: the listed brand domain and the From resolve to
    // the same registrable domain (aws.amazon.com and amazon.com → amazon.com).
    //
    // Skip this collapse when the catalog entry is a brand-specific host *under* a
    // shared/private hosting suffix (e.g. brand.s3.amazonaws.com, whose ICANN
    // registrable domain is the shared amazonaws.com): collapsing it would let any
    // unrelated tenant on the same provider (attacker.s3.amazonaws.com → amazonaws.com)
    // read as the brand and suppress the divergence signal. Such a From is only a
    // genuine match when it is that exact host or a subdomain of it — both already
    // handled above — so falling through to a decisive mismatch is the safe direction
    // an attacker cannot exploit (issue #84 follow-up).
    if (isUnderPrivateSuffix(brandDomain)) continue;
    const brandRegistrableDomain = getRegistrableDomain(brandDomain);
    if (brandRegistrableDomain !== null && brandRegistrableDomain === fromRegistrableDomain) {
      return true;
    }
  }

  // Resolver was available and no family relationship held: a decisive mismatch.
  return false;
}

/**
 * Infer whether a From display name reads as a known brand and, if so, whether the
 * From domain actually belongs to that brand (see DisplayNameBrandInference).
 *
 * Pure and serializable: no scoring, no policy, no I/O. The brand catalog is
 * caller-supplied (the core bundles none), and the From registrable domain is
 * resolved with the built-in PSL resolver unless a caller overrides it. The
 * guardrails — no display name, non-Latin or mixed-script letters, an
 * insufficient (non-brand-like) token, a missing From domain, or an empty catalog —
 * each short-circuit to an explicit notApplicableReason so the inference never
 * guesses past what it can defend, and in particular never folds a homoglyph
 * mixed-script name into a brand match the raw text never had.
 *
 * @param displayText  the raw (unquoted) From display name, or null when absent.
 * @param fromDomain   the canonical From domain (MessageMetrics.fromDomain).
 * @param catalog      the caller's brand catalog.
 * @param getRegistrableDomain optional PSL resolver override; defaults to built-in.
 */
export function computeDisplayNameBrandInference(
  displayText: string | null,
  fromDomain: string | null,
  catalog: readonly BrandCatalogEntry[],
  getRegistrableDomain: (domain: string) => string | null = builtinGetRegistrableDomain,
): DisplayNameBrandInference {
  const fromRegistrableDomain = fromDomain !== null ? getRegistrableDomain(fromDomain) : null;

  if (displayText === null || displayText.length === 0) {
    return notApplicable("no-display-name", null, false, false, fromRegistrableDomain);
  }

  // Script guardrails run on the *raw* text, before folding: folding a Latin
  // brand spelled with accents is fine, but folding a mixed-script homoglyph name
  // would manufacture a brand match, so refuse those outright.
  const { hasLatin, hasNonLatin } = classifyScript(displayText);
  const folded = foldLatinDiacritics(displayText);
  const diacriticsFolded = folded !== displayText;
  const brandToken = normalizeBrandToken(displayText);
  const letterCount = countAsciiLetters(brandToken);
  const brandLike =
    letterCount >= BRAND_LIKE_MIN_LETTERS &&
    brandToken.length > 0 &&
    letterCount / brandToken.length >= BRAND_LIKE_MIN_LETTER_RATIO;

  if (hasNonLatin && hasLatin) {
    return notApplicable("mixed-script", brandToken, diacriticsFolded, brandLike, fromRegistrableDomain);
  }
  if (hasNonLatin) {
    return notApplicable("non-latin-script", brandToken, diacriticsFolded, brandLike, fromRegistrableDomain);
  }
  if (!brandLike) {
    return notApplicable(
      "insufficient-signal",
      brandToken,
      diacriticsFolded,
      brandLike,
      fromRegistrableDomain,
    );
  }
  if (fromDomain === null) {
    return notApplicable(
      "missing-from-domain",
      brandToken,
      diacriticsFolded,
      brandLike,
      fromRegistrableDomain,
    );
  }
  if (catalog.length === 0) {
    return notApplicable("empty-catalog", brandToken, diacriticsFolded, brandLike, fromRegistrableDomain);
  }

  const match = findBrandMatch(brandToken, catalog);
  const inferredBrandDomains = match ? match.domains : [];

  // Compare the brand's domains against the From domain at the registrable
  // (organizational) level, resolving both sides through the same PSL resolver so a
  // brand's wider domain family (e.g. AWS's amazon.com / aws.amazon.com) is
  // recognized rather than mislabelled as divergence (see fromBelongsToBrandDomains,
  // issue #84). A non-match is only meaningful when registrable domains can actually
  // be compared; without PSL resolution the relationship stays `null` (unknown)
  // rather than a false mismatch.
  const brandDomainMatchesFromDomain =
    match === null
      ? null
      : fromBelongsToBrandDomains(
          match.domains,
          fromDomain,
          fromRegistrableDomain,
          getRegistrableDomain,
        );

  return {
    applicable: true,
    notApplicableReason: null,
    brandToken,
    diacriticsFolded,
    brandLike,
    match,
    inferredBrandDomains,
    fromRegistrableDomain,
    brandDomainMatchesFromDomain,
  };
}
