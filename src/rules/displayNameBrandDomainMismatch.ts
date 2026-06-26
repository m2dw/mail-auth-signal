import type { Rule } from "../types.js";

/**
 * Flags a message whose From display name reads as a known brand while the From
 * domain is not one that brand sends from.
 *
 * Attacker pattern — "borrowed brand in the display name". A spoofer sets the
 * display name to a trusted brand the recipient recognizes ("PayPal", "HERMÈS",
 * or the letter-spaced "P a y P a l") but sends from a domain that brand does not
 * own. Many mail clients surface the display name far more prominently than the
 * address, so the reader sees the brand and trusts it. The brand-inference metric
 * (SenderIdentityMetrics.brandInference) folds Latin diacritics and letter-spacing
 * camouflage, matches the result against the caller's brand catalog, and reports
 * brandDomainMatchesFromDomain === false exactly when the display name resolves to
 * a brand and the From domain is provably not one of its domains — an exact domain
 * mismatch, or a registrable-domain mismatch when PSL resolution is available. When
 * the relationship cannot be decided (e.g. a brand subdomain with no registrable-
 * domain resolution) the fact stays null, so this rule turns only the decided
 * `false` into a signal and never flags an unresolved subdomain the brand may own.
 *
 * Requires opt-in data: brand inference runs only when the caller supplies a brand
 * catalog (MetricsDependencies.brandCatalog), so with no catalog brandInference is
 * absent and this rule stays silent. The core bundles no brand list.
 *
 * False-positive note and attacker-triggerability: a legitimate sender may use a
 * brand in its display name while sending from a partner or regional domain the
 * catalog does not list for that brand, so this is medium severity and an
 * observation only — the caller correlates it with authentication results and its
 * own policy. It cannot be used to frame a third party: the signal describes the
 * sender's *own* message and never asserts anything about the impersonated brand's
 * real infrastructure. The mismatch fact only fires on a confident brand match
 * (exact token equality or high Jaro-Winkler corroborated by Jaccard) on a Latin,
 * non-homoglyph display name, so a name that merely resembles a brand fragment, a
 * non-Latin name, or a mixed-script homoglyph never triggers it.
 */
export const displayNameBrandDomainMismatchRule: Rule = {
  key: "displayName.brandDomainMismatch",
  description:
    "The From display name reads as a known brand whose domain the From domain is not.",
  evaluate({ metrics }) {
    const brandInference = metrics.senderIdentity.brandInference;
    if (!brandInference || brandInference.brandDomainMatchesFromDomain !== false) return [];

    return [
      {
        key: "displayName.brandDomainMismatch",
        category: "consistency",
        severity: "medium",
        message: "From display name reads as a brand the From domain does not belong to.",
        data: {
          fromDomain: metrics.fromDomain,
          fromRegistrableDomain: brandInference.fromRegistrableDomain,
          brandToken: brandInference.brandToken,
          inferredBrand: brandInference.match?.brand ?? null,
          inferredBrandDomains: brandInference.inferredBrandDomains,
          similarity: brandInference.match?.similarity ?? null,
        },
      },
    ];
  },
};
