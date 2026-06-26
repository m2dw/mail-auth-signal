import type { CompositeRule, Signal } from "../../types.js";
import { hasBuiltinPslOrgAlignedAuth } from "./builtinPslDkimAlignment.js";

/**
 * Composite: a display-name brand impersonation, elevated by the message's
 * authentication posture into a single phishing observation.
 *
 * Attacker model — borrowed brand in the display name. A spoofer sets the From
 * display name to a brand the recipient trusts ("PayPal", "HERMÈS", letter-spaced
 * "P a y P a l") while sending from a domain that brand does not own. The base
 * `displayName.brandDomainMismatch` rule already names that divergence (a confident
 * brand match on a Latin, non-homoglyph display name whose From domain is provably
 * not one of the brand's domains). This composite is its Layer-4 elevation: it
 * combines the brand divergence with whether the visible From authenticated as its
 * *own* domain, the way the add-on fed brand divergence into its composite score.
 *
 * Why the auth posture matters and is reported, not gated on:
 *   - A brand-divergent From that is *also* unauthenticated (anyAuthAligned === false,
 *     no organizational aligned identifier, no aligned trusted DMARC pass) is the
 *     strongest shape — the reader sees a brand, and nothing vouches for the sending
 *     domain at all.
 *   - A brand-divergent From that *does* authenticate as its own (non-brand) domain
 *     is still impersonation — the sender proved control of `evil.test`, not of the
 *     brand — so this still fires; the authenticated case is reported via
 *     `data.fromAuthenticated` so the caller can weight it differently, mirroring how
 *     authenticatedDisplayNameSpoof and unauthenticatedFromSpoof split the same axis.
 * Either way the brand/From divergence is the load-bearing fact, so the composite
 * fires whenever the base mismatch fired and reports the posture rather than
 * suppressing on it.
 *
 * Requires opt-in data: brand inference (SenderIdentityMetrics.brandInference) runs
 * only when the caller supplies a brand catalog; with none the base signal is absent
 * and this composite stays silent. The core bundles no brand list.
 *
 * Not attacker-triggerable against a third party: the signal describes the sender's
 * *own* message (its display name and its From domain) and asserts nothing about the
 * impersonated brand's real infrastructure, so it cannot frame an innocent party. It
 * is driven by the trusted, base `displayName.brandDomainMismatch` consistency
 * signal, which only fires on a confident brand match — a name that merely resembles
 * a brand fragment, a non-Latin name, or a mixed-script homoglyph never triggers it.
 *
 * Severity high: a confident brand impersonation is a strong phishing lead. It
 * remains an observation; the caller owns the Review/Junk/threshold decision and may
 * downweight the authenticated case via `data.fromAuthenticated`.
 */
export const brandDivergencePhishingRule: CompositeRule = {
  key: "composite.brandDivergencePhishing",
  description:
    "The From display name reads as a known brand the From domain does not belong to, surfaced as a phishing observation with the From's authentication posture.",
  evaluate({ metrics, signals }): Signal[] {
    const brandInference = metrics.senderIdentity.brandInference;
    // Gate on the decided brand/From mismatch, not on a null/unresolved relationship,
    // exactly as the base rule does — so a brand subdomain the brand may own (null) or
    // a legitimate brand domain (true) never reaches here.
    if (!brandInference || brandInference.brandDomainMatchesFromDomain !== false) return [];

    const { authentication } = metrics;
    // Authentication posture of the *visible From's own domain* (not the brand's):
    // whether any aligned trusted identifier — exact, organizational, or an aligned
    // trusted DMARC pass for the From's organization — vouches for the sending domain.
    //
    // organizational.anyAuthAligned / organizational.dmarcPassAligned are exact-only
    // unless the *caller* supplied a registrable-domain resolver, but
    // senderIdentity.fromDomainParts.registrableDomain is resolved with the built-in
    // PSL fallback. Reuse that boundary so the common default path (analyzeMessage
    // without a custom getRegistrableDomain) still recognizes relaxed organizational
    // alignment — e.g. a brand-divergent From security@mail.evil.com with trusted
    // dkim=pass header.d=evil.com (or equivalent relaxed SPF/DMARC) reports
    // fromAuthenticated: true rather than overstating the unauthenticated case, exactly
    // as the DKIM mitigation and deep/own composites do. Not attacker-triggerable: a
    // trusted, passing identifier for the From's organizational domain requires control
    // of it, so a spoofer cannot earn the authenticated posture for someone else's domain.
    const fromAuthenticated =
      authentication.anyAuthAligned === true ||
      authentication.organizational.anyAuthAligned ||
      authentication.organizational.dmarcPassAligned ||
      hasBuiltinPslOrgAlignedAuth(metrics);

    // Trace the base consistency signal that established the divergence, when present
    // (it is emitted by displayNameBrandDomainMismatchRule under the same metrics).
    const contributingSignals = [
      ...new Set(
        signals
          .filter((signal) => signal.key === "displayName.brandDomainMismatch")
          .map((signal) => signal.key),
      ),
    ];

    return [
      {
        key: "composite.brandDivergencePhishing",
        category: "composite",
        severity: "high",
        message:
          "From display name reads as a brand the From domain does not belong to — a brand-impersonation phishing candidate.",
        data: {
          fromDomain: metrics.fromDomain,
          fromRegistrableDomain: brandInference.fromRegistrableDomain,
          brandToken: brandInference.brandToken,
          inferredBrand: brandInference.match?.brand ?? null,
          inferredBrandDomains: brandInference.inferredBrandDomains,
          similarity: brandInference.match?.similarity ?? null,
          fromAuthenticated,
          anyAuthAligned: authentication.anyAuthAligned,
          contributingSignals,
        },
      },
    ];
  },
};
