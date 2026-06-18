import type { CompositeRule, Signal } from "../../types.js";

/**
 * Composite: a message that authenticates cleanly for its real From domain, yet
 * wears a display name that spells out an email address at a *different* domain.
 *
 * Attacker model — "authenticated lookalike with a borrowed display name". The
 * attacker owns (or has compromised) some domain they can actually authenticate
 * — a throwaway, a lookalike, a free-tier ESP subdomain — so SPF/DKIM align with
 * the From and the message earns a genuine authentication pass. They then set the
 * display name to the brand they are impersonating, e.g.
 * `From: "security@paypal.com" <alerts@auth-ok.example>`. Many mail clients show
 * the display name prominently (and some collapse it over the real address), so
 * the reader sees `security@paypal.com` next to a green "authenticated" badge.
 * The authentication is real — for the wrong identity.
 *
 * Why this is a composite, not just the display-name metric: a display name that
 * embeds a foreign domain is, on its own, only mildly interesting (newsletters,
 * "via" forwarders, and ticketing systems do it benignly). It becomes a
 * deliberate spoof shape precisely when the message *also* passes authentication,
 * because that is when the misleading display name is paired with the false
 * comfort of a pass — the one case a pure Junk/auth filter would wave straight
 * through. Composing "anyAuthAligned === true" with "display name addresses a
 * different domain" isolates that case.
 *
 * Guards:
 *   - the From domain genuinely authenticated: either anyAuthAligned === true (an
 *     aligned, trusted, passing SPF/DKIM identifier backs the From) or a trusted
 *     verifier reported a DMARC pass for the visible From — even an aggregate
 *     `dmarc=pass header.from=From` with no SPF/DKIM method rows, which DMARC only
 *     emits when an aligned identifier satisfied the From's policy. This never
 *     piles onto an already-failing message (the unauthenticatedFromSpoof composite
 *     and the base auth/consistency signals cover those), and it matches how that
 *     composite already treats the aligned DMARC-only pass as authenticating the
 *     From.
 *   - displayName.containsEmail && embeddedDomainMatchesFromDomain === false: the
 *     display name contains an email-like address whose domain differs from the
 *     authenticated From domain — the address-in-display-name shape, computed by
 *     extractMetrics with no external word/brand list.
 *
 * False-positive note and attacker-triggerability: a benign sender can put a
 * different domain in its display name, so this is medium severity, not high, and
 * stays an observation the caller weighs against its own policy. An attacker
 * cannot use it to frame a third party: triggering it requires authenticating
 * *their own* From domain, and the signal points at the attacker's message, never
 * at the impersonated brand.
 */
export const authenticatedDisplayNameSpoofRule: CompositeRule = {
  key: "composite.authenticatedDisplayNameSpoof",
  description:
    "A message that authenticates for its From domain carries a display name addressing a different domain.",
  evaluate({ metrics }): Signal[] {
    const { authentication, fromDomain } = metrics;
    // The From domain counts as authenticated when an aligned, trusted, passing
    // SPF/DKIM identifier backs it (anyAuthAligned), or when a trusted verifier
    // reports a DMARC pass for the *visible* From even though the same header omits
    // the SPF/DKIM method lines anyAuthAligned is computed from (a bare
    // `dmarc=pass header.from=From` aggregate leaves anyAuthAligned vacuously
    // false). DMARC passes only when an aligned SPF or DKIM identifier satisfied the
    // From domain's policy, so the aggregate likewise authenticates the From — this
    // mirrors the suppression in the unauthenticatedFromSpoof composite. Only a pass
    // whose header.from equals the visible From counts: a trusted pass for a
    // different header.from is the dmarc.headerFromMismatch spoof tell, and an
    // untrusted pass is forge-able.
    const hasAlignedTrustedDmarcPass = authentication.dmarcResults.some(
      (result) =>
        result.trusted &&
        result.result === "pass" &&
        result.headerFrom !== null &&
        result.headerFrom === fromDomain,
    );
    if (authentication.anyAuthAligned !== true && !hasAlignedTrustedDmarcPass) {
      return [];
    }

    const { displayName } = metrics.senderIdentity;
    if (!displayName.containsEmail) return [];
    if (displayName.embeddedDomainMatchesFromDomain !== false) return [];

    const mismatchedDomains = displayName.embeddedDomains.filter(
      (domain) => domain !== metrics.fromDomain,
    );

    return [
      {
        key: "composite.authenticatedDisplayNameSpoof",
        category: "composite",
        severity: "medium",
        message:
          "Authenticated message's display name addresses a domain other than its From domain.",
        data: {
          fromDomain: metrics.fromDomain,
          embeddedDomains: displayName.embeddedDomains,
          mismatchedDomains,
          contributingSignals: [],
        },
      },
    ];
  },
};
