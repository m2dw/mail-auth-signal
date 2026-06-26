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
 * through. Composing "the From is organizationally authenticated" with "display
 * name addresses a different domain" isolates that case.
 *
 * Guards:
 *   - the From domain genuinely authenticated under DMARC's relaxed (PSL-aware)
 *     view: organizational.anyAuthAligned (an aligned, trusted, passing SPF/DKIM
 *     identifier on the From's registrable domain) or organizational.dmarcPassAligned
 *     (a trusted DMARC pass for that organization — even a bare aggregate `dmarc=pass
 *     header.from=<org>` with no SPF/DKIM method rows, which DMARC only emits when an
 *     aligned identifier satisfied the From's policy). The organizational view is the
 *     practical default and a strict superset of the exact-domain checks, degrading
 *     to exact comparison with no resolver, so a relaxed-aligned subdomain (From
 *     `news.example.co.jp`, DKIM `header.d=example.co.jp`) is recognized as
 *     authenticated and its borrowed display name is not missed. This never piles
 *     onto an already-failing message (the unauthenticatedFromSpoof composite and the
 *     base auth/consistency signals cover those), and it matches how that composite
 *     treats the same organizationally aligned authentication as authenticating the
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
    const { authentication } = metrics;
    // The From domain counts as authenticated when an aligned, trusted, passing
    // SPF/DKIM identifier backs it, or when a trusted verifier reports a DMARC pass
    // for the From. Use the PSL-aware (organizational) view as the practical default
    // — the form of alignment DMARC actually evaluates under relaxed mode — so a
    // DMARC-relaxed aligned subdomain is recognized as authenticated here too.
    // Without it, From `news.example.co.jp` backed by a trusted `dkim=pass
    // header.d=example.co.jp` (with a supplied resolver) reads as unauthenticated
    // under the exact-domain anyAuthAligned, and this authenticated display-name
    // spoof would be missed even though the unauthenticatedFromSpoof composite
    // already treats that message as authenticated. Both organizational flags are
    // strict supersets of their exact-domain counterparts: they vote only on
    // trusted, passing identifiers and degrade to exact comparison when no resolver
    // is supplied, so this never fires on genuinely unauthenticated mail.
    // organizational.dmarcPassAligned additionally covers a bare `dmarc=pass
    // header.from=<org>` aggregate that omits the SPF/DKIM method lines
    // anyAuthAligned is computed from; only trusted, organizationally aligned passes
    // count, so a pass for a different registrable domain (the
    // dmarc.headerFromMismatch spoof tell) or an untrusted, forge-able pass does not
    // authenticate the From.
    if (
      !authentication.organizational.anyAuthAligned &&
      !authentication.organizational.dmarcPassAligned
    ) {
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
