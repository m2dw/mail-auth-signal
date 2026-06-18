import type { CompositeRule, Signal } from "../../types.js";

/**
 * Composite: a visible From on a deep subdomain whose organizational domain
 * publishes no enforced DMARC policy — the shape of disposable-domain spoofing
 * that the lexical/random-label checks miss.
 *
 * Attacker model — disposable deep-subdomain impersonation. The attacker
 * registers (or abuses) a throwaway registrable domain and sends from a deep,
 * pronounceable subdomain of it, e.g. From: `…@sivakeso.support.sn5799.com`.
 * The leftmost labels are deliberately readable ("support", a plausible name),
 * so a per-label randomness/entropy heuristic does not fire; the tell is the
 * *structure* (several subdomain levels stacked under a cheap registrable
 * domain) combined with a *weak DMARC posture* — the organizational domain has
 * no DMARC record / `p=none`, so a verifier returns `dmarc=none` and nothing
 * stops the visible-From from being whatever the attacker types.
 *
 * What it combines (auth posture + identity structure):
 *   - subdomainDepth >= 2: the From domain has at least two labels above its
 *     registrable (organizational) domain. This is a PSL-derived metric, so it is
 *     only available when the caller supplied a registrable-domain resolver
 *     (MetricsDependencies.getRegistrableDomain); without one the depth is null
 *     and this rule cannot tell a deep subdomain from a bare registrable domain,
 *     so it stays silent rather than guess (the core bundles no PSL data).
 *   - a trusted `dmarc=none` result: a verifier the caller declared trusted
 *     reported that the From's organizational domain has no enforced DMARC
 *     policy. Trust is required because, like every DMARC read in this core, an
 *     untrusted Authentication-Results header is forge-able and its `dmarc=none`
 *     is just an upstream assertion; reading it from the recomputed,
 *     trust-resolved `authentication` projection keeps this consistent with the
 *     rest of the pipeline.
 *
 * Why these are individually weak but jointly meaningful: plenty of legitimate
 * mail rides deep ESP subdomains, and plenty of small domains have not deployed
 * DMARC — neither alone is suspicious. Their *combination* on a single visible
 * From is the disposable-spoof shape, because it means the recipient sees a
 * structured, brand-ish hostname that no published policy actually protects.
 *
 * False-positive mitigation (anyAuthAligned === false): a From domain backed by
 * an aligned, trusted, passing SPF or DKIM identifier is authenticated as that
 * domain by DMARC's own logic, even when the organizational domain publishes no
 * DMARC record (so the verifier still says `dmarc=none`). A legitimate
 * deep-subdomain sender that signs with an aligned DKIM key therefore does not
 * trip this. Crucially this guard is not attacker-triggerable: to suppress the
 * signal a spoofer would have to produce aligned, trusted authentication for the
 * very domain in the visible From — which, for a domain they merely typed into
 * the header, they cannot. The signal can only be *raised* by sending from a
 * deep subdomain with weak DMARC, which is the attacker's own choice, never an
 * honest third party's.
 *
 * Severity low: it is a candidate lead, not a confirmed spoof. A structured
 * hostname under an unenforced organizational domain is worth surfacing, but
 * on its own it is consistent with benign under-configured mail, so it stays a
 * low-confidence observation the caller weighs with its own context. It carries
 * `contributingSignals: []` for shape parity with the other composites: its
 * justification is two metrics (depth + DMARC posture), not lower-layer signals.
 *
 * The core still forms no policy: this never tells the caller to junk or block
 * anything — it only names the shape, and the threshold/action stays the
 * caller's.
 */
export const unsecuredDeepSubdomainCandidateRule: CompositeRule = {
  key: "composite.unsecuredDeepSubdomainCandidate",
  description:
    "The visible From sits on a deep subdomain (>= 2 levels) whose organizational domain has a trusted DMARC=none result and no aligned authentication.",
  evaluate({ metrics }): Signal[] {
    const { authentication, fromDomain } = metrics;
    const fromParts = metrics.senderIdentity.fromDomainParts;

    // The subdomain depth is PSL-derived: without a caller-supplied resolver it is
    // null and a deep subdomain is indistinguishable from a bare registrable
    // domain, so the candidate cannot be assessed. Stay silent rather than guess.
    if (fromParts === null || fromParts.subdomainDepth === null) return [];
    if (fromParts.subdomainDepth < 2) return [];

    // Weak DMARC posture: a trusted verifier reported no enforced DMARC policy for
    // the From's organizational domain. Trust is required because an untrusted AR
    // header's `dmarc=none` is forge-able and merely an upstream claim.
    const hasTrustedDmarcNone = authentication.dmarcResults.some(
      (result) => result.trusted && result.result === "none",
    );
    if (!hasTrustedDmarcNone) return [];

    // False-positive mitigation: an aligned, trusted, passing SPF/DKIM identifier
    // authenticates the From domain even when no DMARC record is published, so a
    // legitimately signed deep-subdomain sender is not a candidate. A spoofer of a
    // domain they do not control cannot satisfy this, so the guard is not
    // attacker-triggerable.
    if (authentication.anyAuthAligned !== false) return [];

    return [
      {
        key: "composite.unsecuredDeepSubdomainCandidate",
        category: "composite",
        severity: "low",
        message:
          "Visible From is on a deep subdomain whose organizational domain has no enforced DMARC policy and no aligned authentication.",
        data: {
          fromDomain,
          registrableDomain: fromParts.registrableDomain,
          subdomainDepth: fromParts.subdomainDepth,
          anyAuthAligned: authentication.anyAuthAligned,
          dmarcPass: authentication.dmarcPass,
          contributingSignals: [],
        },
      },
    ];
  },
};
