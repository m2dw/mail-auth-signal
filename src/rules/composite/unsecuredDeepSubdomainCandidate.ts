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
 *   - a trusted `dmarc=none` result *for this From*: a verifier the caller
 *     declared trusted reported that the From's organizational domain has no
 *     enforced DMARC policy. Trust is required because, like every DMARC read in
 *     this core, an untrusted Authentication-Results header is forge-able and its
 *     `dmarc=none` is just an upstream assertion; reading it from the recomputed,
 *     trust-resolved `authentication` projection keeps this consistent with the
 *     rest of the pipeline. The `dmarc=none` is also bound to the current From's
 *     organizational domain via its `header.from`: with several trusted AR
 *     headers, a `none` whose header.from is missing or names a different domain
 *     describes some other identity, and accepting it would let the rule claim
 *     this From is unprotected even when its own DMARC result is `pass`/`fail`.
 *
 * Why these are individually weak but jointly meaningful: plenty of legitimate
 * mail rides deep ESP subdomains, and plenty of small domains have not deployed
 * DMARC — neither alone is suspicious. Their *combination* on a single visible
 * From is the disposable-spoof shape, because it means the recipient sees a
 * structured, brand-ish hostname that no published policy actually protects.
 *
 * False-positive mitigation (no aligned authentication): a From domain backed by
 * a trusted, passing SPF or DKIM identifier is authenticated as that domain by
 * DMARC's own logic, even when the organizational domain publishes no DMARC
 * record (so the verifier still says `dmarc=none`). This is checked two ways,
 * mirroring DMARC's two alignment modes: `anyAuthAligned === false` rules out an
 * *exact*-match aligned pass, and a same-organization check additionally rules
 * out *relaxed* alignment — a parent-domain identifier such as `dkim=pass
 * header.d=example.com` on a From of `bounce.mail.example.com`. Because this rule
 * already depends on the PSL-derived registrable domain, suppressing same-org
 * SPF/DKIM passes avoids false positives for legitimate parent-domain signing.
 * Crucially the guard is not attacker-triggerable: to suppress the signal a
 * spoofer would have to produce trusted, passing authentication for the visible
 * From's organizational domain — which, for a domain they merely typed into the
 * header, they cannot. The signal can only be *raised* by sending from a deep
 * subdomain with weak DMARC, which is the attacker's own choice, never an honest
 * third party's.
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

    // subdomainDepth and registrableDomain are resolved together from the same PSL
    // lookup, so a non-null depth implies a non-null registrable domain; narrow it
    // for the type checker (and stay silent in the impossible null case).
    const registrableDomain = fromParts.registrableDomain;
    if (registrableDomain === null) return [];

    // Same-organization test under DMARC's relaxed alignment: a domain belongs to
    // the From's organization when it *is* the registrable domain or sits beneath
    // it. Used both to bind the DMARC=none result to the visible From and to
    // suppress parent-domain (org-aligned) SPF/DKIM passes below.
    const sharesFromOrg = (domain: string | null): boolean =>
      domain !== null &&
      (domain === registrableDomain || domain.endsWith(`.${registrableDomain}`));

    // Weak DMARC posture: a trusted verifier reported no enforced DMARC policy for
    // the From's organizational domain. Trust is required because an untrusted AR
    // header's `dmarc=none` is forge-able and merely an upstream claim. The result
    // must also concern the *current* From's organizational domain: with several
    // trusted AR headers, a `dmarc=none` whose header.from is missing or names a
    // different domain says nothing about this From — whose own DMARC may even be
    // pass/fail — so it must not raise the candidate.
    const hasTrustedDmarcNone = authentication.dmarcResults.some(
      (result) =>
        result.trusted &&
        result.result === "none" &&
        sharesFromOrg(result.headerFrom),
    );
    if (!hasTrustedDmarcNone) return [];

    // False-positive mitigation: an aligned, trusted, passing SPF/DKIM identifier
    // authenticates the From domain even when no DMARC record is published, so a
    // legitimately signed deep-subdomain sender is not a candidate. A spoofer of a
    // domain they do not control cannot satisfy this, so the guard is not
    // attacker-triggerable.
    if (authentication.anyAuthAligned !== false) return [];

    // anyAuthAligned is exact-match only, but DMARC's relaxed alignment treats a
    // parent-domain identifier as aligned: a deep-subdomain From like
    // `bounce.mail.example.com` is commonly signed with `dkim=pass header.d=example.com`
    // (or SPF'd via an envelope at the organizational domain). Suppress the
    // candidate when a trusted, passing SPF/DKIM authenticates the From's own
    // organizational domain, to avoid false positives for parent-domain signing.
    // This is still not attacker-triggerable: producing trusted, passing
    // authentication for the visible From's organizational domain requires control
    // of that domain, which a spoofer of someone else's domain does not have.
    const hasOrgAlignedDkim = authentication.dkimResults.some(
      (result) =>
        result.trusted && result.result === "pass" && sharesFromOrg(result.headerD),
    );
    const hasOrgAlignedSpf = authentication.spfResults.some(
      (result) =>
        result.trusted &&
        result.result === "pass" &&
        sharesFromOrg(result.smtpMailfrom),
    );
    if (hasOrgAlignedDkim || hasOrgAlignedSpf) return [];

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
