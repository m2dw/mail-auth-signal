import type { CompositeRule, Signal } from "../../types.js";
import { computeRandomLookingCandidate } from "../../senderIdentity.js";

/**
 * Composite (candidate): a visible From on a deep subdomain whose *labels look
 * machine-generated*, with no aligned authentication backing the From.
 *
 * Attacker model — disposable random deep-subdomain impersonation. Where the
 * sibling composite.unsecuredDeepSubdomainCandidate captures the *readable*
 * service-word shape (`support.sn5799.com`), this one captures its random-label
 * twin: a throwaway registrable domain sending from a deep subdomain whose labels
 * are random-looking — high digit ratio, long consonant runs, hex/GUID fragments,
 * letter/digit alternation, e.g. From `…@a8f3qz.k2pls.cheap-domain.test`. A
 * per-label entropy heuristic on its own is noisy (legitimate ESP and DKIM-style
 * labels also look random), and a deep subdomain on its own is normal ESP
 * structure; the spoof tell is the *combination* on the visible From plus the
 * absence of any authentication that vouches for it.
 *
 * What it combines (identity structure + auth posture):
 *   - subdomainDepth >= 2: the From sits at least two labels above its registrable
 *     (organizational) domain. PSL-derived, so it is only available when the caller
 *     supplied a registrable-domain resolver (the core bundles no PSL data); without
 *     one the depth is null and the rule stays silent rather than guess.
 *   - at least one *subdomain* label (a label above the registrable domain) reads as
 *     random by computeRandomLookingCandidate — the same structural, data-free check
 *     the add-on used. The registrable-domain labels themselves are excluded: a
 *     random-looking registrable label is a different shape (a cheap throwaway base
 *     domain) the caller can read from fromDomainParts directly, and excluding it
 *     keeps this rule about the *subdomain* structure an attacker stacks under a base
 *     domain.
 *   - no aligned authentication for the From (the same guard the other From-spoof
 *     composites use): anyAuthAligned === false, no organizational (relaxed) aligned
 *     SPF/DKIM, and no aligned trusted DMARC pass for the From's organization. A From
 *     backed by a trusted, passing aligned identifier is authenticated as that domain
 *     regardless of how its labels read, so it is not a candidate.
 *
 * False-positive mitigation / not attacker-triggerable: the only way to *suppress*
 * the signal is to present aligned, trusted authentication for the visible From's
 * organizational domain, which a spoofer of a domain they do not control cannot do.
 * The signal can only be *raised* by sending from a deep, random-looking subdomain
 * the attacker themselves chose — never by an honest third party. Requiring a
 * trusted sender-auth result to have run (trustedHeaderCount > 0 with at least one
 * trusted SPF/DKIM/DMARC result) keeps unverifiable mail from reading as a
 * candidate.
 *
 * Severity low: a candidate lead, not a confirmed spoof — random-looking subdomain
 * labels occur in legitimate infrastructure too, so it stays a low-confidence
 * observation the caller weighs with its own context. The core forms no policy.
 */
export const deepRandomFromSubdomainRule: CompositeRule = {
  key: "composite.deepRandomFromSubdomain",
  description:
    "The visible From sits on a deep subdomain (>= 2 levels) with at least one random-looking subdomain label and no aligned authentication.",
  evaluate({ metrics }): Signal[] {
    const { authentication, fromDomain } = metrics;
    const fromParts = metrics.senderIdentity.fromDomainParts;

    // Depth is PSL-derived: without a resolver a deep subdomain is indistinguishable
    // from a bare registrable domain, so stay silent rather than guess.
    if (fromParts === null || fromParts.subdomainDepth === null) return [];
    if (fromParts.subdomainDepth < 2) return [];
    const registrableDomain = fromParts.registrableDomain;
    if (registrableDomain === null) return [];

    // The subdomain labels are the labels above the registrable domain. Exclude the
    // registrable-domain labels so this rule judges the stacked subdomain structure,
    // not a cheap throwaway base domain (which the caller reads from fromDomainParts).
    const subdomainLabels = fromParts.labels.slice(0, fromParts.subdomainDepth);
    const randomLabels = subdomainLabels.filter((label) =>
      computeRandomLookingCandidate(label),
    );
    if (randomLabels.length === 0) return [];

    // Require a trusted sender-auth check to have actually run, so unverifiable mail
    // is not turned into a candidate.
    if (authentication.trustedHeaderCount === 0) return [];
    const hasTrustedSenderAuth =
      authentication.spfResults.some((result) => result.trusted) ||
      authentication.dkimResults.some((result) => result.trusted) ||
      authentication.dmarcResults.some((result) => result.trusted);
    if (!hasTrustedSenderAuth) return [];

    // An aligned, trusted, passing identifier authenticates the From regardless of how
    // its labels read. Honor the PSL-aware (organizational) view as the default, and a
    // trusted aggregate DMARC pass for the From's organization, exactly as the other
    // From-spoof composites do.
    if (authentication.anyAuthAligned !== false) return [];
    if (authentication.organizational.anyAuthAligned) return [];
    if (authentication.organizational.dmarcPassAligned) return [];

    // The organizational projection is exact-only unless the *caller* supplied a
    // registrable-domain resolver, but fromDomainParts.registrableDomain above is
    // resolved with the built-in PSL fallback. Without this, a From like
    // `a8f3qz.mail.example.com` with trusted `dkim=pass header.d=example.com` —
    // DMARC-relaxed aligned to the parent — would still reach the signal as a false
    // deep-random candidate. Reuse the same registrable-domain boundary already
    // applied to fromParts (as unsecuredDeepSubdomainCandidate does) to suppress
    // relaxed parent-domain SPF/DKIM passes. Not attacker-triggerable: producing a
    // trusted, passing identifier for the From's organizational domain requires
    // control of that domain, which a spoofer of someone else's domain lacks.
    const sharesFromOrg = (domain: string | null): boolean =>
      domain !== null &&
      (domain === registrableDomain || domain.endsWith(`.${registrableDomain}`));
    const hasOrgAlignedDkim = authentication.dkimResults.some(
      (result) =>
        result.trusted && result.result === "pass" && sharesFromOrg(result.headerD),
    );
    const hasOrgAlignedSpf = authentication.spfResults.some(
      (result) =>
        result.trusted && result.result === "pass" && sharesFromOrg(result.smtpMailfrom),
    );
    if (hasOrgAlignedDkim || hasOrgAlignedSpf) return [];

    // A trusted DMARC pass whose header.from shares the From's organizational domain
    // authenticates the From even when the aggregate header omits the SPF/DKIM method
    // lines, mirroring the sibling composites' relaxed boundary.
    const hasOrgAlignedDmarcPass = authentication.dmarcResults.some(
      (result) =>
        result.trusted && result.result === "pass" && sharesFromOrg(result.headerFrom),
    );
    if (hasOrgAlignedDmarcPass) return [];

    return [
      {
        key: "composite.deepRandomFromSubdomain",
        category: "composite",
        severity: "low",
        message:
          "Visible From is on a deep subdomain with random-looking labels and no aligned authentication.",
        data: {
          fromDomain,
          registrableDomain: fromParts.registrableDomain,
          subdomainDepth: fromParts.subdomainDepth,
          randomLabels,
          anyAuthAligned: authentication.anyAuthAligned,
          dmarcPass: authentication.dmarcPass,
          contributingSignals: [],
        },
      },
    ];
  },
};
