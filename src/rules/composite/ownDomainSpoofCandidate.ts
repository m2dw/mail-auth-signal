import type { AnalyzeOptions, CompositeRule, Signal } from "../../types.js";

/**
 * The caller-context key this composite reads the recipient's own account domains
 * from. The add-on knows which domains belong to the user's own accounts; this core
 * does not, so the caller passes them through the open-ended AnalyzeOptions.context
 * bag (documented on AnalyzeOptions) under this key, as an array of registrable (or
 * exact) domains. When absent the composite stays silent — it is purely opt-in
 * caller context, never inferred.
 */
export const OWN_ACCOUNT_DOMAINS_CONTEXT_KEY = "accountDomains";

/** Read and validate the caller-supplied own-account domains from options.context. */
function readAccountDomains(options: AnalyzeOptions): string[] {
  const raw = options.context?.[OWN_ACCOUNT_DOMAINS_CONTEXT_KEY];
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((value): value is string => typeof value === "string")
    .map((value) => value.trim().toLowerCase())
    .filter((value) => value.length > 0);
}

/**
 * Composite (candidate): a visible From on one of the recipient's *own* account
 * domains that the message's authentication does not back up.
 *
 * Attacker model — self-domain spoofing. A spoofer puts the recipient's own
 * organization in the visible From ("From: it-helpdesk@yourcompany.example") to
 * impersonate an internal colleague or system. Mail genuinely from your own domain
 * is exactly the mail your infrastructure authenticates, so an unauthenticated From
 * on your own domain is a sharp tell on its own — without needing the divergent
 * second identifier the generic unauthenticatedFromSpoof composite requires. This is
 * the reusable form of the add-on's own-domain / auth-fail rule, with the account
 * domain supplied as caller context rather than baked into the core.
 *
 * What it combines:
 *   - the visible From's domain (exact or its registrable domain) is one of the
 *     caller-supplied own-account domains (see OWN_ACCOUNT_DOMAINS_CONTEXT_KEY). The
 *     registrable comparison uses the PSL-derived fromDomainParts.registrableDomain
 *     when a resolver was supplied, so a From on an organizational subdomain of an
 *     own domain still matches; with no resolver it is an exact-domain comparison.
 *   - no aligned authentication for that From: anyAuthAligned === false, no
 *     organizational (relaxed) aligned SPF/DKIM, and no aligned trusted DMARC pass
 *     for the From's organization — the same auth guard the other From-spoof
 *     composites use.
 *   - a trusted sender-auth check actually ran (trustedHeaderCount > 0 with at least
 *     one trusted SPF/DKIM/DMARC result), so unverifiable mail is not flagged.
 *
 * False-positive mitigation / not attacker-triggerable: legitimate internal mail
 * from your own domain authenticates as your own domain, so it satisfies the
 * alignment guard and is not flagged. The only way to *suppress* the signal is to
 * present aligned, trusted authentication for the own domain — which a spoofer who
 * does not control it cannot do. The signal can only be *raised* by the spoofer's
 * own unauthenticated self-domain forgery. (A misconfigured-but-honest internal
 * sender that fails auth lands here too, which is why severity is high but it stays
 * an observation, not a verdict — the caller correlates it with its own knowledge of
 * which internal systems are correctly configured.)
 *
 * Severity high: an unauthenticated message wearing your own organization's From is
 * a strong internal-impersonation lead. The caller owns the action.
 */
export const ownDomainSpoofCandidateRule: CompositeRule = {
  key: "composite.ownDomainSpoofCandidate",
  description:
    "The visible From is one of the caller's own account domains but the message has no aligned, trusted authentication.",
  evaluate({ metrics, signals, options }): Signal[] {
    const { authentication, fromDomain } = metrics;
    if (fromDomain === null) return [];

    const accountDomains = readAccountDomains(options);
    if (accountDomains.length === 0) return [];

    // Match the visible From — exact domain or its registrable (organizational)
    // domain — against the caller's own account domains. The registrable form lets a
    // From on an organizational subdomain of an own domain still match; with no
    // resolver fromDomainParts.registrableDomain is null and only the exact compare
    // applies.
    const fromRegistrable =
      metrics.senderIdentity.fromDomainParts?.registrableDomain ?? null;
    const accountSet = new Set(accountDomains);
    const matchedAccountDomain =
      (accountSet.has(fromDomain) ? fromDomain : null) ??
      (fromRegistrable !== null && accountSet.has(fromRegistrable) ? fromRegistrable : null);
    if (matchedAccountDomain === null) return [];

    // Require a trusted sender-auth check to have run so unverifiable mail is not
    // flagged as a spoof of the own domain.
    if (authentication.trustedHeaderCount === 0) return [];
    const hasTrustedSenderAuth =
      authentication.spfResults.some((result) => result.trusted) ||
      authentication.dkimResults.some((result) => result.trusted) ||
      authentication.dmarcResults.some((result) => result.trusted);
    if (!hasTrustedSenderAuth) return [];

    // Genuine own-domain mail authenticates as the own domain. Honor the exact,
    // organizational (relaxed), and aggregate-DMARC views, exactly as the other
    // From-spoof composites do, so only the genuinely unauthenticated own-domain From
    // reaches the signal.
    if (authentication.anyAuthAligned !== false) return [];
    if (authentication.organizational.anyAuthAligned) return [];
    if (authentication.organizational.dmarcPassAligned) return [];

    // The organizational projection is exact-only unless the *caller* supplied a
    // registrable-domain resolver, but matchedAccountDomain above can come from the
    // built-in PSL fallback (fromDomainParts.registrableDomain). Without this, a From
    // like `user@dept.mycorp.example` with trusted `dkim=pass header.d=mycorp.example`
    // — relaxed-aligned to the caller's own domain — would still emit the spoof
    // candidate. Compare trusted, passing SPF/DKIM/DMARC against the From's
    // registrable boundary rather than matchedAccountDomain itself: when the caller
    // supplies the exact From subdomain as an own-account domain, matchedAccountDomain
    // is that subdomain, and comparing against it would wrongly reject a legitimate
    // relaxed parent-domain pass. fromRegistrable is the same PSL-derived boundary
    // used to match the From above and is the correct organizational boundary in both
    // the exact-subdomain and registrable match cases; fall back to
    // matchedAccountDomain only when no PSL boundary is available at all.
    // Not attacker-triggerable: producing a trusted, passing identifier for the
    // caller's own domain requires control of that domain, which a spoofer lacks.
    const accountOrg = fromRegistrable ?? matchedAccountDomain;
    const sharesAccountOrg = (domain: string | null): boolean =>
      domain !== null && (domain === accountOrg || domain.endsWith(`.${accountOrg}`));
    const hasOrgAlignedDkim = authentication.dkimResults.some(
      (result) =>
        result.trusted && result.result === "pass" && sharesAccountOrg(result.headerD),
    );
    const hasOrgAlignedSpf = authentication.spfResults.some(
      (result) =>
        result.trusted && result.result === "pass" && sharesAccountOrg(result.smtpMailfrom),
    );
    if (hasOrgAlignedDkim || hasOrgAlignedSpf) return [];
    const hasOrgAlignedDmarcPass = authentication.dmarcResults.some(
      (result) =>
        result.trusted && result.result === "pass" && sharesAccountOrg(result.headerFrom),
    );
    if (hasOrgAlignedDmarcPass) return [];

    // Trace the trusted auth-failure signals that evidenced the missing alignment.
    // An untrusted failure is the attacker's own assertion and is never part of the
    // basis; the absence of any aligned trusted pass is itself sufficient evidence, so
    // this may be empty (e.g. a bare `dmarc=none` for the own domain emits no failure).
    const contributingSignals = [
      ...new Set(
        signals
          .filter(
            (signal) => signal.category === "auth-failure" && signal.data?.trusted === true,
          )
          .map((signal) => signal.key),
      ),
    ];

    return [
      {
        key: "composite.ownDomainSpoofCandidate",
        category: "composite",
        severity: "high",
        message:
          "Visible From is one of the recipient's own account domains but the message has no aligned, trusted authentication.",
        data: {
          fromDomain,
          matchedAccountDomain,
          anyAuthAligned: authentication.anyAuthAligned,
          dmarcPass: authentication.dmarcPass,
          contributingSignals,
        },
      },
    ];
  },
};
