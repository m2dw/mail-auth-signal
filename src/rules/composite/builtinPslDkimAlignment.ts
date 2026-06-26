import type { MessageMetrics } from "../../types.js";

/**
 * Built-in-PSL fallback for relaxed (organizational) DKIM alignment of the From.
 *
 * `authentication.organizational.anyDkimAligned` is exact-domain only unless the
 * *caller* supplied a registrable-domain resolver via MetricsDependencies, because
 * the organizational projection is computed against the caller-provided resolver.
 * The normal `analyzeMessage` path, however, still resolves
 * `senderIdentity.fromDomainParts.registrableDomain` with the built-in PSL (issue
 * #61). This helper reuses that already-resolved boundary to detect a DMARC-relaxed
 * aligned DKIM pass — e.g. From `news@mail.example.com` authenticated by a trusted
 * `dkim=pass header.d=example.com` — in the common default path where the
 * organizational projection has degraded to exact comparison.
 *
 * Mirrors the `sharesFromOrg` / `hasOrgAlignedDkim` boundary the deep and own
 * From-spoof composites already apply. Not attacker-triggerable: producing a
 * trusted, passing DKIM signature for the From's organizational domain requires
 * control of that domain, which a spoofer of someone else's domain lacks.
 *
 * Returns false when the From's registrable domain is unknown (no PSL match), so
 * callers fall back to whatever exact/organizational signals already hold.
 */
export function hasBuiltinPslOrgAlignedDkim(metrics: MessageMetrics): boolean {
  const sharesFromOrg = builtinPslFromOrgMatcher(metrics);
  if (sharesFromOrg === null) return false;

  return metrics.authentication.dkimResults.some(
    (result) =>
      result.trusted && result.result === "pass" && sharesFromOrg(result.headerD),
  );
}

/**
 * Built-in-PSL fallback for relaxed (organizational) alignment of *any* trusted,
 * passing sender-auth identifier — SPF, DKIM, or DMARC — against the From's
 * organizational domain.
 *
 * Same boundary and rationale as {@link hasBuiltinPslOrgAlignedDkim}, but it answers
 * the broader "is the From organization authenticated at all under relaxed alignment"
 * question that `authentication.organizational.anyAuthAligned` /
 * `organizational.dmarcPassAligned` answer only when the caller supplied a resolver.
 * Used by posture-reporting composites (e.g. brand divergence) that weigh authenticated
 * vs unauthenticated From, not just the DKIM-gated lexical mitigation.
 *
 * Not attacker-triggerable: a trusted, passing identifier for the From's organizational
 * domain requires control of that domain, which a spoofer of someone else's domain lacks.
 */
export function hasBuiltinPslOrgAlignedAuth(metrics: MessageMetrics): boolean {
  const sharesFromOrg = builtinPslFromOrgMatcher(metrics);
  if (sharesFromOrg === null) return false;

  const { dkimResults, spfResults, dmarcResults } = metrics.authentication;
  const hasOrgAlignedDkim = dkimResults.some(
    (result) => result.trusted && result.result === "pass" && sharesFromOrg(result.headerD),
  );
  const hasOrgAlignedSpf = spfResults.some(
    (result) => result.trusted && result.result === "pass" && sharesFromOrg(result.smtpMailfrom),
  );
  const hasOrgAlignedDmarc = dmarcResults.some(
    (result) => result.trusted && result.result === "pass" && sharesFromOrg(result.headerFrom),
  );
  return hasOrgAlignedDkim || hasOrgAlignedSpf || hasOrgAlignedDmarc;
}

/**
 * Build the From's organizational-boundary matcher from the built-in PSL-derived
 * registrable domain, or null when the From's registrable domain is unknown (no PSL
 * match) so callers fall back to whatever exact/organizational signals already hold.
 */
function builtinPslFromOrgMatcher(
  metrics: MessageMetrics,
): ((domain: string | null) => boolean) | null {
  const registrableDomain = metrics.senderIdentity.fromDomainParts?.registrableDomain ?? null;
  if (registrableDomain === null) return null;
  return (domain: string | null): boolean =>
    domain !== null &&
    (domain === registrableDomain || domain.endsWith(`.${registrableDomain}`));
}
