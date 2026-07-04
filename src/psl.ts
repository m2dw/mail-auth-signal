import { getDomain } from "tldts";

/**
 * Built-in PSL-backed registrable-domain resolver using tldts.
 *
 * Uses ICANN public suffixes only (`allowPrivateDomains: false`), so private
 * entries such as `s3.amazonaws.com` are not treated as additional public
 * suffixes. Unknown TLDs (ones not listed in the PSL) follow tldts's default
 * fallback: the TLD itself is the effective public suffix and the second label
 * is the registrable domain.
 *
 * Examples:
 *   getRegistrableDomain("mail.example.co.jp") → "example.co.jp"
 *   getRegistrableDomain("example.com")        → "example.com"
 *   getRegistrableDomain("sub.evil.test")       → "evil.test"
 *
 * Returns null when tldts cannot derive a registrable domain (e.g. a bare TLD
 * or an IP address).
 *
 * Callers that need private-registry resolution, a pinned PSL snapshot, or
 * different unknown-TLD handling can supply their own resolver via
 * MetricsDependencies.getRegistrableDomain; it takes precedence over this one.
 */
export function getRegistrableDomain(domain: string): string | null {
  return getDomain(domain, { allowPrivateDomains: false }) ?? null;
}

/**
 * Whether `domain` sits *underneath* a PSL private (delegated-hosting) suffix such as
 * `s3.amazonaws.com`, `herokuapp.com`, or `github.io` — i.e. private-aware resolution
 * yields a strictly more specific registrable domain than the ICANN-only resolution
 * `getRegistrableDomain` returns.
 *
 * Brand-catalog matching consults this to avoid collapsing a brand-specific host
 * (e.g. a catalog entry `brand.s3.amazonaws.com`) down to the *shared provider*
 * registrable domain `amazonaws.com`: at the ICANN level `attacker.s3.amazonaws.com`
 * resolves to the same `amazonaws.com`, so an unrelated tenant on the same provider
 * would otherwise read as the brand. Because it reflects the delegated-hosting
 * boundary in the bundled PSL rather than an injected resolver's ICANN view, it is a
 * structural fact about the name, and using it only ever makes brand matching
 * *stricter* (never manufactures a match). Issue #84 follow-up.
 */
export function isUnderPrivateSuffix(domain: string): boolean {
  const icannRegistrable = getDomain(domain, { allowPrivateDomains: false });
  const privateRegistrable = getDomain(domain, { allowPrivateDomains: true });
  return privateRegistrable !== null && privateRegistrable !== icannRegistrable;
}
