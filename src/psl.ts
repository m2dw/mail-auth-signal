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
