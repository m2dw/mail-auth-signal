import type { PublicMailboxProvider } from "./types.js";

/**
 * Built-in catalog of high-confidence public mailbox provider registrable
 * domains, grouped by a stable provider id.
 *
 * Scope and rationale. A "public mailbox provider" here is a consumer mailbox
 * service that hands out addresses under a handful of well-known shared domains
 * (gmail.com, outlook.com, …) and publishes an enforcing DMARC policy for them.
 * That combination is what makes the catalog useful for spoofing detection:
 * legitimate mail from these domains authenticates and aligns, so a visible From
 * at one of them with no aligned authentication is a strong spoof candidate (see
 * the publicMailboxSpoofingCandidate composite). Consumers should not have to
 * hand-maintain this list just to detect that class, so the core bundles it.
 *
 * Deliberately small and explicit. This is hand-authored, owned by this project,
 * and intentionally narrow — it is *not* an imported Public Suffix List, brand
 * list, or third-party dataset, so it carries no external-data license burden
 * (see AGENTS.md / NOTICE). The entries are registrable (organizational) domains,
 * lower-cased; matching is done against the From registrable domain when a PSL
 * resolver is available, falling back to the exact From domain otherwise.
 *
 * Not policy. Membership is a fact ("this domain is a known public mailbox
 * provider"), never a verdict. The core forms no opinion on whether a public
 * mailbox From is good or bad — callers decide, and may extend or override the
 * catalog via MetricsDependencies.publicMailboxProviders.
 *
 * The ids ("google", "microsoft", …) are stable opaque labels a caller can group
 * or display by; they are not brand claims and carry no semantics beyond
 * identifying the catalog entry.
 */
export const defaultPublicMailboxProviders: readonly PublicMailboxProvider[] = [
  { id: "google", domains: ["gmail.com", "googlemail.com"] },
  { id: "microsoft", domains: ["outlook.com", "hotmail.com", "live.com", "msn.com"] },
  { id: "apple", domains: ["icloud.com", "me.com", "mac.com"] },
  { id: "yahoo", domains: ["yahoo.com", "yahoo.co.jp"] },
  { id: "aol", domains: ["aol.com"] },
];

/**
 * Return the provider id of the public mailbox provider that owns `domain`, or
 * null when `domain` is null or belongs to no catalog entry.
 *
 * Matching is an exact, case-insensitive comparison against each entry's
 * registrable domains: the catalog holds registrable domains, so the caller is
 * expected to pass either an already-registrable domain or one it knows matches a
 * catalog entry exactly (computeSenderIdentity tries the From registrable domain
 * first, then the bare From domain). No Public Suffix List logic is applied here,
 * so a subdomain like `mail.gmail.com` does not match unless a resolver already
 * reduced it to `gmail.com` upstream — keeping this function pure, data-free, and
 * free of any guessed organizational-domain boundary.
 *
 * The catalog defaults to the built-in defaultPublicMailboxProviders but may be a
 * caller-supplied list (extended or fully replaced); entry domains are compared
 * case-insensitively so a consumer catalog need not pre-normalize.
 */
export function lookupPublicMailboxProvider(
  domain: string | null,
  catalog: readonly PublicMailboxProvider[] = defaultPublicMailboxProviders,
): string | null {
  if (domain === null) return null;
  const needle = domain.toLowerCase();
  for (const provider of catalog) {
    for (const candidate of provider.domains) {
      if (candidate.toLowerCase() === needle) return provider.id;
    }
  }
  return null;
}
