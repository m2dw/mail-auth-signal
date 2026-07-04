import type { CompositeRule, Signal } from "../../types.js";
import { computeRandomLookingCandidate } from "../../senderIdentity.js";
import { isServiceWordLabel } from "../../domainShape.js";
import { hasBuiltinPslOrgAlignedDkim } from "./builtinPslDkimAlignment.js";

/**
 * Composite (candidate): the visible From sits on a deep subdomain that stacks a
 * *readable service word* (`accounts`, `updates`, `orders`, …) next to a
 * machine-generated label — the "service-word sandwich" of a disposable domain,
 * e.g. From `…@accounts.k2m9x.official-store.test`.
 *
 * Attacker model — disposable service-word subdomain. The attacker registers a
 * throwaway registrable domain and sends from a deep subdomain whose leftmost
 * labels are deliberately *readable* ("accounts", "support") so a per-label
 * randomness heuristic does not fire. The sibling composite.deepRandomFromSubdomain
 * catches the all-random twin; this one catches the readable-service-word variant.
 * The tell is the *combination*: a service word stacked in a deep subdomain
 * alongside a machine-generated label (a random subdomain sibling or a
 * random-looking registrable base) — the disposable shape a legitimate
 * `accounts.google.com` (depth 1, no random companion) never has.
 *
 * Why aligned DKIM is NOT a suppression here (issue #83). The attacker owns the
 * disposable registrable domain and can align DKIM on it for free, so a
 * `!anyDkimAligned` guard would be an attacker-controlled off switch — precisely
 * the adaptation the 2026-07 log analysis observed, where the same sender pattern
 * differed only in whether DKIM was aligned. This rule is about domain *shape*,
 * which an aligned signature does not make benign, so alignment is recorded as
 * context in `data.dkimAligned` rather than used as a hard suppression. It never
 * makes ordinary aligned mail suspicious: the deep-subdomain + service-word +
 * machine-generated-companion shape is still required.
 *
 * What it combines (identity structure):
 *   - subdomainDepth >= 2: the From sits at least two labels above its registrable
 *     domain. PSL-derived, so it is only available when a registrable-domain
 *     resolver was supplied; without one the depth is null and the rule stays
 *     silent rather than guess (the core bundles no PSL data).
 *   - at least one *subdomain* label (a label above the registrable domain) is a
 *     readable service word (isServiceWordLabel, expanded per issue #83).
 *   - a machine-generated companion: another label in the host — a different
 *     subdomain label or a label of the registrable domain — reads as random by
 *     computeRandomLookingCandidate. This is what distinguishes a disposable
 *     throwaway from a legitimate deep service subdomain (`en.updates.example.com`),
 *     and keeps ordinary aligned mail from firing.
 *
 * Requires a trusted sender-auth check to have actually run (trustedHeaderCount > 0
 * with at least one trusted SPF/DKIM/DMARC result), so unverifiable mail is not
 * turned into a candidate. Severity low: a fact-based candidate lead, not a
 * verdict; the caller owns the threshold and action.
 */
export const deepServiceWordSubdomainRule: CompositeRule = {
  key: "composite.deepServiceWordSubdomain",
  description:
    "The visible From is on a deep subdomain (>= 2 levels) stacking a readable service word next to a machine-generated label, regardless of DKIM alignment.",
  evaluate({ metrics }): Signal[] {
    const { authentication, fromDomain } = metrics;
    const fromParts = metrics.senderIdentity.fromDomainParts;

    // Depth is PSL-derived: without a resolver a deep subdomain is indistinguishable
    // from a bare registrable domain, so stay silent rather than guess.
    if (fromParts === null || fromParts.subdomainDepth === null) return [];
    if (fromParts.subdomainDepth < 2) return [];
    const registrableDomain = fromParts.registrableDomain;
    if (registrableDomain === null) return [];

    // The subdomain labels are the labels above the registrable domain.
    const subdomainLabels = fromParts.labels.slice(0, fromParts.subdomainDepth);
    const serviceWordLabels = subdomainLabels.filter((label) => isServiceWordLabel(label));
    if (serviceWordLabels.length === 0) return [];

    // A machine-generated companion elsewhere in the host is what makes this the
    // disposable shape rather than a legitimate deep service subdomain. Consider any
    // label except the service words themselves — other subdomain labels and the
    // registrable-domain labels (excluding the public-suffix top label).
    const serviceWordSet = new Set(serviceWordLabels);
    const registrableTopLabel = fromParts.topLabel;
    const companionLabels = fromParts.labels.filter(
      (label) => !serviceWordSet.has(label) && label !== registrableTopLabel,
    );
    const randomLabels = companionLabels.filter((label) =>
      computeRandomLookingCandidate(label),
    );
    if (randomLabels.length === 0) return [];

    // Require a trusted sender-auth check to have actually run.
    if (authentication.trustedHeaderCount === 0) return [];
    const hasTrustedSenderAuth =
      authentication.spfResults.some((result) => result.trusted) ||
      authentication.dkimResults.some((result) => result.trusted) ||
      authentication.dmarcResults.some((result) => result.trusted);
    if (!hasTrustedSenderAuth) return [];

    // DKIM alignment is context, never a suppression: an aligned signature on a
    // domain the attacker owns does not change its disposable subdomain shape.
    // Include built-in-PSL relaxed alignment so the context is accurate on the
    // default analyzeMessage path, where organizational.anyDkimAligned degrades to
    // exact-only (no caller resolver) and would report a relaxed-aligned deep From
    // such as `accounts.k2m9x7.cheapdomain.com` signed by `d=cheapdomain.com` as
    // unaligned. See composite.builtinPslDkimAlignment.
    const dkimAligned =
      authentication.anyAlignedDkimPass ||
      authentication.organizational.anyDkimAligned ||
      hasBuiltinPslOrgAlignedDkim(metrics);

    return [
      {
        key: "composite.deepServiceWordSubdomain",
        category: "composite",
        severity: "low",
        message:
          "Visible From is on a deep subdomain stacking a readable service word next to a machine-generated label.",
        data: {
          fromDomain,
          registrableDomain,
          subdomainDepth: fromParts.subdomainDepth,
          serviceWordLabels,
          randomLabels,
          dkimAligned,
          anyAuthAligned: authentication.anyAuthAligned,
          dmarcPass: authentication.dmarcPass,
          contributingSignals: [],
        },
      },
    ];
  },
};
