import type { CompositeRule, Signal } from "../../types.js";
import {
  hyphenSegments,
  isGeoCompoundToken,
  isGeoTokenCompoundLabel,
  registrableLabelOf,
} from "../../domainShape.js";
import { hasBuiltinPslOrgAlignedDkim } from "./builtinPslDkimAlignment.js";

/**
 * Composite (candidate): the visible From's *registrable* domain is a
 * geo/token compound — a hyphenated throwaway label carrying a two-letter region
 * token, e.g. From `…@official-zh-ayx.com`.
 *
 * Attacker model — disposable geo-token compound domain. A spammer registers a
 * cheap registrable domain whose label is a hyphen compound of a plausible word,
 * a two-letter geo/region code, and an opaque token (`official` + `zh` + `ayx`).
 * The shape is the tell: legitimate hyphenated brands are typically two readable
 * parts (`coca-cola`, `t-mobile`), whereas a bare two-letter region code wedged
 * into a three-part compound, or paired with a machine-generated segment, is the
 * throwaway shape isGeoTokenCompoundLabel recognizes.
 *
 * Why aligned DKIM is NOT a suppression here (issue #83). Because the spammer
 * *owns* the disposable registrable domain, they can align DKIM on it at near-zero
 * cost. A `!anyDkimAligned` guard would therefore be an attacker-controlled off
 * switch: the same `official-zh-ayx.com` sender suppresses the signal simply by
 * signing its own throwaway domain. The 2026-07 log analysis observed exactly this
 * adaptation. This rule is about the *domain shape*, which an aligned signature
 * does not make benign, so alignment is recorded as context in `data.dkimAligned`
 * rather than used as a hard suppression.
 *
 * Not a broad "aligned mail is suspicious" rule: the signal still requires the
 * suspicious geo/token compound registrable shape, so ordinary aligned mail on an
 * everyday domain never fires. It stays severity low — a fact-based candidate the
 * caller weighs with its own threshold; the core forms no policy.
 *
 * A trusted sender-auth check must actually have run (trustedHeaderCount > 0 with
 * at least one trusted SPF/DKIM/DMARC result), so unverifiable mail is not turned
 * into a candidate — the same guard the sibling deep-subdomain composites apply.
 */
export const geoTokenCompoundDomainRule: CompositeRule = {
  key: "composite.geoTokenCompoundDomain",
  description:
    "The visible From's registrable domain is a geo/token compound (a hyphenated throwaway label carrying a two-letter region token), regardless of DKIM alignment.",
  evaluate({ metrics }): Signal[] {
    const { authentication, fromDomain } = metrics;
    const fromParts = metrics.senderIdentity.fromDomainParts;

    if (fromParts === null) return [];
    const registrableDomain = fromParts.registrableDomain;
    if (registrableDomain === null) return [];

    const registrableLabel = registrableLabelOf(registrableDomain);
    if (!isGeoTokenCompoundLabel(registrableLabel)) return [];

    // Require a trusted sender-auth check to have actually run, so unverifiable mail
    // is not turned into a candidate (parity with the deep-subdomain composites).
    if (authentication.trustedHeaderCount === 0) return [];
    const hasTrustedSenderAuth =
      authentication.spfResults.some((result) => result.trusted) ||
      authentication.dkimResults.some((result) => result.trusted) ||
      authentication.dmarcResults.some((result) => result.trusted);
    if (!hasTrustedSenderAuth) return [];

    const segments = hyphenSegments(registrableLabel);
    const geoTokens = segments.filter((segment) => isGeoCompoundToken(segment));

    // DKIM alignment is context, never a suppression: an aligned signature on a
    // domain the attacker owns does not change its disposable compound shape.
    // Include built-in-PSL relaxed alignment so the context is accurate on the
    // default analyzeMessage path, where organizational.anyDkimAligned degrades to
    // exact-only (no caller resolver) and would report a relaxed-aligned subdomain
    // such as `news@mail.official-zh-ayx.com` signed by `d=official-zh-ayx.com` as
    // unaligned. See composite.builtinPslDkimAlignment.
    const dkimAligned =
      authentication.anyAlignedDkimPass ||
      authentication.organizational.anyDkimAligned ||
      hasBuiltinPslOrgAlignedDkim(metrics);

    return [
      {
        key: "composite.geoTokenCompoundDomain",
        category: "composite",
        severity: "low",
        message:
          "Visible From's registrable domain is a geo/token compound (hyphenated throwaway label with a two-letter region token).",
        data: {
          fromDomain,
          registrableDomain,
          registrableLabel,
          geoTokens,
          segmentCount: segments.length,
          dkimAligned,
          anyAuthAligned: authentication.anyAuthAligned,
          dmarcPass: authentication.dmarcPass,
          contributingSignals: [],
        },
      },
    ];
  },
};
