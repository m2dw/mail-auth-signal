import type { CompositeRule, Signal } from "../../types.js";
import { hasBuiltinPslOrgAlignedDkim } from "./builtinPslDkimAlignment.js";

/**
 * Composite (false-positive mitigation): a delegated sender whose From-domain
 * DKIM signature is aligned and whose envelope route is internally consistent —
 * the Message-ID domain shares a registrable domain with the smtp.mailfrom
 * domain — AND whose message carries mailing-list headers that confirm
 * newsletter/list context.
 *
 * Why this mitigation exists. Legitimate ESP/newsletter senders often show:
 *   - a passing, From-domain aligned DKIM signature (the sending platform
 *     signs on behalf of the list owner's domain), AND
 *   - an SPF smtp.mailfrom that does NOT match the From domain (the envelope
 *     sender is the ESP's own domain, not the list owner's), AND
 *   - a Message-ID whose registrable domain matches the ESP's smtp.mailfrom
 *     domain (consistent route: both the envelope and the Message-ID originate
 *     from the same infrastructure).
 *
 * Without further context this combination could be mistakenly flagged because
 * the SPF envelope mismatch looks like an identifier disagreement. The route
 * consistency and aligned DKIM evidence together constitute a positive counter-
 * signal that the sender is a legitimate delegated ESP.
 *
 * Why List headers are required (adversarial hardening). A self-signed
 * disposable-domain spammer can satisfy all three routing conditions without
 * being a legitimate delegated newsletter:
 *   - they control their own domain → aligned DKIM pass is trivial,
 *   - they can choose any smtp.mailfrom that mismatches From,
 *   - they can stamp a Message-ID on the same domain as smtp.mailfrom.
 *
 * Requiring at least one RFC 2369 / RFC 2919 list header (List-Id,
 * List-Unsubscribe, …) raises the bar: a spammer fabricating these headers
 * exposes itself to spam-filter heuristics that correlate list header presence
 * with actual list behaviour, and most disposable-domain bulk senders omit
 * them entirely. The mitigation is thus reserved for the intended legitimate
 * newsletter use case.
 *
 * Not fully attacker-proof (no mitigation is), but the additional friction
 * keeps the rule from being cheaply weaponised to launder spam through the
 * score offset a caller places on this badge.
 *
 * Severity info: it is the presence of mitigating evidence, not a risk. The
 * core forms no policy; the caller decides how much weight to give the
 * counter-signal versus any co-occurring mismatch signals.
 */
export const delegatedDkimAlignedRouteConsistentRule: CompositeRule = {
  key: "composite.delegatedDkimAlignedRouteConsistent",
  description:
    "A delegated sender with From-aligned DKIM, consistent Message-ID/envelope route, and mailing-list headers — mitigates false positives for legitimate ESP newsletter senders.",
  evaluate({ metrics }): Signal[] {
    // Guard: require mailing-list context. Without this a self-signed
    // disposable-domain sender can satisfy all routing conditions trivially.
    if (!metrics.hasListHeaders) return [];

    // Require From-domain aligned DKIM pass. Accept both exact-domain and
    // DMARC-relaxed organizational alignment (built-in PSL path, matching the
    // approach used by dkimAlignedLexicalMitigation). Not attacker-triggerable
    // against a third-party domain: the domain owner must produce the DKIM key.
    const anyAlignedDkimPass = metrics.authentication.anyAlignedDkimPass;
    const builtinPslOrgDkimAligned = hasBuiltinPslOrgAlignedDkim(metrics);
    const anyOrganizationalDkimAligned =
      metrics.authentication.organizational.anyDkimAligned || builtinPslOrgDkimAligned;
    if (!anyAlignedDkimPass && !anyOrganizationalDkimAligned) return [];

    // Need at least one smtp.mailfrom domain to check route consistency.
    if (metrics.smtpMailfromDomains.length === 0) return [];

    // Collect smtp.mailfrom domains from trusted, passing SPF results only.
    // Using the raw smtpMailfromDomains (populated from every SPF method line
    // regardless of result or trust) would allow a forged/untrusted
    // Authentication-Results header or a failed SPF record to satisfy the
    // route-consistency evidence this rule relies on.
    const trustedPassingSpfDomains = metrics.authentication.spfResults
      .filter((r) => r.trusted && r.result === "pass" && r.smtpMailfrom !== null)
      .map((r) => r.smtpMailfrom as string);

    // If no trusted passing SPF entry carries an smtp.mailfrom, the route
    // cannot be authenticated and the mitigation must not fire.
    if (trustedPassingSpfDomains.length === 0) return [];

    // Require envelope mismatch against trusted passing SPF only. The raw
    // smtpMailfromDomainMatchesFromDomain metric is derived from every SPF
    // method line regardless of result or trust: a failed or untrusted SPF line
    // with a different domain can make it false even when the only authenticated
    // (trusted pass) smtp.mailfrom domain matches From — which is not a
    // delegation pattern at all. Re-derive the mismatch from the already-filtered
    // trustedPassingSpfDomains so the guard is accurate.
    const fromDomain = metrics.fromDomain;
    const trustedPassMatchesFrom =
      fromDomain !== null &&
      trustedPassingSpfDomains.some(
        (d) =>
          d === fromDomain ||
          fromDomain.endsWith(`.${d}`) ||
          d.endsWith(`.${fromDomain}`),
      );
    // When the authenticated SPF route matches From there is no delegation
    // pattern; the mitigation must not fire.
    if (trustedPassMatchesFrom) return [];

    // Route consistency: the Message-ID domain's registrable domain must match
    // the smtp.mailfrom registrable domain — the Message-ID and the envelope
    // were stamped by the same infrastructure (the ESP). Use the built-in PSL
    // registrable domain from senderIdentity, consistent with how the lexical
    // mitigation and the deep/own composites resolve organizational boundaries.
    const messageIdParts = metrics.senderIdentity.messageIdDomainParts;
    if (messageIdParts === null) return [];
    const messageIdOrg = messageIdParts.registrableDomain ?? messageIdParts.domain;
    if (messageIdOrg === null) return [];

    // Resolve smtp.mailfrom registrable domains using the built-in PSL boundary
    // from senderIdentity where possible, falling back to domain-as-org.
    // We compare each trusted passing smtp.mailfrom domain against the
    // Message-ID registrable domain; route-consistent means ALL authenticated
    // smtp.mailfrom domains agree (an inconsistent multi-hop chain does not
    // qualify).
    const routeConsistent = trustedPassingSpfDomains.every((smtpDomain) => {
      // Use tldts-derived registrable domain. senderIdentity carries the
      // fromDomainParts resolver; for smtp.mailfrom domains we use a simple
      // suffix-match against the Message-ID org: exact registrable or subdomain.
      return smtpDomain === messageIdOrg || smtpDomain.endsWith(`.${messageIdOrg}`);
    });

    // Also check the reverse: Message-ID org is a subdomain of smtp.mailfrom.
    // (ESP stamps Message-ID on their sub-infrastructure.)
    const routeConsistentReverse =
      !routeConsistent &&
      trustedPassingSpfDomains.every((smtpDomain) => {
        return messageIdOrg === smtpDomain || messageIdOrg.endsWith(`.${smtpDomain}`);
      });

    if (!routeConsistent && !routeConsistentReverse) return [];

    return [
      {
        key: "composite.delegatedDkimAlignedRouteConsistent",
        category: "composite",
        severity: "info",
        message:
          "Delegated sender: From-aligned DKIM with consistent ESP envelope route and mailing-list headers.",
        data: {
          fromDomain: metrics.fromDomain,
          smtpMailfromDomains: metrics.smtpMailfromDomains,
          messageIdOrg,
          anyAlignedDkimPass,
          anyOrganizationalDkimAligned,
          hasListHeaders: metrics.hasListHeaders,
          contributingSignals: [],
        },
      },
    ];
  },
};
