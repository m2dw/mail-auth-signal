import type { CompositeRule, Signal } from "../../types.js";
import { hasBuiltinPslOrgAlignedDkim } from "./builtinPslDkimAlignment.js";

/**
 * Composite (false-positive mitigation): a DKIM *failure* that co-occurs with an
 * aligned DKIM *pass* for the From domain — a benign broken/extra signature, not an
 * authentication gap.
 *
 * Why this mitigation exists. A message may carry several DKIM signatures: a mailing
 * list or forwarder commonly adds its own signature (which a downstream verifier
 * reports as `dkim=fail` because the body was modified) on top of the author
 * domain's still-valid signature. The base auth.method.failure signal faithfully
 * reports the failing DKIM result, but on its own a caller cannot tell that
 * "fingerprint" apart from a genuinely unauthenticated message. This composite names
 * the combination so the caller can recognize that the failure is harmless: an
 * aligned, trusted, passing DKIM signature for the From domain is present alongside
 * the failure.
 *
 * What it combines:
 *   - at least one trusted DKIM result with `result === "fail"` (the failing
 *     signature the base signal flagged); and
 *   - an aligned, trusted, passing DKIM signature for the From domain — either
 *     exact-domain (anyAlignedDkimPass) or DMARC-relaxed organizational alignment
 *     (organizational.anyDkimAligned, where the author signature is at the parent
 *     organizational domain of a From subdomain). DMARC's DKIM leg passes if *any*
 *     aligned signature passes, so the From domain is authenticated despite the
 *     co-occurring failure.
 *
 * Not attacker-triggerable: the gate is a real aligned DKIM pass, which only the
 * actual From domain can produce. A spoofer cannot manufacture the passing aligned
 * signature, so they cannot use this to make a forged message's DKIM failure read as
 * benign. The mitigation only *contextualizes* a failure the From domain already
 * authenticated past; it never suppresses a failure on an unauthenticated From.
 *
 * Severity info: mitigating context, not a risk. The core forms no policy — the
 * caller decides whether to discount the DKIM failure given the aligned pass.
 */
export const dkimFailWithAlignedPassRule: CompositeRule = {
  key: "composite.dkimFailWithAlignedPass",
  description:
    "A trusted DKIM failure co-occurs with an aligned, trusted, passing DKIM signature for the From domain (a benign broken/extra signature).",
  evaluate({ metrics }): Signal[] {
    const { authentication } = metrics;

    // The From domain must be DKIM-authenticated by an aligned, trusted, passing
    // signature — the cryptographic basis that the co-occurring failure is benign.
    // Honor both exact-domain alignment (anyAlignedDkimPass) and DMARC-relaxed
    // organizational alignment (organizational.anyDkimAligned): a From on a
    // subdomain whose author signature sits at the parent organizational domain
    // (e.g. From: news@mail.example.com signed by header.d=example.com) is
    // authenticated under relaxed alignment, and the same trust+pass gating still
    // applies, so a spoofer cannot manufacture it.
    const anyAlignedDkimPass = authentication.anyAlignedDkimPass;
    // organizational.anyDkimAligned is exact-only unless the *caller* supplied a
    // registrable-domain resolver, but senderIdentity.fromDomainParts.registrableDomain
    // is resolved with the built-in PSL fallback. Reuse that boundary so the common
    // default path (analyzeMessage without a custom getRegistrableDomain) still
    // recognizes a relaxed parent-domain DKIM pass — e.g. From: news@mail.example.com
    // with trusted dkim=pass header.d=example.com — exactly as the deep/own composites
    // do. Not attacker-triggerable: a trusted, passing signature for the From's
    // organizational domain requires control of that domain.
    const builtinPslOrgDkimAligned = hasBuiltinPslOrgAlignedDkim(metrics);
    const anyOrganizationalDkimAligned =
      authentication.organizational.anyDkimAligned || builtinPslOrgDkimAligned;
    if (!anyAlignedDkimPass && !anyOrganizationalDkimAligned) return [];

    // There must actually be a trusted DKIM failure to contextualize.
    const failingDkimDomains = [
      ...new Set(
        authentication.dkimResults
          .filter((result) => result.trusted && result.result === "fail")
          .map((result) => result.headerD)
          .filter((domain): domain is string => domain !== null),
      ),
    ];
    const hasTrustedDkimFail = authentication.dkimResults.some(
      (result) => result.trusted && result.result === "fail",
    );
    if (!hasTrustedDkimFail) return [];

    return [
      {
        key: "composite.dkimFailWithAlignedPass",
        category: "composite",
        severity: "info",
        message:
          "A DKIM signature failed, but an aligned DKIM signature for the From domain passed — the failure is a benign broken or additional signature.",
        data: {
          fromDomain: metrics.fromDomain,
          failingDkimDomains,
          anyAlignedDkimPass,
          anyOrganizationalDkimAligned,
          contributingSignals: [],
        },
      },
    ];
  },
};
