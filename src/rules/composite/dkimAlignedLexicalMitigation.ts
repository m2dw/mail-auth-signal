import type { CompositeRule, Signal } from "../../types.js";
import { computeRandomLookingCandidate } from "../../senderIdentity.js";
import { hasBuiltinPslOrgAlignedDkim } from "./builtinPslDkimAlignment.js";

/**
 * Composite (false-positive mitigation): a From whose local part or domain *looks*
 * machine-generated but is cryptographically authenticated by an aligned DKIM
 * signature.
 *
 * Why this mitigation exists. The lexical / random-looking metrics
 * (computeRandomLookingCandidate over the From local part and domain labels) are
 * deliberately noisy: legitimate transactional senders, ESPs, and ticketing systems
 * routinely use random-looking local parts (`a8f3qz9k@…`) or labels. A caller
 * scoring those lexical hints needs a positive counter-signal for "this random-
 * looking identity is nonetheless provably the From domain", so it can avoid
 * penalizing authenticated automated mail. This composite supplies exactly that.
 *
 * What it combines:
 *   - a random-looking From identity: computeRandomLookingCandidate is true for the
 *     From local part, or for at least one From domain label (the structural,
 *     data-free check the add-on used). `data.lexicalBasis` names which.
 *   - an aligned, trusted, passing DKIM signature for the From domain — either
 *     exact-domain (anyAlignedDkimPass) or DMARC-relaxed organizational alignment
 *     (organizational.anyDkimAligned, where a From subdomain is signed by its parent
 *     organizational domain): cryptographic proof of authority over the From domain.
 *     DKIM (not SPF) is required because a DKIM signature is bound to the From
 *     domain's key, so it cannot be produced by a spoofer of a domain they do not
 *     control — the mitigation cannot be used to launder a forgery.
 *
 * Not attacker-triggerable: the gate is a real aligned DKIM pass, which only the
 * actual From domain can produce, so a spoofer cannot earn this badge for someone
 * else's domain. The signal only *lowers* the weight a caller might place on the
 * lexical shape; it never asserts the message is clean (a co-occurring identifier
 * mismatch is still surfaced by its own base/composite signals, which the caller
 * weighs separately).
 *
 * Severity info: it is the presence of mitigating evidence, not a risk. It carries
 * `contributingSignals: []` for shape parity (its justification is a metric plus an
 * auth fact, not a lower-layer signal). The core forms no policy: the caller decides
 * how much the cryptographic proof offsets the lexical suspicion.
 */
export const dkimAlignedLexicalMitigationRule: CompositeRule = {
  key: "composite.dkimAlignedLexicalMitigation",
  description:
    "A random-looking From identity is mitigated by an aligned, trusted, passing DKIM signature for the From domain.",
  evaluate({ metrics }): Signal[] {
    const { authentication, senderIdentity } = metrics;

    // Require the cryptographic counter-evidence first: an aligned, trusted, passing
    // DKIM signature for the From domain. Without it there is nothing to mitigate with.
    // Accept both exact-domain alignment (anyAlignedDkimPass) and DMARC-relaxed
    // organizational alignment (organizational.anyDkimAligned): random-looking mail on
    // a subdomain signed by its parent organizational domain (an ESP/automated sender
    // under relaxed alignment) is just as authenticated, and the same trust+pass gating
    // keeps a spoofer from earning the badge for a domain they do not control.
    const anyAlignedDkimPass = authentication.anyAlignedDkimPass;
    // organizational.anyDkimAligned is exact-only unless the *caller* supplied a
    // registrable-domain resolver, but senderIdentity.fromDomainParts.registrableDomain
    // is resolved with the built-in PSL fallback. Reuse that boundary so the common
    // default path (analyzeMessage without a custom getRegistrableDomain) still
    // recognizes a relaxed parent-domain DKIM pass — e.g. a random-looking
    // From: a8f3qz9k@mail.example.com with trusted dkim=pass header.d=example.com —
    // exactly as the deep/own composites do. Not attacker-triggerable: a trusted,
    // passing signature for the From's organizational domain requires control of it.
    const builtinPslOrgDkimAligned = hasBuiltinPslOrgAlignedDkim(metrics);
    const anyOrganizationalDkimAligned =
      authentication.organizational.anyDkimAligned || builtinPslOrgDkimAligned;
    if (!anyAlignedDkimPass && !anyOrganizationalDkimAligned) return [];

    // Identify which part of the From identity reads as random-looking.
    const lexicalBasis: string[] = [];
    if (senderIdentity.localPart !== null && computeRandomLookingCandidate(senderIdentity.localPart)) {
      lexicalBasis.push("localPart");
    }
    const fromParts = senderIdentity.fromDomainParts;
    if (fromParts !== null && fromParts.labels.some((label) => computeRandomLookingCandidate(label))) {
      lexicalBasis.push("domainLabel");
    }
    // No lexical suspicion to mitigate — stay silent rather than emit a vacuous badge.
    if (lexicalBasis.length === 0) return [];

    return [
      {
        key: "composite.dkimAlignedLexicalMitigation",
        category: "composite",
        severity: "info",
        message:
          "From identity looks machine-generated but is authenticated by an aligned DKIM signature.",
        data: {
          fromDomain: metrics.fromDomain,
          lexicalBasis,
          anyAlignedDkimPass,
          anyOrganizationalDkimAligned,
          contributingSignals: [],
        },
      },
    ];
  },
};
