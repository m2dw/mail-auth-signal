import type { Rule } from "../types.js";

/**
 * Flags messages where a trusted, passing DMARC `header.from` domain differs from
 * the visible `From` domain the recipient parses.
 *
 * Attacker pattern: DMARC's `header.from` is the receiver's own parse of the
 * RFC 5322 From domain — the domain a DMARC `pass` actually vouches for. When a
 * crafted From header is ambiguous (e.g. two From headers, encoded-word tricks,
 * or list-syntax edge cases) the verifier and the recipient's mail client can
 * resolve different domains from it. A DMARC `pass` for `header.from=X` then gets
 * displayed against a From the user reads as `Y`: an authentication "pass" badge
 * applied to a domain the user never sees. This rule surfaces exactly that
 * parser-differential gap between what was authenticated and what is shown.
 *
 * Pass-and-trust gated by construction: this rule reads dmarcHeaderFromDomains,
 * which the metric layer populates only from DMARC results that passed and only
 * from trusted Authentication-Results headers. A non-pass DMARC authenticates
 * nothing, so its header.from never enters the comparison — a failed DMARC is
 * already surfaced by authMethodFailureRule and must not also manufacture a noisy
 * consistency mismatch here. And because header.from is not cryptographic (unlike
 * a DKIM signature), a forge-able untrusted header's value is just the attacker's
 * own assertion of what they "evaluated"; trivially matched or mismatched, it
 * carries no signal, so untrusted headers are excluded entirely.
 *
 * False-positive note: even a trusted, passing DMARC header.from can legitimately
 * differ from the parsed From in benign ways — the comparison is exact, so a
 * subdomain difference or a verifier that records the organizational domain reads
 * as a mismatch, and this core deliberately adds no PSL/org-domain logic. The
 * signal is therefore low severity and exists only as a consistency hint, never a
 * verdict; the caller correlates it with the actual DMARC result and its own
 * policy before acting.
 *
 * Noise control for missing/malformed input: the comparison is skipped entirely
 * (dmarcHeaderFromMatchesFromDomain === null) when there is nothing to compare —
 * a missing From, no trusted+passing DMARC result, or a header.from the parser
 * could not resolve to a real dotted domain. When several headers carry
 * header.from values, a single domain that differs from From is enough to flag.
 */
export const dmarcHeaderFromMismatchRule: Rule = {
  key: "dmarc.headerFromMismatch",
  description: "A trusted, passing DMARC header.from domain does not match the visible From domain.",
  evaluate({ metrics }) {
    if (metrics.dmarcHeaderFromMatchesFromDomain !== false) return [];
    const mismatchedDomains = metrics.dmarcHeaderFromDomains.filter(
      (domain) => domain !== metrics.fromDomain,
    );
    return [
      {
        key: "dmarc.headerFromMismatch",
        severity: "low",
        message: "DMARC header.from domain differs from the visible From domain.",
        data: {
          fromDomain: metrics.fromDomain,
          dmarcHeaderFromDomains: metrics.dmarcHeaderFromDomains,
          mismatchedDomains,
        },
      },
    ];
  },
};
