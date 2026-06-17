import type { Rule } from "../types.js";

/**
 * Flags messages whose Return-Path domain and SPF `smtp.mailfrom` domain
 * disagree with each other.
 *
 * Both headers describe the same thing — the envelope sender (MAIL FROM /
 * reverse-path) — so on a coherent message they name the same domain. When they
 * disagree, the message's own envelope metadata is internally inconsistent: a
 * sign the Return-Path was rewritten, stripped and re-added, or forged
 * independently of the SPF-checked envelope-from. This is orthogonal to the
 * From-alignment rules, so it can surface tampering even when both values happen
 * to align with (or both diverge from) From.
 *
 * False-positive note: a benign disagreement is possible — an intermediate hop
 * may rewrite Return-Path while an earlier Authentication-Results header retains
 * the original smtp.mailfrom, and a forwarding chain legitimately produces
 * several smtp.mailfrom values. The signal is therefore low severity and exists
 * only as a consistency hint, never a verdict; the caller correlates it with the
 * authentication results and its own policy before acting.
 *
 * Noise control for missing/malformed input: the comparison is skipped entirely
 * (envelopeSenderDomainsAgree === null) when there is nothing to compare — no
 * Return-Path domain (missing or null `<>`) or no smtp.mailfrom domain. Having
 * only one of the two envelope-sender sources therefore emits no signal. The
 * comparison is exact; any smtp.mailfrom domain differing from the Return-Path
 * domain is enough to flag.
 */
export const envelopeSenderDisagreementRule: Rule = {
  key: "envelopeSender.domainDisagreement",
  description: "The Return-Path domain and an SPF smtp.mailfrom domain disagree.",
  evaluate({ metrics }) {
    if (metrics.envelopeSenderDomainsAgree !== false) return [];
    const disagreeingDomains = metrics.smtpMailfromDomains.filter(
      (domain) => domain !== metrics.returnPathDomain,
    );
    return [
      {
        key: "envelopeSender.domainDisagreement",
        severity: "low",
        message: "Return-Path domain differs from the SPF smtp.mailfrom domain.",
        data: {
          returnPathDomain: metrics.returnPathDomain,
          smtpMailfromDomains: metrics.smtpMailfromDomains,
          disagreeingDomains,
        },
      },
    ];
  },
};
