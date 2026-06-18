import { describe, expect, it } from "vitest";
import {
  analyzeMessage,
  defaultCompositeRules,
  defaultRules,
  unsecuredDeepSubdomainCandidateRule,
} from "../src/index.js";
import type { AnalyzeInput, AnalyzeResult, MetricsDependencies, Signal } from "../src/index.js";

const TRUSTED_ID = "mx.example.net";

/**
 * A tiny stand-in Public Suffix List resolver; the core bundles none, so the
 * subdomain-depth metric this rule needs is only available when a caller injects
 * one. Each disposable deep-subdomain host resolves to its cheap registrable
 * domain, and the benign hosts resolve to their organizational domains.
 */
const PSL: Record<string, string> = {
  "sivakeso.support.sn5799.com": "sn5799.com",
  "deep.sub.disposable.test": "disposable.test",
  "mail.example.com": "example.com",
  "bounce.mail.example.com": "example.com",
  "example.com": "example.com",
};
const deps: MetricsDependencies = { getRegistrableDomain: (domain) => PSL[domain] ?? null };

/** analyzeMessage with the default base rules, the PSL resolver, and composites enabled. */
function analyze(input: AnalyzeInput): AnalyzeResult {
  return analyzeMessage(input, defaultRules, deps, defaultCompositeRules);
}

function candidate(signals: readonly Signal[]): Signal | undefined {
  return signals.find((s) => s.key === "composite.unsecuredDeepSubdomainCandidate");
}

describe("composite.unsecuredDeepSubdomainCandidate", () => {
  it("flags a deep subdomain whose org domain reports trusted DMARC none", () => {
    const result = analyze({
      headers: {
        from: "Support <alerts@sivakeso.support.sn5799.com>",
        "authentication-results": `${TRUSTED_ID}; dmarc=none header.from=sivakeso.support.sn5799.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.senderIdentity.fromDomainParts?.subdomainDepth).toBe(2);
    const signal = candidate(result.signals);
    expect(signal).toBeDefined();
    expect(signal?.severity).toBe("low");
    expect(signal?.category).toBe("composite");
    expect(signal?.data?.fromDomain).toBe("sivakeso.support.sn5799.com");
    expect(signal?.data?.registrableDomain).toBe("sn5799.com");
    expect(signal?.data?.subdomainDepth).toBe(2);
    expect(signal?.data?.anyAuthAligned).toBe(false);
    expect(signal?.data?.contributingSignals).toEqual([]);
  });

  it("does not flag a shallow (depth 1) subdomain with DMARC none", () => {
    const result = analyze({
      headers: {
        from: "Mailer <a@mail.example.com>",
        "authentication-results": `${TRUSTED_ID}; dmarc=none header.from=mail.example.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.senderIdentity.fromDomainParts?.subdomainDepth).toBe(1);
    expect(candidate(result.signals)).toBeUndefined();
  });

  it("does not flag a registrable domain (depth 0) with DMARC none", () => {
    const result = analyze({
      headers: {
        from: "Org <a@example.com>",
        "authentication-results": `${TRUSTED_ID}; dmarc=none header.from=example.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.senderIdentity.fromDomainParts?.subdomainDepth).toBe(0);
    expect(candidate(result.signals)).toBeUndefined();
  });

  it("does not flag a deep subdomain whose DMARC is not none (e.g. fail)", () => {
    const result = analyze({
      headers: {
        from: "Support <alerts@deep.sub.disposable.test>",
        "authentication-results": `${TRUSTED_ID}; dmarc=fail header.from=deep.sub.disposable.test`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.senderIdentity.fromDomainParts?.subdomainDepth).toBe(2);
    expect(candidate(result.signals)).toBeUndefined();
  });

  it("does not flag a deep subdomain backed by aligned DKIM despite DMARC none", () => {
    // A legitimately signed ESP-style deep subdomain: DMARC=none (no published
    // policy) but an aligned, trusted, passing DKIM signature authenticates the
    // From. The false-positive guard withholds the candidate.
    const result = analyze({
      headers: {
        from: "Mail <a@bounce.mail.example.com>",
        "authentication-results": `${TRUSTED_ID}; dmarc=none header.from=bounce.mail.example.com; dkim=pass header.d=bounce.mail.example.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.senderIdentity.fromDomainParts?.subdomainDepth).toBe(2);
    expect(result.metrics.authentication.anyAuthAligned).toBe(true);
    expect(candidate(result.signals)).toBeUndefined();
  });

  it("flags when the trusted DMARC none names the organizational domain (relaxed)", () => {
    // A verifier may report the registrable/organizational domain in header.from
    // rather than the exact deep-subdomain From. That still describes this From's
    // organization, so the candidate is bound and raised.
    const result = analyze({
      headers: {
        from: "Support <alerts@sivakeso.support.sn5799.com>",
        "authentication-results": `${TRUSTED_ID}; dmarc=none header.from=sn5799.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(candidate(result.signals)).toBeDefined();
  });

  it("does not flag when the trusted DMARC none names a different From domain", () => {
    // With several trusted AR headers, the deep-subdomain From's own DMARC passes
    // while a trusted dmarc=none describes an unrelated domain. The none must be
    // bound to this From's organizational domain, so it does not raise the
    // candidate for a From that is actually DMARC-protected.
    const result = analyze({
      headers: {
        from: "Support <alerts@sivakeso.support.sn5799.com>",
        "authentication-results": [
          `${TRUSTED_ID}; dmarc=pass header.from=sivakeso.support.sn5799.com`,
          `${TRUSTED_ID}; dmarc=none header.from=unrelated.test`,
        ],
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.senderIdentity.fromDomainParts?.subdomainDepth).toBe(2);
    expect(candidate(result.signals)).toBeUndefined();
  });

  it("does not flag when a trusted aggregate DMARC pass authenticates the visible From", () => {
    // Aggregate-only reporting: a trusted verifier emits `dmarc=pass
    // header.from=<visible From>` with no SPF/DKIM method rows (so anyAuthAligned
    // stays vacuously false), alongside a trusted `dmarc=none` for the same org.
    // DMARC only passes when an aligned SPF/DKIM identifier satisfied the From's
    // policy, so this is authenticated mail and must not be flagged — matching how
    // the other composites count this DMARC-only pass as authenticating the From.
    const result = analyze({
      headers: {
        from: "Support <alerts@sivakeso.support.sn5799.com>",
        "authentication-results": [
          `${TRUSTED_ID}; dmarc=pass header.from=sivakeso.support.sn5799.com`,
          `${TRUSTED_ID}; dmarc=none header.from=sn5799.com`,
        ],
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.senderIdentity.fromDomainParts?.subdomainDepth).toBe(2);
    expect(result.metrics.authentication.anyAuthAligned).toBe(false);
    expect(result.metrics.authentication.dmarcPass).toBe(true);
    expect(candidate(result.signals)).toBeUndefined();
  });

  it("does not flag a deep subdomain backed by org-domain (relaxed) aligned DKIM", () => {
    // Parent-domain signing: From `bounce.mail.example.com` signed with
    // `header.d=example.com`. anyAuthAligned is exact-match only, so it is false
    // here, but DMARC's relaxed alignment treats this as authenticated, so the
    // same-org guard withholds the candidate.
    const result = analyze({
      headers: {
        from: "Mail <a@bounce.mail.example.com>",
        "authentication-results": `${TRUSTED_ID}; dmarc=none header.from=bounce.mail.example.com; dkim=pass header.d=example.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.senderIdentity.fromDomainParts?.subdomainDepth).toBe(2);
    expect(result.metrics.authentication.anyAuthAligned).toBe(false);
    expect(candidate(result.signals)).toBeUndefined();
  });

  it("does not flag a deep subdomain backed by org-domain (relaxed) aligned SPF", () => {
    // Envelope at the organizational domain: From `bounce.mail.example.com` with
    // an aligned-by-relaxed SPF pass on `smtp.mailfrom=example.com`.
    const result = analyze({
      headers: {
        from: "Mail <a@bounce.mail.example.com>",
        "authentication-results": `${TRUSTED_ID}; dmarc=none header.from=bounce.mail.example.com; spf=pass smtp.mailfrom=example.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.senderIdentity.fromDomainParts?.subdomainDepth).toBe(2);
    expect(result.metrics.authentication.anyAuthAligned).toBe(false);
    expect(candidate(result.signals)).toBeUndefined();
  });

  it("does not flag when the DMARC none comes only from an untrusted header", () => {
    // An untrusted AR header's dmarc=none is forge-able and not authoritative, so
    // it must not, on its own, raise the candidate.
    const result = analyze({
      headers: {
        from: "Support <alerts@sivakeso.support.sn5799.com>",
        "authentication-results": "relay.evil.test; dmarc=none header.from=sivakeso.support.sn5799.com",
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.senderIdentity.fromDomainParts?.subdomainDepth).toBe(2);
    expect(candidate(result.signals)).toBeUndefined();
  });

  it("stays silent without a PSL resolver (subdomain depth is unknown)", () => {
    // No resolver injected, so fromDomainParts.subdomainDepth is null and a deep
    // subdomain cannot be distinguished from a registrable domain.
    const result = analyzeMessage(
      {
        headers: {
          from: "Support <alerts@sivakeso.support.sn5799.com>",
          "authentication-results": `${TRUSTED_ID}; dmarc=none header.from=sivakeso.support.sn5799.com`,
        },
        options: { trustedAuthservIds: [TRUSTED_ID] },
      },
      defaultRules,
      undefined,
      defaultCompositeRules,
    );
    expect(result.metrics.senderIdentity.fromDomainParts?.subdomainDepth).toBeNull();
    expect(candidate(result.signals)).toBeUndefined();
  });

  it("is disabled by default (no composite rules passed in)", () => {
    const result = analyzeMessage(
      {
        headers: {
          from: "Support <alerts@sivakeso.support.sn5799.com>",
          "authentication-results": `${TRUSTED_ID}; dmarc=none header.from=sivakeso.support.sn5799.com`,
        },
        options: { trustedAuthservIds: [TRUSTED_ID] },
      },
      defaultRules,
      deps,
    );
    expect(candidate(result.signals)).toBeUndefined();
  });

  it("exposes a stable rule identity", () => {
    expect(unsecuredDeepSubdomainCandidateRule.key).toBe(
      "composite.unsecuredDeepSubdomainCandidate",
    );
  });
});
