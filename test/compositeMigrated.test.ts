import { describe, expect, it } from "vitest";
import {
  analyzeMessage,
  brandDivergencePhishingRule,
  deepRandomFromSubdomainRule,
  defaultCompositeRules,
  defaultRules,
  dkimAlignedLexicalMitigationRule,
  dkimFailWithAlignedPassRule,
  OWN_ACCOUNT_DOMAINS_CONTEXT_KEY,
  ownDomainSpoofCandidateRule,
} from "../src/index.js";
import type {
  AnalyzeInput,
  AnalyzeResult,
  BrandCatalogEntry,
  MetricsDependencies,
  Signal,
} from "../src/index.js";

const TRUSTED_ID = "mx.example.net";

function compositeKeys(result: AnalyzeResult): string[] {
  return result.signals.filter((s) => s.category === "composite").map((s) => s.key);
}

function compositeSignal(result: AnalyzeResult, key: string): Signal | undefined {
  return result.signals.find((s) => s.key === key);
}

function analyze(input: AnalyzeInput, deps?: MetricsDependencies): AnalyzeResult {
  return analyzeMessage(input, defaultRules, deps, defaultCompositeRules);
}

describe("composite rules — stable identity", () => {
  it("each migrated composite exposes a stable, documented key", () => {
    expect(deepRandomFromSubdomainRule.key).toBe("composite.deepRandomFromSubdomain");
    expect(brandDivergencePhishingRule.key).toBe("composite.brandDivergencePhishing");
    expect(ownDomainSpoofCandidateRule.key).toBe("composite.ownDomainSpoofCandidate");
    expect(dkimFailWithAlignedPassRule.key).toBe("composite.dkimFailWithAlignedPass");
    expect(dkimAlignedLexicalMitigationRule.key).toBe("composite.dkimAlignedLexicalMitigation");
    expect(OWN_ACCOUNT_DOMAINS_CONTEXT_KEY).toBe("accountDomains");
  });
});

describe("composite.deepRandomFromSubdomain", () => {
  // Resolver: everything under cheapdomain.test is organizationally cheapdomain.test.
  const deps: MetricsDependencies = {
    getRegistrableDomain: (domain) =>
      domain === "cheapdomain.test" || domain.endsWith(".cheapdomain.test")
        ? "cheapdomain.test"
        : null,
  };

  it("fires (spam-like) on a deep, random-looking subdomain with no aligned auth", () => {
    const result = analyze(
      {
        headers: {
          from: "Notice <notice@a8f3qz.k2pls.cheapdomain.test>",
          "authentication-results": `${TRUSTED_ID}; dmarc=fail header.from=a8f3qz.k2pls.cheapdomain.test`,
        },
        options: { trustedAuthservIds: [TRUSTED_ID] },
      },
      deps,
    );
    const signal = compositeSignal(result, "composite.deepRandomFromSubdomain");
    expect(signal?.severity).toBe("low");
    expect(signal?.data?.registrableDomain).toBe("cheapdomain.test");
    expect(signal?.data?.subdomainDepth).toBe(2);
    expect(signal?.data?.randomLabels).toContain("a8f3qz");
  });

  it("stays silent (ham-like) when an aligned DKIM signature authenticates the From", () => {
    const result = analyze(
      {
        headers: {
          from: "Notice <notice@a8f3qz.k2pls.cheapdomain.test>",
          "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=a8f3qz.k2pls.cheapdomain.test`,
        },
        options: { trustedAuthservIds: [TRUSTED_ID] },
      },
      deps,
    );
    expect(result.metrics.authentication.anyAuthAligned).toBe(true);
    expect(compositeKeys(result)).not.toContain("composite.deepRandomFromSubdomain");
  });

  it("stays silent without a resolver (subdomain depth is unknown)", () => {
    const result = analyze({
      headers: {
        from: "Notice <notice@a8f3qz.k2pls.cheapdomain.test>",
        "authentication-results": `${TRUSTED_ID}; dmarc=fail header.from=a8f3qz.k2pls.cheapdomain.test`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    }, { getRegistrableDomain: () => null });
    expect(compositeKeys(result)).not.toContain("composite.deepRandomFromSubdomain");
  });

  it("stays silent under the default PSL when relaxed parent-domain DKIM aligns the From", () => {
    // No caller resolver: fromDomainParts uses the built-in PSL (so depth is known),
    // but authentication.organizational degrades to exact comparison and reads the
    // parent-domain DKIM as unaligned. The relaxed parent signing must still suppress
    // the candidate via the fromParts registrable boundary.
    const result = analyze({
      headers: {
        from: "Notice <notice@a8f3qz.mail.example.com>",
        "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=example.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.senderIdentity.fromDomainParts?.subdomainDepth).toBe(2);
    expect(result.metrics.authentication.anyAuthAligned).toBe(false);
    expect(result.metrics.authentication.organizational.anyAuthAligned).toBe(false);
    expect(compositeKeys(result)).not.toContain("composite.deepRandomFromSubdomain");
  });
});

describe("composite.brandDivergencePhishing", () => {
  const brandCatalog: BrandCatalogEntry[] = [{ brand: "paypal", domains: ["paypal.com"] }];

  it("fires high (spam-like) when the display name reads as a brand the From is not", () => {
    const result = analyze(
      {
        headers: {
          from: '"PayPal" <security@evil.test>',
          "authentication-results": `${TRUSTED_ID}; dmarc=fail header.from=evil.test`,
        },
        options: { trustedAuthservIds: [TRUSTED_ID] },
      },
      { brandCatalog },
    );
    const signal = compositeSignal(result, "composite.brandDivergencePhishing");
    expect(signal?.severity).toBe("high");
    expect(signal?.data?.inferredBrand).toBe("paypal");
    expect(signal?.data?.inferredBrandDomains).toEqual(["paypal.com"]);
    expect(signal?.data?.fromAuthenticated).toBe(false);
    // Traces the base brand-mismatch consistency signal.
    expect(signal?.data?.contributingSignals).toContain("displayName.brandDomainMismatch");
  });

  it("stays silent (ham-like) when the brand legitimately matches the From domain", () => {
    const result = analyze(
      {
        headers: {
          from: '"PayPal" <service@paypal.com>',
          "authentication-results": `${TRUSTED_ID}; dmarc=pass header.from=paypal.com; dkim=pass header.d=paypal.com`,
        },
        options: { trustedAuthservIds: [TRUSTED_ID] },
      },
      { brandCatalog },
    );
    expect(compositeKeys(result)).not.toContain("composite.brandDivergencePhishing");
  });

  it("reports fromAuthenticated under the default PSL when relaxed parent-domain DKIM aligns the From", () => {
    // Default analyzeMessage path: no getRegistrableDomain supplied, so the
    // organizational projection degrades to exact-only. The brand-divergent From sits
    // on a subdomain (mail.evil.com) authenticated by a relaxed parent-domain DKIM
    // (header.d=evil.com). The composite still fires on the brand/From divergence, but
    // the posture must read authenticated via the built-in PSL fallback rather than
    // overstating the unauthenticated case.
    const result = analyze(
      {
        headers: {
          from: '"PayPal" <security@mail.evil.com>',
          "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=evil.com`,
        },
        options: { trustedAuthservIds: [TRUSTED_ID] },
      },
      { brandCatalog },
    );
    const signal = compositeSignal(result, "composite.brandDivergencePhishing");
    expect(signal?.severity).toBe("high");
    expect(signal?.data?.inferredBrand).toBe("paypal");
    // Exact-only organizational projection would miss the relaxed pass...
    expect(result.metrics.authentication.organizational.anyAuthAligned).toBe(false);
    // ...but the PSL-aware fallback recognizes it.
    expect(signal?.data?.fromAuthenticated).toBe(true);
  });

  it("reports unauthenticated (not attacker-triggerable) when the DKIM pass is for an unrelated domain", () => {
    // A trusted DKIM pass that does not share the From's organizational domain must not
    // credit the From's posture under the PSL fallback — a spoofer cannot launder an
    // authenticated badge for evil.com by presenting a pass for some other domain.
    const result = analyze(
      {
        headers: {
          from: '"PayPal" <security@mail.evil.com>',
          "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=unrelated.example`,
        },
        options: { trustedAuthservIds: [TRUSTED_ID] },
      },
      { brandCatalog },
    );
    const signal = compositeSignal(result, "composite.brandDivergencePhishing");
    expect(signal?.severity).toBe("high");
    expect(signal?.data?.fromAuthenticated).toBe(false);
  });

  it("stays silent when no brand catalog is supplied (no brand surface at all)", () => {
    const result = analyze({
      headers: {
        from: '"PayPal" <security@evil.test>',
        "authentication-results": `${TRUSTED_ID}; dmarc=fail header.from=evil.test`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(compositeKeys(result)).not.toContain("composite.brandDivergencePhishing");
  });
});

describe("composite.ownDomainSpoofCandidate", () => {
  const ownContext = { context: { [OWN_ACCOUNT_DOMAINS_CONTEXT_KEY]: ["mycorp.example"] } };

  it("fires high (spam-like) on an unauthenticated From wearing the recipient's own domain", () => {
    const result = analyze({
      headers: {
        from: "IT Helpdesk <it-helpdesk@mycorp.example>",
        "authentication-results": `${TRUSTED_ID}; dmarc=fail header.from=mycorp.example`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID], ...ownContext },
    });
    const signal = compositeSignal(result, "composite.ownDomainSpoofCandidate");
    expect(signal?.severity).toBe("high");
    expect(signal?.data?.matchedAccountDomain).toBe("mycorp.example");
    expect(Array.isArray(signal?.data?.contributingSignals)).toBe(true);
  });

  it("stays silent (ham-like) when the own-domain From authenticates with aligned DKIM", () => {
    const result = analyze({
      headers: {
        from: "IT Helpdesk <it-helpdesk@mycorp.example>",
        "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=mycorp.example`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID], ...ownContext },
    });
    expect(result.metrics.authentication.anyAuthAligned).toBe(true);
    expect(compositeKeys(result)).not.toContain("composite.ownDomainSpoofCandidate");
  });

  it("stays silent when the caller supplies no account domains", () => {
    const result = analyze({
      headers: {
        from: "IT Helpdesk <it-helpdesk@mycorp.example>",
        "authentication-results": `${TRUSTED_ID}; dmarc=fail header.from=mycorp.example`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(compositeKeys(result)).not.toContain("composite.ownDomainSpoofCandidate");
  });

  it("stays silent under the default PSL when a relaxed parent-domain DKIM aligns the own-domain From", () => {
    // No caller resolver: matchedAccountDomain comes from the built-in PSL (the From's
    // registrable mycorp.com matches the own domain), but authentication.organizational
    // degrades to exact comparison and reads the parent-domain DKIM as unaligned. The
    // relaxed parent signing of the own domain must still suppress the candidate.
    const ownComContext = { context: { [OWN_ACCOUNT_DOMAINS_CONTEXT_KEY]: ["mycorp.com"] } };
    const result = analyze({
      headers: {
        from: "Alice <alice@dept.mycorp.com>",
        "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=mycorp.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID], ...ownComContext },
    });
    expect(result.metrics.senderIdentity.fromDomainParts?.registrableDomain).toBe("mycorp.com");
    expect(result.metrics.authentication.anyAuthAligned).toBe(false);
    expect(result.metrics.authentication.organizational.anyAuthAligned).toBe(false);
    expect(compositeKeys(result)).not.toContain("composite.ownDomainSpoofCandidate");
  });

  it("stays silent when the exact From subdomain is an own domain and the parent signs (relaxed)", () => {
    // The caller supplies the exact From subdomain (and its registrable parent) as own
    // domains, so matchedAccountDomain is the subdomain dept.mycorp.com. The trusted
    // dkim=pass header.d=mycorp.com is a legitimate relaxed parent-domain signing; the
    // suppression must compare against the registrable boundary, not the matched
    // subdomain, otherwise the parent pass is wrongly read as unaligned and fires.
    const ownSubContext = {
      context: { [OWN_ACCOUNT_DOMAINS_CONTEXT_KEY]: ["dept.mycorp.com", "mycorp.com"] },
    };
    const result = analyze({
      headers: {
        from: "Alice <alice@dept.mycorp.com>",
        "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=mycorp.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID], ...ownSubContext },
    });
    expect(result.metrics.senderIdentity.fromDomainParts?.registrableDomain).toBe("mycorp.com");
    expect(result.metrics.authentication.organizational.anyAuthAligned).toBe(false);
    expect(compositeKeys(result)).not.toContain("composite.ownDomainSpoofCandidate");
  });
});

describe("composite.dkimFailWithAlignedPass (mitigation)", () => {
  it("affirms (ham-like) a benign extra DKIM failure alongside an aligned pass", () => {
    const result = analyze({
      headers: {
        from: "News <news@example.com>",
        "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=example.com; dkim=fail header.d=list.example.org`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    const signal = compositeSignal(result, "composite.dkimFailWithAlignedPass");
    expect(signal?.severity).toBe("info");
    expect(signal?.data?.failingDkimDomains).toEqual(["list.example.org"]);
  });

  it("affirms (ham-like) a DMARC-relaxed aligned pass from the parent organizational domain", () => {
    // From is a subdomain; the valid author signature is at the parent org domain.
    // Exact-domain anyAlignedDkimPass is false, but relaxed organizational alignment
    // is true, so the failure should still be recognized as benign.
    const orgResolver: MetricsDependencies = {
      getRegistrableDomain: (domain) =>
        domain === "example.com" || domain.endsWith(".example.com") ? "example.com" : null,
    };
    const result = analyze(
      {
        headers: {
          from: "News <news@mail.example.com>",
          "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=example.com; dkim=fail header.d=list.example.org`,
        },
        options: { trustedAuthservIds: [TRUSTED_ID] },
      },
      orgResolver,
    );
    expect(result.metrics.authentication.anyAlignedDkimPass).toBe(false);
    expect(result.metrics.authentication.organizational.anyDkimAligned).toBe(true);
    const signal = compositeSignal(result, "composite.dkimFailWithAlignedPass");
    expect(signal?.severity).toBe("info");
    expect(signal?.data?.anyOrganizationalDkimAligned).toBe(true);
    expect(signal?.data?.failingDkimDomains).toEqual(["list.example.org"]);
  });

  it("affirms (ham-like) a relaxed parent-domain pass via the built-in PSL with no custom resolver", () => {
    // Default analyzeMessage path: no getRegistrableDomain supplied, so
    // organizational.anyDkimAligned degrades to exact-only and is false, but the
    // built-in PSL still resolves mail.example.com -> example.com, so the relaxed
    // parent-domain DKIM pass must still mitigate the co-occurring failure.
    const result = analyze({
      headers: {
        from: "News <news@mail.example.com>",
        "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=example.com; dkim=fail header.d=list.example.org`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.senderIdentity.fromDomainParts?.registrableDomain).toBe("example.com");
    expect(result.metrics.authentication.anyAlignedDkimPass).toBe(false);
    expect(result.metrics.authentication.organizational.anyDkimAligned).toBe(false);
    const signal = compositeSignal(result, "composite.dkimFailWithAlignedPass");
    expect(signal?.severity).toBe("info");
    expect(signal?.data?.anyOrganizationalDkimAligned).toBe(true);
    expect(signal?.data?.failingDkimDomains).toEqual(["list.example.org"]);
  });

  it("stays silent (spam-like) when the DKIM failure has no aligned pass to mitigate it", () => {
    const result = analyze({
      headers: {
        from: "News <news@example.com>",
        "authentication-results": `${TRUSTED_ID}; dkim=fail header.d=example.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.authentication.anyAlignedDkimPass).toBe(false);
    expect(compositeKeys(result)).not.toContain("composite.dkimFailWithAlignedPass");
  });
});

describe("composite.dkimAlignedLexicalMitigation (mitigation)", () => {
  it("affirms (ham-like) a random-looking local part backed by an aligned DKIM pass", () => {
    const result = analyze({
      headers: {
        from: "Receipts <a8f3qz9k@example.com>",
        "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=example.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    const signal = compositeSignal(result, "composite.dkimAlignedLexicalMitigation");
    expect(signal?.severity).toBe("info");
    expect(signal?.data?.lexicalBasis).toContain("localPart");
  });

  it("affirms (ham-like) a random-looking local part on a subdomain signed by the parent org domain", () => {
    // ESP/automated mail on a subdomain authenticated under DMARC relaxed alignment:
    // exact-domain anyAlignedDkimPass is false, organizational alignment is true.
    const orgResolver: MetricsDependencies = {
      getRegistrableDomain: (domain) =>
        domain === "example.com" || domain.endsWith(".example.com") ? "example.com" : null,
    };
    const result = analyze(
      {
        headers: {
          from: "Receipts <a8f3qz9k@mail.example.com>",
          "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=example.com`,
        },
        options: { trustedAuthservIds: [TRUSTED_ID] },
      },
      orgResolver,
    );
    expect(result.metrics.authentication.anyAlignedDkimPass).toBe(false);
    expect(result.metrics.authentication.organizational.anyDkimAligned).toBe(true);
    const signal = compositeSignal(result, "composite.dkimAlignedLexicalMitigation");
    expect(signal?.severity).toBe("info");
    expect(signal?.data?.anyOrganizationalDkimAligned).toBe(true);
    expect(signal?.data?.lexicalBasis).toContain("localPart");
  });

  it("affirms (ham-like) a random-looking subdomain From via the built-in PSL with no custom resolver", () => {
    // Default analyzeMessage path: no getRegistrableDomain supplied, so
    // organizational.anyDkimAligned degrades to exact-only and is false, but the
    // built-in PSL still resolves mail.example.com -> example.com, so the relaxed
    // parent-domain DKIM pass must still mitigate the random-looking local part.
    const result = analyze({
      headers: {
        from: "Receipts <a8f3qz9k@mail.example.com>",
        "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=example.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.senderIdentity.fromDomainParts?.registrableDomain).toBe("example.com");
    expect(result.metrics.authentication.anyAlignedDkimPass).toBe(false);
    expect(result.metrics.authentication.organizational.anyDkimAligned).toBe(false);
    const signal = compositeSignal(result, "composite.dkimAlignedLexicalMitigation");
    expect(signal?.severity).toBe("info");
    expect(signal?.data?.anyOrganizationalDkimAligned).toBe(true);
    expect(signal?.data?.lexicalBasis).toContain("localPart");
  });

  it("stays silent (not attacker-triggerable) when the DKIM pass is not aligned to the From", () => {
    const result = analyze({
      headers: {
        from: "Receipts <a8f3qz9k@example.com>",
        "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=evil.test`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.authentication.anyAlignedDkimPass).toBe(false);
    expect(compositeKeys(result)).not.toContain("composite.dkimAlignedLexicalMitigation");
  });

  it("stays silent when the From identity does not look machine-generated", () => {
    const result = analyze({
      headers: {
        from: "Support <support@example.com>",
        "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=example.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.authentication.anyAlignedDkimPass).toBe(true);
    expect(compositeKeys(result)).not.toContain("composite.dkimAlignedLexicalMitigation");
  });
});
