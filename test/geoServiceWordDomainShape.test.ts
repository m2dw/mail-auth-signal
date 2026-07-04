import { describe, expect, it } from "vitest";
import {
  analyzeMessage,
  defaultCompositeRules,
  defaultRules,
  deepServiceWordSubdomainRule,
  geoTokenCompoundDomainRule,
  isCommonWordGeoToken,
  isGeoCompoundToken,
  isGeoTokenCompoundLabel,
  isServiceWordLabel,
  registrableLabelOf,
  hyphenSegments,
  GEO_COMPOUND_TOKENS,
  SERVICE_WORD_SUBDOMAIN_LABELS,
} from "../src/index.js";
import type {
  AnalyzeInput,
  AnalyzeResult,
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

// Resolver: everything under cheapdomain.test / bigbank.test is organizationally
// that base domain (the built-in PSL does not resolve the reserved .test TLD).
const testTldResolver: MetricsDependencies = {
  getRegistrableDomain: (domain) => {
    for (const base of ["cheapdomain.test", "bigbank.test"]) {
      if (domain === base || domain.endsWith(`.${base}`)) return base;
    }
    return null;
  },
};

describe("domain-shape vocabulary helpers", () => {
  it("recognizes expanded service words including the issue #83 additions", () => {
    for (const word of [
      "accounts",
      "events",
      "updates",
      "users",
      "orders",
      "system",
      "form",
      "client",
      "customer",
      "billing",
      "invoice",
      "support",
      "status",
      "notice",
      "portal",
      "payment",
      "ship",
      "auth",
      "promo",
    ]) {
      expect(SERVICE_WORD_SUBDOMAIN_LABELS.has(word)).toBe(true);
      expect(isServiceWordLabel(word.toUpperCase())).toBe(true);
    }
    expect(isServiceWordLabel("switchbot")).toBe(false);
  });

  it("recognizes two-letter geo tokens but not brand-ish words", () => {
    expect(isGeoCompoundToken("zh")).toBe(true);
    expect(isGeoCompoundToken("US")).toBe(true);
    expect(GEO_COMPOUND_TOKENS.has("jp")).toBe(true);
    expect(isGeoCompoundToken("america")).toBe(false);
    expect(isGeoCompoundToken("global")).toBe(false);
  });

  it("splits and reads registrable labels", () => {
    expect(registrableLabelOf("official-zh-ayx.com")).toBe("official-zh-ayx");
    expect(registrableLabelOf("foo.co.uk")).toBe("foo");
    expect(hyphenSegments("official-zh-ayx")).toEqual(["official", "zh", "ayx"]);
  });

  it("flags geo/token compounds and spares legitimate hyphenated brands", () => {
    expect(isGeoTokenCompoundLabel("official-zh-ayx")).toBe(true); // 3 segments + bare region code
    expect(isGeoTokenCompoundLabel("us-a8f3qz9")).toBe(true); // 2 segments + geo + random
    expect(isGeoTokenCompoundLabel("mail-us-a8f3qz9")).toBe(true); // common-word geo + random companion
    expect(isGeoTokenCompoundLabel("coca-cola")).toBe(false); // no geo token
    expect(isGeoTokenCompoundLabel("t-mobile")).toBe(false); // no geo token
    expect(isGeoTokenCompoundLabel("de-mail")).toBe(false); // geo but no 3rd segment / random
    expect(isGeoTokenCompoundLabel("example")).toBe(false); // not hyphenated
  });

  it("spares 3-part phrases whose only geo token is a common English word (issue #83 review)", () => {
    // us / in / at / be / my double as ordinary words: a 3-part label carrying only
    // such a token, with no random/opaque companion, is a legitimate phrase, not a
    // disposable geo compound.
    expect(isCommonWordGeoToken("us")).toBe(true);
    expect(isCommonWordGeoToken("in")).toBe(true);
    expect(isCommonWordGeoToken("zh")).toBe(false);
    expect(isGeoTokenCompoundLabel("contact-us-now")).toBe(false);
    expect(isGeoTokenCompoundLabel("made-in-china")).toBe(false);
    expect(isGeoTokenCompoundLabel("do-it-now")).toBe(false);
    // A common-word geo token still qualifies once a machine-generated companion
    // is present — the shape the rule actually targets.
    expect(isGeoTokenCompoundLabel("contact-us-a8f3qz9")).toBe(true);
  });
});

describe("composite rules — stable identity", () => {
  it("exposes stable, documented keys", () => {
    expect(geoTokenCompoundDomainRule.key).toBe("composite.geoTokenCompoundDomain");
    expect(deepServiceWordSubdomainRule.key).toBe("composite.deepServiceWordSubdomain");
  });
});

describe("composite.geoTokenCompoundDomain", () => {
  it("fires on official-zh-ayx.com EVEN WHEN DKIM is aligned (issue #83)", () => {
    const result = analyze({
      headers: {
        from: "Official <notice@official-zh-ayx.com>",
        "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=official-zh-ayx.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    // The attacker owns the disposable domain and aligned DKIM on it — alignment
    // must NOT be a suppression switch for a domain-shape signal.
    expect(result.metrics.authentication.anyAuthAligned).toBe(true);
    const signal = compositeSignal(result, "composite.geoTokenCompoundDomain");
    expect(signal?.severity).toBe("low");
    expect(signal?.data?.registrableDomain).toBe("official-zh-ayx.com");
    expect(signal?.data?.geoTokens).toContain("zh");
    expect(signal?.data?.dkimAligned).toBe(true);
  });

  it("fires on a two-segment geo + random-looking compound", () => {
    const result = analyze({
      headers: {
        from: "Ship <ship@us-a8f3qz9.com>",
        "authentication-results": `${TRUSTED_ID}; spf=pass smtp.mailfrom=us-a8f3qz9.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(compositeKeys(result)).toContain("composite.geoTokenCompoundDomain");
  });

  it("does NOT fire on an ordinary DKIM-aligned domain", () => {
    const result = analyze({
      headers: {
        from: "News <newsletter@news.example.com>",
        "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=example.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(compositeKeys(result)).not.toContain("composite.geoTokenCompoundDomain");
  });

  it("reports dkimAligned:true for a relaxed-aligned subdomain on the default PSL path (issue #83 review)", () => {
    // No custom resolver: organizational.anyDkimAligned degrades to exact-only, but
    // the built-in PSL still resolves the From's registrable domain, so a relaxed
    // (organizational) DKIM signature must be reflected as aligned context.
    const result = analyze({
      headers: {
        from: "Official <news@mail.official-zh-ayx.com>",
        "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=official-zh-ayx.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    // Exact-domain alignment is false here (signing domain != From subdomain)...
    expect(result.metrics.authentication.organizational.anyDkimAligned).toBe(false);
    const signal = compositeSignal(result, "composite.geoTokenCompoundDomain");
    expect(signal?.data?.registrableDomain).toBe("official-zh-ayx.com");
    // ...yet the emitted context reflects the relaxed organizational alignment.
    expect(signal?.data?.dkimAligned).toBe(true);
  });

  it("does NOT fire on ordinary common-word geo phrases even when DKIM aligned (issue #83 review)", () => {
    for (const domain of ["contact-us-now.com", "made-in-china.com"]) {
      const result = analyze({
        headers: {
          from: `Newsletter <newsletter@${domain}>`,
          "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=${domain}`,
        },
        options: { trustedAuthservIds: [TRUSTED_ID] },
      });
      expect(result.metrics.authentication.anyAuthAligned).toBe(true);
      expect(compositeKeys(result), `expected ${domain} to stay silent`).not.toContain(
        "composite.geoTokenCompoundDomain",
      );
    }
  });

  it("does NOT fire on a legitimate two-part hyphenated brand", () => {
    const result = analyze({
      headers: {
        from: "Cola <hello@coca-cola.com>",
        "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=coca-cola.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(compositeKeys(result)).not.toContain("composite.geoTokenCompoundDomain");
  });

  it("stays silent on unverifiable mail (no trusted auth ran)", () => {
    const result = analyze({
      headers: {
        from: "Official <notice@official-zh-ayx.com>",
        "authentication-results": `some.other.host; dkim=pass header.d=official-zh-ayx.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.authentication.trustedHeaderCount).toBe(0);
    expect(compositeKeys(result)).not.toContain("composite.geoTokenCompoundDomain");
  });
});

describe("composite.deepServiceWordSubdomain", () => {
  it("detects each expanded service word next to a random label, DKIM aligned", () => {
    for (const word of [
      "accounts",
      "events",
      "updates",
      "users",
      "orders",
      "system",
      "form",
    ]) {
      const fromDomain = `${word}.k2m9x7.cheapdomain.test`;
      const result = analyze(
        {
          headers: {
            from: `Service <hi@${fromDomain}>`,
            "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=${fromDomain}`,
          },
          options: { trustedAuthservIds: [TRUSTED_ID] },
        },
        testTldResolver,
      );
      expect(result.metrics.authentication.anyAuthAligned).toBe(true);
      const signal = compositeSignal(result, "composite.deepServiceWordSubdomain");
      expect(signal, `expected ${word} to fire`).toBeDefined();
      expect(signal?.severity).toBe("low");
      expect(signal?.data?.serviceWordLabels).toContain(word);
      expect(signal?.data?.randomLabels).toContain("k2m9x7");
      expect(signal?.data?.dkimAligned).toBe(true);
    }
  });

  it("reports dkimAligned:true for a relaxed-aligned deep From on the default PSL path (issue #83 review)", () => {
    // Default analyzeMessage path, no custom resolver: the built-in PSL resolves the
    // .com registrable domain and depth, and a relaxed DKIM signature on the
    // organizational domain must surface as aligned context, not exact-only false.
    const result = analyze({
      headers: {
        from: "Accounts <hi@accounts.k2m9x7.cheapdomain.com>",
        "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=cheapdomain.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.authentication.organizational.anyDkimAligned).toBe(false);
    const signal = compositeSignal(result, "composite.deepServiceWordSubdomain");
    expect(signal, "expected deep service-word signal to fire").toBeDefined();
    expect(signal?.data?.serviceWordLabels).toContain("accounts");
    expect(signal?.data?.randomLabels).toContain("k2m9x7");
    expect(signal?.data?.dkimAligned).toBe(true);
  });

  it("does NOT fire on a legitimate deep service subdomain without a random companion", () => {
    const result = analyze(
      {
        headers: {
          from: "Accounts <no-reply@accounts.corp.bigbank.test>",
          "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=accounts.corp.bigbank.test`,
        },
        options: { trustedAuthservIds: [TRUSTED_ID] },
      },
      testTldResolver,
    );
    expect(result.metrics.senderIdentity.fromDomainParts?.subdomainDepth).toBe(2);
    expect(result.metrics.authentication.anyAuthAligned).toBe(true);
    expect(compositeKeys(result)).not.toContain("composite.deepServiceWordSubdomain");
  });

  it("does NOT fire at subdomain depth 1", () => {
    const result = analyze(
      {
        headers: {
          from: "Accounts <no-reply@accounts.cheapdomain.test>",
          "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=accounts.cheapdomain.test`,
        },
        options: { trustedAuthservIds: [TRUSTED_ID] },
      },
      testTldResolver,
    );
    expect(result.metrics.senderIdentity.fromDomainParts?.subdomainDepth).toBe(1);
    expect(compositeKeys(result)).not.toContain("composite.deepServiceWordSubdomain");
  });

  it("stays silent without a resolver (subdomain depth unknown)", () => {
    const result = analyze({
      headers: {
        from: "Accounts <hi@accounts.k2m9x7.cheapdomain.test>",
        "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=accounts.k2m9x7.cheapdomain.test`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    }, { getRegistrableDomain: () => null });
    expect(compositeKeys(result)).not.toContain("composite.deepServiceWordSubdomain");
  });

  it("stays silent on unverifiable mail (no trusted auth ran)", () => {
    const result = analyze(
      {
        headers: {
          from: "Accounts <hi@accounts.k2m9x7.cheapdomain.test>",
          "authentication-results": `some.other.host; dkim=pass header.d=accounts.k2m9x7.cheapdomain.test`,
        },
        options: { trustedAuthservIds: [TRUSTED_ID] },
      },
      testTldResolver,
    );
    expect(result.metrics.authentication.trustedHeaderCount).toBe(0);
    expect(compositeKeys(result)).not.toContain("composite.deepServiceWordSubdomain");
  });
});
