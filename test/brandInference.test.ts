import { describe, expect, it } from "vitest";
import {
  analyzeMessage,
  BRAND_MATCH_MIN_FUZZY_LENGTH,
  computeDisplayNameBrandInference,
  computeJaccard,
  foldLatinDiacritics,
  normalizeBrandToken,
} from "../src/index.js";
import type { AnalyzeInput, BrandCatalogEntry, MetricsDependencies } from "../src/index.js";

/**
 * A tiny hand-authored catalog. The library bundles no brand list, so every test
 * supplies its own — exactly the caller-owned-data boundary issue #64 keeps.
 */
const catalog: BrandCatalogEntry[] = [
  { brand: "paypal", domains: ["paypal.com"] },
  { brand: "hermes", domains: ["hermes.com"] },
  { brand: "daiichilife", domains: ["dai-ichi-life.co.jp"] },
];

/** A stand-in resolver so registrable-domain comparison is deterministic. */
const PSL: Record<string, string> = {
  "evil.test": "evil.test",
  "paypal.com": "paypal.com",
  "mail.paypal.com": "paypal.com",
  "hermes.com": "hermes.com",
};
const resolve = (domain: string): string | null => PSL[domain] ?? null;

describe("computeJaccard — bigram set similarity", () => {
  it("is 1 for identical strings (including empty) and 0 for disjoint", () => {
    expect(computeJaccard("paypal", "paypal")).toBe(1);
    expect(computeJaccard("", "")).toBe(1);
    expect(computeJaccard("abc", "xyz")).toBe(0);
    expect(computeJaccard("abc", "")).toBe(0);
  });

  it("rewards shared substrings and is order-sensitive", () => {
    // "abc"/"cba" share no bigram despite identical character sets.
    expect(computeJaccard("abc", "cba")).toBe(0);
    expect(computeJaccard("paypai", "paypal")).toBeGreaterThanOrEqual(0.5);
  });
});

describe("foldLatinDiacritics / normalizeBrandToken", () => {
  it("folds Latin diacritics to base letters (the #59 HERMÈS bug)", () => {
    expect(foldLatinDiacritics("HERMÈS")).toBe("HERMES");
    expect(foldLatinDiacritics("café")).toBe("cafe");
  });

  it("normalizes to a lower-case alphanumeric token, collapsing spacing", () => {
    expect(normalizeBrandToken("HERMÈS")).toBe("hermes");
    expect(normalizeBrandToken("P a y P a l")).toBe("paypal");
    expect(normalizeBrandToken("Dai-ichi Life")).toBe("daiichilife");
  });
});

describe("computeDisplayNameBrandInference — HERMES / HERMÈS parity", () => {
  it("matches the same brand with and without diacritics", () => {
    const plain = computeDisplayNameBrandInference("HERMES", "evil.test", catalog, resolve);
    const accented = computeDisplayNameBrandInference("HERMÈS", "evil.test", catalog, resolve);

    expect(plain.applicable).toBe(true);
    expect(plain.brandToken).toBe("hermes");
    expect(plain.diacriticsFolded).toBe(false);
    expect(plain.match?.brand).toBe("hermes");
    expect(plain.match?.exact).toBe(true);
    expect(plain.brandDomainMatchesFromDomain).toBe(false);

    // Folding HERMÈS must reach the identical brand decision, only flagging that
    // a diacritic was folded.
    expect(accented.diacriticsFolded).toBe(true);
    expect(accented.brandToken).toBe("hermes");
    expect(accented.match?.brand).toBe("hermes");
    expect(accented.inferredBrandDomains).toEqual(["hermes.com"]);
    expect(accented.brandDomainMatchesFromDomain).toBe(false);
  });
});

describe("computeDisplayNameBrandInference — brand/domain mismatch vs match", () => {
  it("flags an obvious brand mismatch (display PayPal, From evil.test)", () => {
    const result = computeDisplayNameBrandInference("PayPal", "evil.test", catalog, resolve);
    expect(result.applicable).toBe(true);
    expect(result.match?.brand).toBe("paypal");
    expect(result.match?.exact).toBe(true);
    expect(result.brandDomainMatchesFromDomain).toBe(false);
  });

  it("does not flag a matching brand domain (display PayPal, From paypal.com)", () => {
    const result = computeDisplayNameBrandInference("PayPal", "paypal.com", catalog, resolve);
    expect(result.brandDomainMatchesFromDomain).toBe(true);
  });

  it("treats a brand subdomain as the brand via the registrable domain", () => {
    const result = computeDisplayNameBrandInference("PayPal", "mail.paypal.com", catalog, resolve);
    expect(result.fromRegistrableDomain).toBe("paypal.com");
    expect(result.brandDomainMatchesFromDomain).toBe(true);
  });

  it("leaves a subdomain unknown (not a mismatch) when PSL resolution is unavailable", () => {
    // Caller opts out of registrable-domain resolution. mail.paypal.com is a
    // legitimate PayPal subdomain, but without PSL we cannot prove it, so the
    // result must be `null` (unknown) rather than a false mismatch.
    const optOut = computeDisplayNameBrandInference(
      "PayPal",
      "mail.paypal.com",
      catalog,
      () => null,
    );
    expect(optOut.applicable).toBe(true);
    expect(optOut.match?.brand).toBe("paypal");
    expect(optOut.fromRegistrableDomain).toBeNull();
    expect(optOut.brandDomainMatchesFromDomain).toBeNull();

    // An exact From of the catalog domain still matches even without a resolver.
    const exact = computeDisplayNameBrandInference("PayPal", "paypal.com", catalog, () => null);
    expect(exact.brandDomainMatchesFromDomain).toBe(true);

    // A genuinely unrelated domain is still only "unknown" without resolution —
    // we never assert a mismatch we cannot substantiate.
    const unrelated = computeDisplayNameBrandInference("PayPal", "evil.test", catalog, () => null);
    expect(unrelated.brandDomainMatchesFromDomain).toBeNull();
  });

  it("sees through letter-spacing camouflage", () => {
    const result = computeDisplayNameBrandInference("P a y P a l", "evil.test", catalog, resolve);
    expect(result.brandToken).toBe("paypal");
    expect(result.match?.brand).toBe("paypal");
    expect(result.brandDomainMatchesFromDomain).toBe(false);
  });

  it("matches a near-miss lookalike via Jaro-Winkler + Jaccard, not just exact", () => {
    // "PaypaI" uses a capital I (Latin) where the brand has an l; it folds to a
    // pure-Latin token that is a confident but non-exact match.
    const result = computeDisplayNameBrandInference("PaypaI", "evil.test", catalog, resolve);
    expect(result.match?.brand).toBe("paypal");
    expect(result.match?.exact).toBe(false);
    expect(result.match?.jaroWinkler).toBeGreaterThanOrEqual(0.9);
    expect(result.match?.jaccard).toBeGreaterThanOrEqual(0.5);
    expect(result.brandDomainMatchesFromDomain).toBe(false);
  });

  it("reports no match (not a mismatch) for an unrelated display name", () => {
    const result = computeDisplayNameBrandInference("Quarterly Newsletter", "evil.test", catalog, resolve);
    expect(result.applicable).toBe(true);
    expect(result.match).toBeNull();
    expect(result.inferredBrandDomains).toEqual([]);
    expect(result.brandDomainMatchesFromDomain).toBeNull();
  });
});

describe("computeDisplayNameBrandInference — guardrails / not-applicable reasons", () => {
  it("declines a non-Latin display name", () => {
    const result = computeDisplayNameBrandInference("山本太郎", "evil.test", catalog, resolve);
    expect(result.applicable).toBe(false);
    expect(result.notApplicableReason).toBe("non-latin-script");
    expect(result.match).toBeNull();
  });

  it("declines a mixed-script homoglyph name without fabricating a brand match", () => {
    // "pаypal" contains a Cyrillic 'а' (U+0430). Folding it to a Latin token would
    // manufacture a paypal match the raw text never had, so it must be refused.
    const homoglyph = "pаypal";
    const result = computeDisplayNameBrandInference(homoglyph, "evil.test", catalog, resolve);
    expect(result.applicable).toBe(false);
    expect(result.notApplicableReason).toBe("mixed-script");
    expect(result.match).toBeNull();
    expect(result.brandDomainMatchesFromDomain).toBeNull();
  });

  it("declines when the From domain is missing", () => {
    const result = computeDisplayNameBrandInference("PayPal", null, catalog, resolve);
    expect(result.applicable).toBe(false);
    expect(result.notApplicableReason).toBe("missing-from-domain");
    // The normalized token is still surfaced for the caller's inspection.
    expect(result.brandToken).toBe("paypal");
  });

  it("declines an insufficient (too-short / non-brand-like) token", () => {
    const result = computeDisplayNameBrandInference("Hi", "evil.test", catalog, resolve);
    expect(result.applicable).toBe(false);
    expect(result.notApplicableReason).toBe("insufficient-signal");
  });

  it("declines when no display name is present", () => {
    const result = computeDisplayNameBrandInference(null, "evil.test", catalog, resolve);
    expect(result.applicable).toBe(false);
    expect(result.notApplicableReason).toBe("no-display-name");
    expect(result.brandToken).toBeNull();
  });

  it("reports an empty-catalog reason when opted in with no entries", () => {
    const result = computeDisplayNameBrandInference("PayPal", "evil.test", [], resolve);
    expect(result.applicable).toBe(false);
    expect(result.notApplicableReason).toBe("empty-catalog");
  });
});

describe("computeDisplayNameBrandInference — AWS organizational family (issue #84)", () => {
  // AWS legitimately sends from an organizational *family* of domains — amazon.com,
  // aws.amazon.com, email.aws.amazon.com — that all resolve to the amazon.com
  // registrable domain. A catalog listing a single AWS domain must not flag the
  // rest of the family as brand divergence.
  const awsCatalog: BrandCatalogEntry[] = [
    { brand: "aws", domains: ["aws.amazon.com"] },
    { brand: "paypal", domains: ["paypal.com"] },
  ];
  const awsResolve = (domain: string): string | null => {
    if (domain === "amazon.com" || domain.endsWith(".amazon.com")) return "amazon.com";
    if (domain === "amazonaws.com" || domain.endsWith(".amazonaws.com")) return "amazonaws.com";
    if (domain === "paypal.com" || domain.endsWith(".paypal.com")) return "paypal.com";
    if (domain === "paypal-support.com") return "paypal-support.com";
    if (domain === "aws-security.com") return "aws-security.com";
    if (domain === "evil.test" || domain.endsWith(".evil.test")) return "evil.test";
    return null;
  };

  it("does not flag legitimate AWS mail from the parent org domain (the ham FP)", () => {
    // Catalog lists aws.amazon.com; the real message is from amazon.com. Both resolve
    // to the amazon.com organization, so this must read as belonging, not divergence.
    const result = computeDisplayNameBrandInference("AWS", "amazon.com", awsCatalog, awsResolve);
    expect(result.applicable).toBe(true);
    expect(result.match?.brand).toBe("aws");
    expect(result.match?.exact).toBe(true);
    expect(result.brandDomainMatchesFromDomain).toBe(true);
  });

  it("does not flag a deeper legitimate AWS sending subdomain", () => {
    const result = computeDisplayNameBrandInference(
      "AWS",
      "email.aws.amazon.com",
      awsCatalog,
      awsResolve,
    );
    expect(result.fromRegistrableDomain).toBe("amazon.com");
    expect(result.brandDomainMatchesFromDomain).toBe(true);
  });

  it("still flags a clear AWS impersonation from an unrelated domain", () => {
    const result = computeDisplayNameBrandInference("AWS", "evil.test", awsCatalog, awsResolve);
    expect(result.match?.brand).toBe("aws");
    expect(result.brandDomainMatchesFromDomain).toBe(false);
  });

  it("still flags an AWS look-alike (hyphenated) domain the org does not own", () => {
    // aws-security.com is a different registrable domain — a classic look-alike an
    // attacker registers — so it must not be absorbed into the amazon.com family.
    const result = computeDisplayNameBrandInference(
      "AWS",
      "aws-security.com",
      awsCatalog,
      awsResolve,
    );
    expect(result.brandDomainMatchesFromDomain).toBe(false);
  });

  it("still flags a spoof when the catalog domain is a brand host under a shared provider suffix", () => {
    // A catalog that lists a brand-specific host under a shared/private hosting suffix
    // (brand.s3.amazonaws.com, whose ICANN registrable domain is the shared
    // amazonaws.com). An unrelated tenant on the same provider must NOT be absorbed
    // into the brand by the organizational-family collapse — otherwise a spoofer on
    // attacker.s3.amazonaws.com (same amazonaws.com registrable) would suppress the
    // divergence signal. Issue #84 follow-up.
    const sharedHostCatalog: BrandCatalogEntry[] = [
      { brand: "aws", domains: ["brand.s3.amazonaws.com"] },
    ];
    const result = computeDisplayNameBrandInference(
      "AWS",
      "attacker.s3.amazonaws.com",
      sharedHostCatalog,
      awsResolve,
    );
    expect(result.match?.brand).toBe("aws");
    expect(result.brandDomainMatchesFromDomain).toBe(false);
  });

  it("still recognizes legitimate mail from the exact brand host under a shared suffix", () => {
    // The carve-out only skips the registrable collapse; an exact host match (or a
    // subdomain of it) is still a genuine belonging and must not be flagged.
    const sharedHostCatalog: BrandCatalogEntry[] = [
      { brand: "aws", domains: ["brand.s3.amazonaws.com"] },
    ];
    const exact = computeDisplayNameBrandInference(
      "AWS",
      "brand.s3.amazonaws.com",
      sharedHostCatalog,
      awsResolve,
    );
    expect(exact.brandDomainMatchesFromDomain).toBe(true);

    const subdomain = computeDisplayNameBrandInference(
      "AWS",
      "mail.brand.s3.amazonaws.com",
      sharedHostCatalog,
      awsResolve,
    );
    expect(subdomain.brandDomainMatchesFromDomain).toBe(true);
  });

  it("exposes the short-brand fuzzy-match floor as a public constant", () => {
    expect(BRAND_MATCH_MIN_FUZZY_LENGTH).toBe(4);
  });

  it("does not fuzzy-match a short brand against a coincidental everyday word", () => {
    // "Jaws" / "Laws" score above the Jaro-Winkler + Jaccard thresholds against the
    // 3-letter brand "aws", but must not manufacture a brand match on a short token —
    // otherwise a benign sender an attacker names "Jaws" would be flagged.
    for (const name of ["Jaws", "Laws", "Paws"]) {
      const result = computeDisplayNameBrandInference(name, "evil.test", awsCatalog, awsResolve);
      expect(result.match, `${name} must not match a short brand fuzzily`).toBeNull();
      expect(result.brandDomainMatchesFromDomain).toBeNull();
    }
  });

  it("keeps flagging an ordinary non-AWS brand divergence (regression guard)", () => {
    // A hyphenated PayPal look-alike is still a mismatch — the family fix must not
    // weaken obvious divergence detection.
    const result = computeDisplayNameBrandInference(
      "PayPal",
      "paypal-support.com",
      awsCatalog,
      awsResolve,
    );
    expect(result.match?.brand).toBe("paypal");
    expect(result.brandDomainMatchesFromDomain).toBe(false);
  });
});

describe("analyzeMessage integration — opt-in brand catalog", () => {
  const input: AnalyzeInput = {
    headers: [
      { name: "From", value: '"PayPal" <security@evil.test>' },
      { name: "Message-ID", value: "<abc@evil.test>" },
    ],
  };

  it("emits brandInference metric and a mismatch signal when a catalog is supplied", () => {
    const deps: MetricsDependencies = { getRegistrableDomain: resolve, brandCatalog: catalog };
    const { metrics, signals } = analyzeMessage(input, undefined, deps);

    const brandInference = metrics.senderIdentity.brandInference;
    expect(brandInference?.applicable).toBe(true);
    expect(brandInference?.match?.brand).toBe("paypal");
    expect(brandInference?.brandDomainMatchesFromDomain).toBe(false);

    const signal = signals.find((s) => s.key === "displayName.brandDomainMismatch");
    expect(signal).toBeDefined();
    expect(signal?.severity).toBe("medium");
    expect(signal?.data?.inferredBrandDomains).toEqual(["paypal.com"]);
  });

  it("omits brandInference entirely and stays silent without a catalog", () => {
    const { metrics, signals } = analyzeMessage(input, undefined, {
      getRegistrableDomain: resolve,
    });
    expect(metrics.senderIdentity.brandInference).toBeUndefined();
    expect("brandInference" in metrics.senderIdentity).toBe(false);
    expect(signals.some((s) => s.key === "displayName.brandDomainMismatch")).toBe(false);
  });

  it("stays silent for a brand subdomain when registrable-domain resolution is disabled", () => {
    // service@mail.paypal.com is a legitimate PayPal subdomain. With the resolver
    // opted out, brand-domain match is unknown, so the medium mismatch signal must
    // not fire.
    const legitSubdomain: AnalyzeInput = {
      headers: [{ name: "From", value: '"PayPal" <service@mail.paypal.com>' }],
    };
    const deps: MetricsDependencies = { getRegistrableDomain: () => null, brandCatalog: catalog };
    const { metrics, signals } = analyzeMessage(legitSubdomain, undefined, deps);
    expect(metrics.senderIdentity.brandInference?.brandDomainMatchesFromDomain).toBeNull();
    expect(signals.some((s) => s.key === "displayName.brandDomainMismatch")).toBe(false);
  });

  it("does not flag a brand sending from its own domain", () => {
    const legit: AnalyzeInput = {
      headers: [{ name: "From", value: '"PayPal" <service@paypal.com>' }],
    };
    const deps: MetricsDependencies = { getRegistrableDomain: resolve, brandCatalog: catalog };
    const { metrics, signals } = analyzeMessage(legit, undefined, deps);
    expect(metrics.senderIdentity.brandInference?.brandDomainMatchesFromDomain).toBe(true);
    expect(signals.some((s) => s.key === "displayName.brandDomainMismatch")).toBe(false);
  });
});
