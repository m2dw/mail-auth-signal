import { describe, expect, it } from "vitest";
import { analyzeMessage, computeRegistrableLabelNaturalness } from "../src/index.js";
import type { LabelNaturalnessModel, MetricsDependencies } from "../src/index.js";

// A stand-in model: deterministic, data-free, and deliberately *not* a real
// corpus (the core bundles none). It lets tests assert exactly what label the
// core hands to the caller's model and how the returned value is recorded.
const seen: string[] = [];
const recordingModel: LabelNaturalnessModel = (label) => {
  seen.push(label);
  return label.length + 0.123456;
};

describe("computeRegistrableLabelNaturalness — label identification", () => {
  it("measures the registrable label beneath a random subdomain (dessert.axgporj.com -> axgporj)", () => {
    const r = computeRegistrableLabelNaturalness("dessert.axgporj.com", {
      scoreLabelNaturalness: () => 5.582,
    });
    expect(r).toEqual({
      domain: "dessert.axgporj.com",
      registrableDomain: "axgporj.com",
      underPrivateSuffix: false,
      measuredDomain: "axgporj.com",
      label: "axgporj",
      labelLength: 7,
      score: 5.582,
      status: "measured",
    });
  });

  it("handles compound ICANN suffixes (dcm-hldgs.co.jp -> dcm-hldgs)", () => {
    for (const domain of ["dcm-hldgs.co.jp", "mail.dcm-hldgs.co.jp"]) {
      seen.length = 0;
      const r = computeRegistrableLabelNaturalness(domain, {
        scoreLabelNaturalness: recordingModel,
      });
      expect(r.registrableDomain).toBe("dcm-hldgs.co.jp");
      expect(r.label).toBe("dcm-hldgs");
      expect(seen).toEqual(["dcm-hldgs"]);
      expect(r.status).toBe("measured");
    }
  });

  it("measures ordinary domains", () => {
    const r = computeRegistrableLabelNaturalness("news.example.com", {
      scoreLabelNaturalness: recordingModel,
    });
    expect(r.label).toBe("example");
    expect(r.score).toBe(7.1235);
  });

  it("measures the tenant label beneath a PSL private suffix", () => {
    const gh = computeRegistrableLabelNaturalness("axgporj.github.io", {
      scoreLabelNaturalness: recordingModel,
    });
    expect(gh.registrableDomain).toBe("github.io");
    expect(gh.underPrivateSuffix).toBe(true);
    expect(gh.measuredDomain).toBe("axgporj.github.io");
    expect(gh.label).toBe("axgporj");

    const s3 = computeRegistrableLabelNaturalness("x.acme.s3.amazonaws.com");
    expect(s3.underPrivateSuffix).toBe(true);
    expect(s3.label).toBe("acme");

    // The private suffix itself has no tenant, so the provider label is measured.
    const bare = computeRegistrableLabelNaturalness("github.io");
    expect(bare.underPrivateSuffix).toBe(false);
    expect(bare.label).toBe("github");
  });

  it("normalizes case, surrounding whitespace, and a trailing dot", () => {
    const r = computeRegistrableLabelNaturalness("  Dessert.AXGPORJ.com. ", {
      scoreLabelNaturalness: recordingModel,
    });
    expect(r.domain).toBe("dessert.axgporj.com");
    expect(r.label).toBe("axgporj");
  });

  it("reports the label and a no-model status when no model is supplied", () => {
    const r = computeRegistrableLabelNaturalness("dessert.axgporj.com");
    expect(r.label).toBe("axgporj");
    expect(r.score).toBeNull();
    expect(r.status).toBe("no-model");
  });

  it("measures short labels and reports their length for caller filtering", () => {
    const r = computeRegistrableLabelNaturalness("x.co", { scoreLabelNaturalness: () => 1 });
    expect(r.label).toBe("x");
    expect(r.labelLength).toBe(1);
    expect(r.status).toBe("measured");
  });

  it("does not score punycode or non-ASCII labels", () => {
    const calls: string[] = [];
    const model: LabelNaturalnessModel = (label) => {
      calls.push(label);
      return 1;
    };
    const puny = computeRegistrableLabelNaturalness("xn--bcher-kva.example", {
      scoreLabelNaturalness: model,
    });
    expect(puny.label).toBe("xn--bcher-kva");
    expect(puny.status).toBe("unsupported-label");
    expect(puny.score).toBeNull();
    const unicode = computeRegistrableLabelNaturalness("bücher.example", {
      getRegistrableDomain: (d) => d,
      scoreLabelNaturalness: model,
    });
    expect(unicode.label).toBe("bücher");
    expect(unicode.status).toBe("unsupported-label");
    expect(calls).toEqual([]);
  });
});

describe("computeRegistrableLabelNaturalness — unavailable results", () => {
  it.each([null, undefined, "", "   ", "."])("returns no-domain for %j", (domain) => {
    const r = computeRegistrableLabelNaturalness(domain, { scoreLabelNaturalness: recordingModel });
    expect(r).toEqual({
      domain: null,
      registrableDomain: null,
      underPrivateSuffix: false,
      measuredDomain: null,
      label: null,
      labelLength: 0,
      score: null,
      status: "no-domain",
    });
  });

  it.each(["com", "co.jp", "192.168.0.1", "localhost"])(
    "returns no-registrable-domain for unparseable %s",
    (domain) => {
      const r = computeRegistrableLabelNaturalness(domain, {
        scoreLabelNaturalness: recordingModel,
      });
      expect(r.status).toBe("no-registrable-domain");
      expect(r.label).toBeNull();
      expect(r.score).toBeNull();
    },
  );

  it("honours the PSL opt-out resolver, even beneath a private suffix", () => {
    const r = computeRegistrableLabelNaturalness("axgporj.github.io", {
      getRegistrableDomain: () => null,
      scoreLabelNaturalness: recordingModel,
    });
    expect(r.status).toBe("no-registrable-domain");
  });

  it("ignores the built-in private suffix when a caller resolver disagrees with it", () => {
    const r = computeRegistrableLabelNaturalness("axgporj.github.io", {
      getRegistrableDomain: () => "example.com",
      scoreLabelNaturalness: recordingModel,
    });
    expect(r.underPrivateSuffix).toBe(false);
    expect(r.measuredDomain).toBe("example.com");
    expect(r.label).toBe("example");
  });

  it.each([
    ["NaN", () => Number.NaN],
    ["Infinity", () => Number.POSITIVE_INFINITY],
    ["a string", () => "5.5" as unknown as number],
    ["undefined", () => undefined as unknown as number],
  ])("returns invalid-model-output when the model returns %s", (_name, model) => {
    const r = computeRegistrableLabelNaturalness("dessert.axgporj.com", {
      scoreLabelNaturalness: model,
    });
    expect(r.status).toBe("invalid-model-output");
    expect(r.label).toBe("axgporj");
    expect(r.score).toBeNull();
  });

  it("returns model-error when the model throws", () => {
    const r = computeRegistrableLabelNaturalness("dessert.axgporj.com", {
      scoreLabelNaturalness: () => {
        throw new Error("boom");
      },
    });
    expect(r.status).toBe("model-error");
    expect(r.score).toBeNull();
  });

  it("distinguishes a null model from a non-function model", () => {
    const asModel = (v: unknown) => v as LabelNaturalnessModel;
    expect(
      computeRegistrableLabelNaturalness("a.example.com", { scoreLabelNaturalness: asModel(null) })
        .status,
    ).toBe("no-model");
    expect(
      computeRegistrableLabelNaturalness("a.example.com", { scoreLabelNaturalness: asModel(5.5) })
        .status,
    ).toBe("invalid-model");
  });

  it("rounds to 4 decimals and folds -0 to 0", () => {
    expect(
      computeRegistrableLabelNaturalness("a.example.com", {
        scoreLabelNaturalness: () => 5.58249999,
      }).score,
    ).toBe(5.5825);
    const negZero = computeRegistrableLabelNaturalness("a.example.com", {
      scoreLabelNaturalness: () => -0.00001,
    });
    expect(Object.is(negZero.score, 0)).toBe(true);
  });
});

describe("senderIdentity.fromRegistrableLabelNaturalness (opt-in dependency)", () => {
  const input = { headers: { from: "Dessert <news@dessert.axgporj.com>" } };

  it("is omitted when no model is supplied", () => {
    const { metrics } = analyzeMessage(input);
    expect(metrics.senderIdentity).not.toHaveProperty("fromRegistrableLabelNaturalness");
  });

  it("is present, serializable, and emits no signal when a model is supplied", () => {
    const deps: MetricsDependencies = { scoreLabelNaturalness: () => 5.582 };
    const baseline = analyzeMessage(input);
    const { metrics, signals } = analyzeMessage(input, undefined, deps);
    const n = metrics.senderIdentity.fromRegistrableLabelNaturalness;
    expect(n?.label).toBe("axgporj");
    expect(n?.score).toBe(5.582);
    expect(JSON.parse(JSON.stringify(n))).toEqual(n);
    // Observation only: no threshold, verdict, or signal is attached to it.
    expect(signals).toEqual(baseline.signals);
  });

  it("uses a caller-supplied resolver", () => {
    const { metrics } = analyzeMessage(input, undefined, {
      getRegistrableDomain: () => "dessert.axgporj.com",
      scoreLabelNaturalness: () => 1,
    });
    expect(metrics.senderIdentity.fromRegistrableLabelNaturalness?.label).toBe("dessert");
  });

  it("reports no-domain when From has no parseable domain", () => {
    const { metrics } = analyzeMessage({ headers: { from: "no address" } }, undefined, {
      scoreLabelNaturalness: () => 1,
    });
    expect(metrics.senderIdentity.fromRegistrableLabelNaturalness?.status).toBe("no-domain");
  });
});
