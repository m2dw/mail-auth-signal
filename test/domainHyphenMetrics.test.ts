import { describe, expect, it } from "vitest";
import { computeDomainParts } from "../src/index.js";
import type { DomainLabelMetrics } from "../src/index.js";

describe("computeDomainParts — consecutive-hyphen and punycode metrics", () => {
  it("flags zh-entry--kaiyun.com: consecutive hyphen outside punycode", () => {
    const parts = computeDomainParts("zh-entry--kaiyun.com");
    expect(parts.hasConsecutiveHyphen).toBe(true);
    expect(parts.hasPunycodeLabel).toBe(false);
    expect(parts.hasConsecutiveHyphenOutsidePunycode).toBe(true);
    const expected: DomainLabelMetrics[] = [
      { label: "zh-entry--kaiyun", isPunycode: false, hasConsecutiveHyphen: true },
      { label: "com", isPunycode: false, hasConsecutiveHyphen: false },
    ];
    expect(parts.labelMetrics).toEqual(expected);
  });

  it("flags foo--bar.example.com: consecutive hyphen in subdomain", () => {
    const parts = computeDomainParts("foo--bar.example.com");
    expect(parts.hasConsecutiveHyphen).toBe(true);
    expect(parts.hasPunycodeLabel).toBe(false);
    expect(parts.hasConsecutiveHyphenOutsidePunycode).toBe(true);
    const fooBar = parts.labelMetrics.find((lm) => lm.label === "foo--bar");
    expect(fooBar?.hasConsecutiveHyphen).toBe(true);
    expect(fooBar?.isPunycode).toBe(false);
  });

  it("detects xn-- punycode label and does not set hasConsecutiveHyphenOutsidePunycode", () => {
    const parts = computeDomainParts("xn--nxasmq6b.com");
    expect(parts.hasConsecutiveHyphen).toBe(true);
    expect(parts.hasPunycodeLabel).toBe(true);
    expect(parts.hasConsecutiveHyphenOutsidePunycode).toBe(false);
    const expected: DomainLabelMetrics[] = [
      { label: "xn--nxasmq6b", isPunycode: true, hasConsecutiveHyphen: true },
      { label: "com", isPunycode: false, hasConsecutiveHyphen: false },
    ];
    expect(parts.labelMetrics).toEqual(expected);
  });

  it("detects uppercase ACE label XN-- as punycode (case-insensitive)", () => {
    const parts = computeDomainParts("XN--NXASMQ6B.com");
    expect(parts.hasPunycodeLabel).toBe(true);
    expect(parts.hasConsecutiveHyphenOutsidePunycode).toBe(false);
    const ace = parts.labelMetrics.find((lm) => lm.label === "XN--NXASMQ6B");
    expect(ace?.isPunycode).toBe(true);
    expect(ace?.hasConsecutiveHyphen).toBe(true);
  });

  it("handles a domain with both a punycode label and a non-punycode -- label", () => {
    // foo--bar is suspicious; xn--nxasmq6b is a legitimate IDN label
    const parts = computeDomainParts("foo--bar.xn--nxasmq6b.com");
    expect(parts.hasConsecutiveHyphen).toBe(true);
    expect(parts.hasPunycodeLabel).toBe(true);
    expect(parts.hasConsecutiveHyphenOutsidePunycode).toBe(true);
    expect(parts.labelMetrics[0]).toEqual<DomainLabelMetrics>({
      label: "foo--bar",
      isPunycode: false,
      hasConsecutiveHyphen: true,
    });
    expect(parts.labelMetrics[1]).toEqual<DomainLabelMetrics>({
      label: "xn--nxasmq6b",
      isPunycode: true,
      hasConsecutiveHyphen: true,
    });
  });

  it("does not flag paypay-card.co.jp: normal single-hyphen domain", () => {
    const parts = computeDomainParts("paypay-card.co.jp");
    expect(parts.hasConsecutiveHyphen).toBe(false);
    expect(parts.hasPunycodeLabel).toBe(false);
    expect(parts.hasConsecutiveHyphenOutsidePunycode).toBe(false);
    const expected: DomainLabelMetrics[] = [
      { label: "paypay-card", isPunycode: false, hasConsecutiveHyphen: false },
      { label: "co", isPunycode: false, hasConsecutiveHyphen: false },
      { label: "jp", isPunycode: false, hasConsecutiveHyphen: false },
    ];
    expect(parts.labelMetrics).toEqual(expected);
  });

  it("does not flag example.com: plain domain with no hyphens", () => {
    const parts = computeDomainParts("example.com");
    expect(parts.hasConsecutiveHyphen).toBe(false);
    expect(parts.hasPunycodeLabel).toBe(false);
    expect(parts.hasConsecutiveHyphenOutsidePunycode).toBe(false);
    expect(parts.labelMetrics).toEqual<DomainLabelMetrics[]>([
      { label: "example", isPunycode: false, hasConsecutiveHyphen: false },
      { label: "com", isPunycode: false, hasConsecutiveHyphen: false },
    ]);
  });

  it("labelMetrics is parallel to labels in length and order", () => {
    const parts = computeDomainParts("a.b.xn--foo.example.com");
    expect(parts.labelMetrics.length).toBe(parts.labels.length);
    for (let i = 0; i < parts.labels.length; i++) {
      expect(parts.labelMetrics[i]?.label).toBe(parts.labels[i]);
    }
  });
});
