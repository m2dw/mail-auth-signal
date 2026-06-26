import { describe, expect, it } from "vitest";
import { analyzeMessage, defaultGetRegistrableDomain, extractMetrics } from "../src/index.js";

describe("built-in PSL resolver — default behavior (no caller setup required)", () => {
  it("populates registrableDomain and subdomainDepth for a .co.jp compound suffix", () => {
    const metrics = extractMetrics({
      headers: { from: "Test <user@mail.example.co.jp>" },
    });
    expect(metrics.senderIdentity.fromDomainParts?.registrableDomain).toBe("example.co.jp");
    expect(metrics.senderIdentity.fromDomainParts?.subdomainDepth).toBe(1);
  });

  it("populates registrableDomain and subdomainDepth for a standard subdomain", () => {
    const metrics = extractMetrics({
      headers: { from: "Test <user@mail.example.com>" },
    });
    expect(metrics.senderIdentity.fromDomainParts?.registrableDomain).toBe("example.com");
    expect(metrics.senderIdentity.fromDomainParts?.subdomainDepth).toBe(1);
  });

  it("sets subdomainDepth to 0 for a bare registrable domain", () => {
    const metrics = extractMetrics({
      headers: { from: "Test <user@example.com>" },
    });
    expect(metrics.senderIdentity.fromDomainParts?.registrableDomain).toBe("example.com");
    expect(metrics.senderIdentity.fromDomainParts?.subdomainDepth).toBe(0);
  });

  it("populates messageIdRegistrableDomainMatchesFromDomain true when both resolve to the same org", () => {
    const metrics = extractMetrics({
      headers: {
        from: "Test <user@mail.example.com>",
        "message-id": "<abc@smtp.example.com>",
      },
    });
    expect(metrics.senderIdentity.messageIdRegistrableDomainMatchesFromDomain).toBe(true);
  });

  it("populates messageIdRegistrableDomainMatchesFromDomain false for different orgs", () => {
    const metrics = extractMetrics({
      headers: {
        from: "Test <user@example.com>",
        "message-id": "<abc@other-org.com>",
      },
    });
    expect(metrics.senderIdentity.messageIdRegistrableDomainMatchesFromDomain).toBe(false);
  });

  it("populates messageIdDomainParts when Message-ID is present", () => {
    const metrics = extractMetrics({
      headers: {
        from: "Test <user@example.com>",
        "message-id": "<abc@mailer.example.net>",
      },
    });
    expect(metrics.senderIdentity.messageIdDomainParts?.registrableDomain).toBe("example.net");
    expect(metrics.senderIdentity.messageIdDomainParts?.subdomainDepth).toBe(1);
  });
});

describe("built-in PSL resolver — custom resolver override", () => {
  it("a custom getRegistrableDomain overrides the built-in resolver", () => {
    const customResolver = (_domain: string): string | null => "custom-override.com";
    const metrics = extractMetrics(
      { headers: { from: "Test <user@deep.sub.example.com>" } },
      { getRegistrableDomain: customResolver },
    );
    expect(metrics.senderIdentity.fromDomainParts?.registrableDomain).toBe("custom-override.com");
  });

  it("passing getRegistrableDomain: () => null opts out of PSL resolution", () => {
    const metrics = extractMetrics(
      { headers: { from: "Test <user@mail.example.com>" } },
      { getRegistrableDomain: () => null },
    );
    expect(metrics.senderIdentity.fromDomainParts?.registrableDomain).toBeNull();
    expect(metrics.senderIdentity.fromDomainParts?.subdomainDepth).toBeNull();
    expect(metrics.senderIdentity.messageIdRegistrableDomainMatchesFromDomain).toBeNull();
  });
});

describe("defaultGetRegistrableDomain — exported built-in resolver", () => {
  it("resolves a .co.jp compound suffix correctly", () => {
    expect(defaultGetRegistrableDomain("mail.example.co.jp")).toBe("example.co.jp");
  });

  it("resolves a standard .com domain", () => {
    expect(defaultGetRegistrableDomain("example.com")).toBe("example.com");
  });

  it("resolves a deep subdomain to its registrable domain", () => {
    expect(defaultGetRegistrableDomain("deep.sub.example.com")).toBe("example.com");
  });

  it("returns null for a bare TLD", () => {
    expect(defaultGetRegistrableDomain("com")).toBeNull();
  });
});

describe("built-in PSL resolver — analyzeMessage default", () => {
  it("PSL-backed metrics are available without passing deps to analyzeMessage", () => {
    const result = analyzeMessage({
      headers: {
        from: "Test <alerts@mail.example.co.jp>",
        "authentication-results": "mx.example.co.jp; dmarc=pass header.from=mail.example.co.jp",
      },
      options: { trustedAuthservIds: ["mx.example.co.jp"] },
    });
    expect(result.metrics.senderIdentity.fromDomainParts?.registrableDomain).toBe("example.co.jp");
    expect(result.metrics.senderIdentity.fromDomainParts?.subdomainDepth).toBe(1);
  });
});
