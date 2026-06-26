import { describe, expect, it } from "vitest";
import {
  allRegistrableDomainsMatch,
  analyzeMessage,
  extractMetrics,
  registrableDomainsMatch,
} from "../src/index.js";
import type { MetricsDependencies } from "../src/index.js";

/** Opt out of PSL resolution so the registrable comparisons report null. */
const noPsl: MetricsDependencies = { getRegistrableDomain: () => null };

describe("Sender header — authoritative extraction and comparison", () => {
  it("extracts the Sender domain and reports exact + registrable agreement with From", () => {
    const m = extractMetrics({
      headers: {
        from: "Example Sender <notice@example.com>",
        sender: "Bounce Agent <bounce@mail.example.com>",
      },
    });
    expect(m.senderDomain).toBe("mail.example.com");
    // Exact comparison treats the sending subdomain as a mismatch …
    expect(m.senderDomainMatchesFromDomain).toBe(false);
    // … while the built-in PSL recognizes the shared organization.
    expect(m.senderDomainRegistrableMatchesFromDomain).toBe(true);
  });

  it("flags a Sender at a different organization on both comparisons", () => {
    const m = extractMetrics({
      headers: {
        from: "Example Sender <notice@example.com>",
        sender: "submitter@evil.test",
      },
    });
    expect(m.senderDomain).toBe("evil.test");
    expect(m.senderDomainMatchesFromDomain).toBe(false);
    expect(m.senderDomainRegistrableMatchesFromDomain).toBe(false);
  });

  it("stays silent (all null) when no Sender header is present — the common case", () => {
    const m = extractMetrics({ headers: { from: "notice@example.com" } });
    expect(m.senderDomain).toBeNull();
    expect(m.senderDomainMatchesFromDomain).toBeNull();
    expect(m.senderDomainRegistrableMatchesFromDomain).toBeNull();
  });

  it("honors angle-bracket precedence and does not reach into a quoted display name", () => {
    // The quoted Sender display name embeds a full <svc@paypal.com> angle-addr;
    // the real submitter is the angle-addr outside the quotes.
    const m = extractMetrics({
      headers: {
        from: "notice@example.com",
        sender: '"Support <svc@paypal.com>" <bounce@example.com>',
      },
    });
    expect(m.senderDomain).toBe("example.com");
    expect(m.senderDomainMatchesFromDomain).toBe(true);
  });

  it("reports null registrable comparison when PSL resolution is disabled", () => {
    const m = extractMetrics(
      { headers: { from: "notice@example.com", sender: "bounce@mail.example.com" } },
      noPsl,
    );
    expect(m.senderDomain).toBe("mail.example.com");
    expect(m.senderDomainMatchesFromDomain).toBe(false);
    expect(m.senderDomainRegistrableMatchesFromDomain).toBeNull();
  });
});

describe("registrable-domain comparisons — .co.jp organizational boundary", () => {
  it("treats a Reply-To subdomain of the same .co.jp organization as same-org", () => {
    const result = analyzeMessage({
      headers: {
        from: "Support <info@example.co.jp>",
        "reply-to": "Desk <desk@news.example.co.jp>",
      },
    });
    expect(result.metrics.replyToDomainMatchesFromDomain).toBe(false);
    expect(result.metrics.replyToDomainRegistrableMatchesFromDomain).toBe(true);
  });

  it("flags a Reply-To at a different .co.jp organization on both comparisons", () => {
    const result = analyzeMessage({
      headers: {
        from: "Support <info@example.co.jp>",
        "reply-to": "attacker@evil.co.jp",
      },
    });
    expect(result.metrics.replyToDomainMatchesFromDomain).toBe(false);
    expect(result.metrics.replyToDomainRegistrableMatchesFromDomain).toBe(false);
  });

  it("recognizes a Return-Path VERP subdomain as the same .co.jp organization", () => {
    const result = analyzeMessage({
      headers: {
        from: "Support <info@example.co.jp>",
        "return-path": "<bounce+verp@vps.example.co.jp>",
      },
    });
    expect(result.metrics.returnPathDomainMatchesFromDomain).toBe(false);
    expect(result.metrics.returnPathDomainRegistrableMatchesFromDomain).toBe(true);
  });

  it("leaves the registrable comparisons null when no domain is present to compare", () => {
    const result = analyzeMessage({ headers: { from: "info@example.co.jp" } });
    expect(result.metrics.replyToDomainRegistrableMatchesFromDomain).toBeNull();
    expect(result.metrics.returnPathDomainRegistrableMatchesFromDomain).toBeNull();
  });
});

describe("registrable comparison helpers — exported for callers", () => {
  /** A tiny stand-in resolver; only the listed domains resolve. */
  const resolve = (domain: string): string | null =>
    ({
      "example.com": "example.com",
      "mail.example.com": "example.com",
      "evil.test": "evil.test",
    })[domain] ?? null;

  it("registrableDomainsMatch is null when either domain is absent or unresolvable", () => {
    expect(registrableDomainsMatch(null, "example.com", resolve)).toBeNull();
    expect(registrableDomainsMatch("example.com", null, resolve)).toBeNull();
    // "unknown.test" does not resolve, so no confident verdict is possible.
    expect(registrableDomainsMatch("example.com", "unknown.test", resolve)).toBeNull();
  });

  it("registrableDomainsMatch compares registrable forms, not exact strings", () => {
    expect(registrableDomainsMatch("example.com", "mail.example.com", resolve)).toBe(true);
    expect(registrableDomainsMatch("example.com", "evil.test", resolve)).toBe(false);
  });

  it("allRegistrableDomainsMatch returns null on an empty list or any unresolvable member", () => {
    expect(allRegistrableDomainsMatch("example.com", [], resolve)).toBeNull();
    expect(
      allRegistrableDomainsMatch("example.com", ["mail.example.com", "unknown.test"], resolve),
    ).toBeNull();
  });

  it("allRegistrableDomainsMatch is true only when every member shares the registrable domain", () => {
    expect(
      allRegistrableDomainsMatch("example.com", ["mail.example.com", "example.com"], resolve),
    ).toBe(true);
    expect(
      allRegistrableDomainsMatch("example.com", ["mail.example.com", "evil.test"], resolve),
    ).toBe(false);
  });
});
