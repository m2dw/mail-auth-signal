import { describe, expect, it } from "vitest";
import {
  analyzeMessage,
  computeDisplayNameWhitespace,
  computeDomainParts,
  computeLexicalStats,
  computeSenderIdentity,
  extractEmbeddedDomains,
  extractMetrics,
  parseFromMailbox,
} from "../src/index.js";
import type { AnalyzeInput, MetricsDependencies, SenderIdentityMetrics } from "../src/index.js";
import benign from "./fixtures/senderidentity-benign.json" with { type: "json" };
import spoof from "./fixtures/senderidentity-display-name-spoof.json" with { type: "json" };

/** A tiny stand-in Public Suffix List resolver; the core bundles none. */
const PSL: Record<string, string> = {
  "example.com": "example.com",
  "mailer.example.com": "example.com",
  "news.mail.example.co.uk": "example.co.uk",
  "evil.test": "evil.test",
};
const deps: MetricsDependencies = { getRegistrableDomain: (domain) => PSL[domain] ?? null };

describe("senderIdentity — serializable fixtures (benign and suspicious)", () => {
  for (const fixture of [benign, spoof]) {
    it(`matches fixture: ${fixture.description.slice(0, 48)}…`, () => {
      const senderIdentity = analyzeMessage(fixture.input).metrics.senderIdentity;
      const roundTripped: SenderIdentityMetrics = JSON.parse(JSON.stringify(senderIdentity));
      expect(roundTripped).toEqual(fixture.expected);
    });
  }
});

describe("computeLexicalStats — structural counts only, codepoint-based", () => {
  it("counts length, digits, and hyphens", () => {
    expect(computeLexicalStats("secure-login-2024")).toEqual({
      length: 17,
      digitCount: 4,
      hyphenCount: 2,
      hasNonAscii: false,
    });
  });

  it("flags non-ASCII and measures by codepoint, not UTF-16 unit", () => {
    // "café" is 4 codepoints; the é is non-ASCII.
    expect(computeLexicalStats("café")).toEqual({
      length: 4,
      digitCount: 0,
      hyphenCount: 0,
      hasNonAscii: true,
    });
  });
});

describe("computeDomainParts — labels always, registrable only with a resolver", () => {
  it("decomposes labels without any external data", () => {
    expect(computeDomainParts("mail.example.com")).toEqual({
      domain: "mail.example.com",
      labels: ["mail", "example", "com"],
      labelCount: 3,
      topLabel: "com",
      registrableDomain: null,
      subdomainDepth: null,
    });
  });

  it("reports the registrable domain and subdomain depth when a resolver is supplied", () => {
    expect(computeDomainParts("news.mail.example.co.uk", deps.getRegistrableDomain)).toEqual({
      domain: "news.mail.example.co.uk",
      labels: ["news", "mail", "example", "co", "uk"],
      labelCount: 5,
      topLabel: "uk",
      registrableDomain: "example.co.uk",
      subdomainDepth: 2,
    });
  });

  it("leaves registrable fields null when the resolver cannot resolve the domain", () => {
    const parts = computeDomainParts("unknown.example.org", deps.getRegistrableDomain);
    expect(parts.registrableDomain).toBeNull();
    expect(parts.subdomainDepth).toBeNull();
  });
});

describe("extractEmbeddedDomains — addresses hidden in free text", () => {
  it("pulls every normalized domain from an address-shaped fragment", () => {
    expect(extractEmbeddedDomains("security@paypal.com")).toEqual(["paypal.com"]);
  });

  it("returns an empty array for text with no address", () => {
    expect(extractEmbeddedDomains("Example Support Team")).toEqual([]);
  });

  it("captures a raw IDN / homoglyph domain instead of stopping at the first non-ASCII byte", () => {
    // "раураl" is Cyrillic homoglyphs of the Latin brand; an ASCII-only capture
    // would never reach the dotted host.
    expect(extractEmbeddedDomains("support@раураl.com")).toEqual(["раураl.com"]);
  });
});

describe("parseFromMailbox — domain agrees with the canonical extractor", () => {
  it("splits display name, local part, and domain", () => {
    expect(parseFromMailbox("Example Sender <notice@example.com>")).toEqual({
      displayName: "Example Sender",
      localPart: "notice",
      domain: "example.com",
    });
  });

  it("does not fabricate a domain or local part from a multi-'@' angle-addr", () => {
    expect(parseFromMailbox("<a@b@example.com>")).toEqual({
      displayName: null,
      localPart: null,
      domain: null,
    });
  });

  it("slices the display name at the real angle-addr, not an earlier literal '<'", () => {
    // The quoted display name legally contains a "<notice>" fragment before the
    // real mailbox; cutting at the first "<" would truncate it to `"Team` and
    // drop the embedded address-shaped spoof.
    expect(parseFromMailbox('"Team <notice> service@paypal.com" <attacker@evil.test>')).toEqual({
      displayName: "Team <notice> service@paypal.com",
      localPart: "attacker",
      domain: "evil.test",
    });
  });

  it("skips an address-shaped angle fragment inside the quoted display name", () => {
    // The quoted phrase holds a full `<service@paypal.com>` angle-addr; the real
    // mailbox is the angle-addr *outside* the quotes. Taking the inner fragment
    // would report paypal.com as the sender and hide the display-name spoof.
    expect(parseFromMailbox('"Support <service@paypal.com>" <attacker@evil.test>')).toEqual({
      displayName: "Support <service@paypal.com>",
      localPart: "attacker",
      domain: "evil.test",
    });
  });
});

describe("senderIdentity — display-name address spoof", () => {
  it("surfaces an embedded brand domain that differs from the real From domain", () => {
    const metrics = extractMetrics({
      headers: { from: '"security@paypal.com" <attacker@evil.test>' },
    });
    const si = metrics.senderIdentity;
    expect(si.displayName.containsEmail).toBe(true);
    expect(si.displayName.embeddedDomains).toEqual(["paypal.com"]);
    expect(si.displayName.embeddedDomainMatchesFromDomain).toBe(false);
    expect(si.localPart).toBe("attacker");
    expect(metrics.fromDomain).toBe("evil.test");
  });

  it("still catches the spoof when the display name holds an earlier '<...>' fragment", () => {
    const metrics = extractMetrics({
      headers: { from: '"Team <notice> service@paypal.com" <attacker@evil.test>' },
    });
    const si = metrics.senderIdentity;
    expect(si.displayName.text).toBe("Team <notice> service@paypal.com");
    expect(si.displayName.containsEmail).toBe(true);
    expect(si.displayName.embeddedDomains).toEqual(["paypal.com"]);
    expect(si.displayName.embeddedDomainMatchesFromDomain).toBe(false);
    expect(metrics.fromDomain).toBe("evil.test");
  });

  it("still catches the spoof when the quoted display name holds an angle-addr fragment", () => {
    const metrics = extractMetrics({
      headers: { from: '"Support <service@paypal.com>" <attacker@evil.test>' },
    });
    const si = metrics.senderIdentity;
    expect(si.displayName.text).toBe("Support <service@paypal.com>");
    expect(si.displayName.containsEmail).toBe(true);
    expect(si.displayName.embeddedDomains).toEqual(["paypal.com"]);
    expect(si.displayName.embeddedDomainMatchesFromDomain).toBe(false);
    expect(si.localPart).toBe("attacker");
    expect(metrics.fromDomain).toBe("evil.test");
  });

  it("surfaces an embedded homoglyph IDN domain hidden in the display name", () => {
    const metrics = extractMetrics({
      headers: { from: '"support@раураl.com" <attacker@evil.test>' },
    });
    const si = metrics.senderIdentity;
    expect(si.displayName.containsEmail).toBe(true);
    expect(si.displayName.embeddedDomains).toEqual(["раураl.com"]);
    expect(si.displayName.embeddedDomainMatchesFromDomain).toBe(false);
    expect(metrics.fromDomain).toBe("evil.test");
  });
});

describe("senderIdentity — lexical anomalies are reported, not judged", () => {
  it("counts digits and hyphens in a lookalike domain", () => {
    const si = extractMetrics({
      headers: { from: "Account <secure@paypa1-login.com>" },
    }).senderIdentity;
    expect(si.fromDomainLexical).toEqual({
      length: 16,
      digitCount: 1,
      hyphenCount: 1,
      hasNonAscii: false,
    });
  });

  it("flags a non-ASCII (raw IDN) domain and display name", () => {
    const si = extractMetrics({
      headers: { from: '"Stürmer" <kunde@stürmer-bank.example>' },
    }).senderIdentity;
    expect(si.displayName.hasNonAscii).toBe(true);
    expect(si.fromDomainLexical?.hasNonAscii).toBe(true);
    expect(si.fromDomainLexical?.hyphenCount).toBe(1);
  });
});

describe("senderIdentity — registrable-domain comparison requires a resolver", () => {
  const message = (messageId: string): AnalyzeInput => ({
    headers: { from: "Example Sender <notice@example.com>", "message-id": messageId },
  });

  it("is null without a resolver even when an exact comparison is possible", () => {
    const result = analyzeMessage(message("<x@mailer.example.com>"));
    expect(result.metrics.messageIdDomainMatchesFromDomain).toBe(false);
    expect(result.metrics.senderIdentity.messageIdRegistrableDomainMatchesFromDomain).toBeNull();
  });

  it("treats an ESP subdomain as same-organization when a resolver is supplied", () => {
    const result = analyzeMessage(message("<x@mailer.example.com>"), undefined, deps);
    // Exact comparison still reads as a mismatch …
    expect(result.metrics.messageIdDomainMatchesFromDomain).toBe(false);
    // … but the registrable-domain comparison recognizes the shared organization.
    expect(result.metrics.senderIdentity.messageIdRegistrableDomainMatchesFromDomain).toBe(true);
  });

  it("reports false when the registrable domains genuinely differ", () => {
    const result = analyzeMessage(message("<x@evil.test>"), undefined, deps);
    expect(result.metrics.senderIdentity.messageIdRegistrableDomainMatchesFromDomain).toBe(false);
  });
});

describe("displayName — whitespace-compacted brand-style normalization", () => {
  it("compacts a letter-spaced brand name into a useful matchable token", () => {
    const si = extractMetrics({
      headers: { from: "D d a i i c h i L i f e I n s u r a n c e <noreply@evil.test>" },
    }).senderIdentity;
    // The raw display name is preserved verbatim for consumers …
    expect(si.displayName.text).toBe("D d a i i c h i L i f e I n s u r a n c e");
    // … alongside a compacted token a brand-list match can actually hit.
    expect(si.displayName.normalized.compactedWhitespace).toBe("DdaiichiLifeInsurance");
    expect(si.displayName.metrics.whitespaceCompactedChanged).toBe(true);
    expect(si.displayName.signals.spacedDisplayNameCamouflageCandidate).toBe(true);
  });

  it("does not flag a normal multi-word human name as spacing camouflage", () => {
    const si = extractMetrics({
      headers: { from: "Daiichi Life Insurance <support@example.com>" },
    }).senderIdentity;
    expect(si.displayName.text).toBe("Daiichi Life Insurance");
    // Compaction still happens (it is a plain metric) …
    expect(si.displayName.normalized.compactedWhitespace).toBe("DaiichiLifeInsurance");
    expect(si.displayName.metrics.whitespaceCompactedChanged).toBe(true);
    // … but the compacted token is never treated as an address, and the
    // camouflage signal stays false for an ordinary multi-word name.
    expect(si.displayName.containsEmail).toBe(false);
    expect(si.displayName.embeddedDomains).toEqual([]);
    expect(si.displayName.signals.spacedDisplayNameCamouflageCandidate).toBe(false);
  });

  it("leaves a single-word display name unchanged and unflagged", () => {
    const result = computeDisplayNameWhitespace("Daiichi");
    expect(result).toEqual({
      normalized: { compactedWhitespace: "Daiichi" },
      metrics: { whitespaceCompactedChanged: false },
      signals: { spacedDisplayNameCamouflageCandidate: false },
    });
  });

  it("does not flag a name carrying one or two initials as camouflage", () => {
    // "John A Smith" (one initial) and "J P Morgan" (two initials) are common
    // human/brand shapes; neither crosses the single-letter-majority threshold.
    expect(
      computeDisplayNameWhitespace("John A Smith").signals.spacedDisplayNameCamouflageCandidate,
    ).toBe(false);
    expect(
      computeDisplayNameWhitespace("J P Morgan").signals.spacedDisplayNameCamouflageCandidate,
    ).toBe(false);
  });

  it("flags a partially letter-spaced brand (majority single letters)", () => {
    const result = computeDisplayNameWhitespace("D d a i i c h i Life Insurance");
    expect(result.normalized.compactedWhitespace).toBe("DdaiichiLifeInsurance");
    expect(result.signals.spacedDisplayNameCamouflageCandidate).toBe(true);
  });

  it("reports nulls/false for an absent display name", () => {
    expect(computeDisplayNameWhitespace(null)).toEqual({
      normalized: { compactedWhitespace: null },
      metrics: { whitespaceCompactedChanged: false },
      signals: { spacedDisplayNameCamouflageCandidate: false },
    });
  });

  it("does not count single non-letter tokens (e.g. ampersand) toward camouflage", () => {
    // "A & B Corp" has single-char tokens but only two are letters, so the
    // single-letter count stays below the threshold and it is not flagged.
    const result = computeDisplayNameWhitespace("A & B Corp");
    expect(result.signals.spacedDisplayNameCamouflageCandidate).toBe(false);
  });
});

describe("senderIdentity — missing From stays silent (all null)", () => {
  it("reports nulls for every From-derived field when From is absent", () => {
    const si = computeSenderIdentity(null, null, "mailer.example.net");
    expect(si.localPart).toBeNull();
    expect(si.localPartLexical).toBeNull();
    expect(si.fromDomainLexical).toBeNull();
    expect(si.fromDomainParts).toBeNull();
    expect(si.displayName.present).toBe(false);
    expect(si.displayName.text).toBeNull();
    expect(si.displayName.length).toBe(0);
    // The Message-ID domain still decomposes.
    expect(si.messageIdDomainParts?.labelCount).toBe(3);
  });
});
