import { describe, expect, it } from "vitest";
import {
  analyzeMessage,
  defaultCompositeRules,
  defaultPublicMailboxProviders,
  defaultRules,
  extractMetrics,
  lookupPublicMailboxProvider,
  publicMailboxSpoofingCandidateRule,
} from "../src/index.js";
import type {
  AnalyzeInput,
  MetricsDependencies,
  PublicMailboxProvider,
  Signal,
} from "../src/index.js";

const TRUSTED_ID = "mx.example.net";

/** The publicMailboxSpoofingCandidate composite signal, if present. */
function candidate(input: AnalyzeInput): Signal | undefined {
  const result = analyzeMessage(input, defaultRules, undefined, defaultCompositeRules);
  return result.signals.find((s) => s.key === "composite.publicMailboxSpoofingCandidate");
}

describe("lookupPublicMailboxProvider — exact, case-insensitive catalog lookup", () => {
  it("maps each built-in domain to its provider id", () => {
    expect(lookupPublicMailboxProvider("gmail.com")).toBe("google");
    expect(lookupPublicMailboxProvider("googlemail.com")).toBe("google");
    expect(lookupPublicMailboxProvider("outlook.com")).toBe("microsoft");
    expect(lookupPublicMailboxProvider("hotmail.com")).toBe("microsoft");
    expect(lookupPublicMailboxProvider("live.com")).toBe("microsoft");
    expect(lookupPublicMailboxProvider("msn.com")).toBe("microsoft");
    expect(lookupPublicMailboxProvider("icloud.com")).toBe("apple");
    expect(lookupPublicMailboxProvider("me.com")).toBe("apple");
    expect(lookupPublicMailboxProvider("mac.com")).toBe("apple");
    expect(lookupPublicMailboxProvider("yahoo.com")).toBe("yahoo");
    expect(lookupPublicMailboxProvider("yahoo.co.jp")).toBe("yahoo");
    expect(lookupPublicMailboxProvider("aol.com")).toBe("aol");
  });

  it("is case-insensitive", () => {
    expect(lookupPublicMailboxProvider("GMail.com")).toBe("google");
  });

  it("returns null for a non-catalog domain and for null", () => {
    expect(lookupPublicMailboxProvider("example.com")).toBeNull();
    // A subdomain is not matched — no PSL logic is applied here.
    expect(lookupPublicMailboxProvider("mail.gmail.com")).toBeNull();
    expect(lookupPublicMailboxProvider(null)).toBeNull();
  });

  it("honors a caller-supplied catalog (extend or replace)", () => {
    const custom: PublicMailboxProvider[] = [{ id: "acme", domains: ["acme.example"] }];
    expect(lookupPublicMailboxProvider("acme.example", custom)).toBe("acme");
    // A replacement catalog no longer matches the built-ins.
    expect(lookupPublicMailboxProvider("gmail.com", custom)).toBeNull();
    // Extending keeps the built-ins.
    expect(lookupPublicMailboxProvider("gmail.com", [...defaultPublicMailboxProviders, ...custom])).toBe(
      "google",
    );
  });

  it("exposes the documented initial catalog", () => {
    const ids = defaultPublicMailboxProviders.map((p) => p.id);
    expect(ids).toEqual(["google", "microsoft", "apple", "yahoo", "aol"]);
  });
});

describe("senderIdentity — public mailbox provider membership", () => {
  it("flags a public-mailbox From and records its provider id", () => {
    const { senderIdentity } = extractMetrics({
      headers: { from: "Someone <someone@outlook.com>" },
    });
    expect(senderIdentity.fromDomainIsPublicMailboxProvider).toBe(true);
    expect(senderIdentity.publicMailboxProviderId).toBe("microsoft");
  });

  it("does not flag an ordinary non-catalog domain", () => {
    const { senderIdentity } = extractMetrics({
      headers: { from: "Notice <notice@example.com>" },
    });
    expect(senderIdentity.fromDomainIsPublicMailboxProvider).toBe(false);
    expect(senderIdentity.publicMailboxProviderId).toBeNull();
  });

  it("is false/null when there is no parseable From domain", () => {
    const { senderIdentity } = extractMetrics({ headers: { from: "not an address" } });
    expect(senderIdentity.fromDomainIsPublicMailboxProvider).toBe(false);
    expect(senderIdentity.publicMailboxProviderId).toBeNull();
  });

  it("matches via the registrable domain when a PSL resolver is supplied", () => {
    // Without a resolver a provider subdomain does not match (no PSL logic).
    const noResolver = extractMetrics({
      headers: { from: "User <user@mail.gmail.com>" },
    });
    expect(noResolver.senderIdentity.fromDomainIsPublicMailboxProvider).toBe(false);

    // With a resolver reducing mail.gmail.com -> gmail.com, it matches "google".
    const deps: MetricsDependencies = {
      getRegistrableDomain: (domain) => (domain.endsWith("gmail.com") ? "gmail.com" : null),
    };
    const withResolver = extractMetrics(
      { headers: { from: "User <user@mail.gmail.com>" } },
      deps,
    );
    expect(withResolver.senderIdentity.fromDomainIsPublicMailboxProvider).toBe(true);
    expect(withResolver.senderIdentity.publicMailboxProviderId).toBe("google");
  });

  it("honors a caller-overridden catalog via MetricsDependencies", () => {
    const deps: MetricsDependencies = {
      publicMailboxProviders: [{ id: "acme", domains: ["acme.example"] }],
    };
    // The override replaces the built-ins: gmail.com no longer matches…
    const gmail = extractMetrics({ headers: { from: "a@gmail.com" } }, deps);
    expect(gmail.senderIdentity.fromDomainIsPublicMailboxProvider).toBe(false);
    // …but the caller's own domain does.
    const acme = extractMetrics({ headers: { from: "a@acme.example" } }, deps);
    expect(acme.senderIdentity.publicMailboxProviderId).toBe("acme");
  });
});

describe("composite.publicMailboxSpoofingCandidate", () => {
  it("flags the outlook/icloud/yahoo split pattern", () => {
    // From outlook.com, but the envelope/Message-ID name other providers and the
    // trusted verifier failed DMARC/SPF — the logged real-world spoof shape.
    const signal = candidate({
      headers: {
        from: "Account <user@outlook.com>",
        "return-path": "<bounce@icloud.com>",
        "message-id": "<abc123@yahoo.co.jp>",
        "authentication-results": `${TRUSTED_ID}; dmarc=fail header.from=outlook.com; spf=fail smtp.mailfrom=icloud.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(signal).toBeDefined();
    expect(signal?.severity).toBe("medium");
    expect(signal?.category).toBe("composite");
    expect(signal?.data?.fromDomain).toBe("outlook.com");
    expect(signal?.data?.publicMailboxProviderId).toBe("microsoft");
  });

  it("does not flag genuine aligned public mailbox mail", () => {
    const signal = candidate({
      headers: {
        from: "Real User <real@gmail.com>",
        "message-id": "<id@gmail.com>",
        "authentication-results": `${TRUSTED_ID}; dmarc=pass header.from=gmail.com; spf=pass smtp.mailfrom=gmail.com; dkim=pass header.d=gmail.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(signal).toBeUndefined();
  });

  it("does not flag a non-catalog ordinary domain even when unauthenticated", () => {
    const signal = candidate({
      headers: {
        from: "Notice <notice@example.com>",
        "message-id": "<id@evil.test>",
        "authentication-results": `${TRUSTED_ID}; dmarc=fail header.from=example.com; spf=fail smtp.mailfrom=evil.test`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(signal).toBeUndefined();
  });

  it("stays silent when no trusted Authentication-Results header evaluated the message", () => {
    // From a public mailbox provider, failing auth, but the AR header is from an
    // untrusted authserv-id — nothing authoritative actually ran, so the candidate
    // is not manufactured from an unverifiable message.
    const signal = candidate({
      headers: {
        from: "Account <user@outlook.com>",
        "authentication-results": `mx.attacker.test; dmarc=fail header.from=outlook.com; spf=fail smtp.mailfrom=icloud.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(signal).toBeUndefined();
  });

  it("stays silent when a trusted DMARC pass aligns with the public-mailbox From", () => {
    // A bare aggregate dmarc=pass for the visible From (no SPF/DKIM method rows)
    // authenticates it, so a benign Message-ID host mismatch does not trip this.
    const signal = candidate({
      headers: {
        from: "Real User <real@yahoo.co.jp>",
        "message-id": "<id@mailer.example.net>",
        "authentication-results": `${TRUSTED_ID}; dmarc=pass header.from=yahoo.co.jp`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(signal).toBeUndefined();
  });

  it("has the expected stable rule identity", () => {
    expect(publicMailboxSpoofingCandidateRule.key).toBe(
      "composite.publicMailboxSpoofingCandidate",
    );
  });
});
