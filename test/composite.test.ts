import { describe, expect, it } from "vitest";
import {
  alignedAuthenticationConfirmedRule,
  analyzeMessage,
  authenticatedDisplayNameSpoofRule,
  defaultCompositeRules,
  defaultRules,
  extractMetrics,
  runCompositeRules,
  runRules,
  unauthenticatedFromSpoofRule,
} from "../src/index.js";
import type { AnalyzeInput, AnalyzeResult, Signal } from "../src/index.js";
import unauthSpoof from "./fixtures/composite-unauthenticated-from-spoof.json" with { type: "json" };
import displayNameSpoof from "./fixtures/composite-authenticated-displayname-spoof.json" with { type: "json" };
import confirmed from "./fixtures/composite-aligned-authentication-confirmed.json" with { type: "json" };

const TRUSTED_ID = "mx.example.net";

/** The composite.* signals only. */
function compositeSignals(signals: readonly Signal[]): Signal[] {
  return signals.filter((signal) => signal.key.startsWith("composite."));
}

/** analyzeMessage with the default base rules and the full composite layer enabled. */
function analyzeWithComposites(input: AnalyzeInput): AnalyzeResult {
  return analyzeMessage(input, defaultRules, undefined, defaultCompositeRules);
}

describe("composite layer — disabled by default", () => {
  it("emits no composite signal unless composite rules are passed in", () => {
    const input: AnalyzeInput = {
      headers: {
        from: "Example <a@example.com>",
        "message-id": "<id@evil.test>",
        "authentication-results": `${TRUSTED_ID}; dmarc=fail header.from=example.com; spf=fail smtp.mailfrom=evil.test; dkim=fail header.d=evil.test`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    };
    const base = analyzeMessage(input);
    expect(compositeSignals(base.signals)).toEqual([]);
    // Same input, composites enabled, now surfaces the spoof.
    const withComposites = analyzeWithComposites(input);
    expect(compositeSignals(withComposites.signals).map((s) => s.key)).toContain(
      "composite.unauthenticatedFromSpoof",
    );
  });

  it("appends composite signals after the base signals", () => {
    const result = analyzeWithComposites({
      headers: {
        from: "Example <a@example.com>",
        "message-id": "<id@evil.test>",
        "authentication-results": `${TRUSTED_ID}; dmarc=fail header.from=example.com; spf=fail smtp.mailfrom=evil.test; dkim=fail header.d=evil.test`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    const firstComposite = result.signals.findIndex((s) => s.category === "composite");
    const lastBase = result.signals.reduce(
      (acc, s, i) => (s.category !== "composite" ? i : acc),
      -1,
    );
    expect(firstComposite).toBeGreaterThan(lastBase);
  });
});

describe("composite.unauthenticatedFromSpoof", () => {
  it("fires high when From is unauthenticated and an identifier disagrees", () => {
    const result = analyzeWithComposites({
      headers: {
        from: "Example <notice@example.com>",
        "message-id": "<spoof@evil.test>",
        "return-path": "<bounce@evil.test>",
        "authentication-results": `${TRUSTED_ID}; dmarc=fail header.from=example.com; spf=fail smtp.mailfrom=evil.test; dkim=fail header.d=evil.test`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    const signals = compositeSignals(result.signals);
    expect(signals).toHaveLength(1);
    const signal = signals[0];
    expect(signal?.key).toBe("composite.unauthenticatedFromSpoof");
    expect(signal?.severity).toBe("high");
    expect(signal?.category).toBe("composite");
    expect(signal?.data?.fromDomain).toBe("example.com");
    expect(signal?.data?.anyAuthAligned).toBe(false);
    // Contributing signals name the lower-layer keys that justified it.
    const contributing = signal?.data?.contributingSignals as string[];
    expect(contributing).toContain("auth.method.failure");
    expect(contributing).toContain("messageId.domainMismatch");
    expect(contributing).toContain("returnPath.domainMismatch");
    expect(contributing).toContain("smtpMailfrom.domainMismatch");
    // Deduplicated despite three failed methods sharing the auth.method.failure key.
    expect(contributing.filter((k) => k === "auth.method.failure")).toHaveLength(1);
  });

  it("stays silent when an aligned DKIM signature authenticates the From (forwarder)", () => {
    // SPF fails and the envelope diverges, but an aligned DKIM pass means the From
    // domain is authenticated — the spoof composite must not fire.
    const result = analyzeWithComposites({
      headers: {
        from: "Example <notice@example.com>",
        "message-id": "<id@example.com>",
        "return-path": "<bounce@forwarder.test>",
        "authentication-results": `${TRUSTED_ID}; spf=fail smtp.mailfrom=forwarder.test; dkim=pass header.d=example.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.authentication.anyAuthAligned).toBe(true);
    expect(
      compositeSignals(result.signals).map((s) => s.key),
    ).not.toContain("composite.unauthenticatedFromSpoof");
  });

  it("stays silent on an honest authentication failure with no identifier mismatch", () => {
    // Everything names example.com; auth just failed. That is a misconfiguration,
    // not impersonation, so only base auth.method.failure fires.
    const result = analyzeWithComposites({
      headers: {
        from: "Example <notice@example.com>",
        "message-id": "<id@example.com>",
        "return-path": "<bounce@example.com>",
        "authentication-results": `${TRUSTED_ID}; spf=fail smtp.mailfrom=example.com; dkim=fail header.d=example.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(
      compositeSignals(result.signals).map((s) => s.key),
    ).not.toContain("composite.unauthenticatedFromSpoof");
  });

  it("stays silent when the trusted header carries no SPF/DKIM/DMARC sender-auth result", () => {
    // The trusted header only reports arc=pass — no sender authentication ran — so
    // anyAuthAligned is vacuously false. A bare Message-ID mismatch must not turn an
    // unevaluated message into a confirmed unauthenticated spoof.
    const result = analyzeWithComposites({
      headers: {
        from: "Example <notice@example.com>",
        "message-id": "<spoof@evil.test>",
        "authentication-results": `${TRUSTED_ID}; arc=pass`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.authentication.trustedHeaderCount).toBe(1);
    expect(result.metrics.authentication.anyAuthAligned).toBe(false);
    // The Message-ID mismatch is present as a base consistency signal...
    expect(result.signals.map((s) => s.key)).toContain("messageId.domainMismatch");
    // ...but with no trusted sender-auth result it must not escalate.
    expect(
      compositeSignals(result.signals).map((s) => s.key),
    ).not.toContain("composite.unauthenticatedFromSpoof");
  });

  it("does not escalate when the only mismatch comes from an untrusted AR header", () => {
    // Honest-but-failing message: every identifier names example.com and the trusted
    // header shows SPF/DKIM/DMARC fail. An attacker injects an untrusted header
    // claiming dkim=pass header.d=evil.test, which makes dkim.domainMismatch fire. That
    // forge-able AR-derived mismatch must not escalate the honest failure to a spoof.
    const result = analyzeWithComposites({
      headers: {
        from: "Example <notice@example.com>",
        "message-id": "<id@example.com>",
        "return-path": "<bounce@example.com>",
        "authentication-results": [
          `${TRUSTED_ID}; dmarc=fail header.from=example.com; spf=fail smtp.mailfrom=example.com; dkim=fail header.d=example.com`,
          "relay.evil.test; dkim=pass header.d=evil.test",
        ],
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.authentication.anyAuthAligned).toBe(false);
    // The forged untrusted header produced a base consistency mismatch...
    expect(result.signals.map((s) => s.key)).toContain("dkim.domainMismatch");
    // ...but only trusted/message-header evidence may escalate, so the composite stays silent.
    expect(
      compositeSignals(result.signals).map((s) => s.key),
    ).not.toContain("composite.unauthenticatedFromSpoof");
  });

  it("does not escalate on an untrusted smtp.mailfrom mismatch alone", () => {
    // Same shape as above but the injected untrusted header forges an SPF
    // smtp.mailfrom=evil.test. The smtpMailfrom.domainMismatch it produces is
    // forge-able, so it must not escalate the honest failure.
    const result = analyzeWithComposites({
      headers: {
        from: "Example <notice@example.com>",
        "message-id": "<id@example.com>",
        "return-path": "<bounce@example.com>",
        "authentication-results": [
          `${TRUSTED_ID}; dmarc=fail header.from=example.com; spf=fail smtp.mailfrom=example.com; dkim=fail header.d=example.com`,
          "relay.evil.test; spf=pass smtp.mailfrom=evil.test",
        ],
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.authentication.anyAuthAligned).toBe(false);
    expect(result.signals.map((s) => s.key)).toContain("smtpMailfrom.domainMismatch");
    expect(
      compositeSignals(result.signals).map((s) => s.key),
    ).not.toContain("composite.unauthenticatedFromSpoof");
  });

  it("still fires on a trusted smtp.mailfrom mismatch even without a message-header tell", () => {
    // Authoritative evidence need not be a message header: a trusted SPF header whose
    // smtp.mailfrom disagrees with From is enough divergent-identity evidence to fire.
    const result = analyzeWithComposites({
      headers: {
        from: "Example <notice@example.com>",
        "message-id": "<id@example.com>",
        "return-path": "<bounce@example.com>",
        "authentication-results": `${TRUSTED_ID}; dmarc=fail header.from=example.com; spf=fail smtp.mailfrom=evil.test; dkim=fail header.d=example.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.authentication.anyAuthAligned).toBe(false);
    expect(
      compositeSignals(result.signals).map((s) => s.key),
    ).toContain("composite.unauthenticatedFromSpoof");
  });

  it("stays silent when no trusted header gives a basis to judge", () => {
    const result = analyzeWithComposites({
      headers: {
        from: "Example <notice@example.com>",
        "message-id": "<spoof@evil.test>",
        "authentication-results": "relay.evil.test; dmarc=fail header.from=example.com",
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.authentication.trustedHeaderCount).toBe(0);
    expect(
      compositeSignals(result.signals).map((s) => s.key),
    ).not.toContain("composite.unauthenticatedFromSpoof");
  });

  it("stays silent with no parseable From even when the envelope sender disagrees", () => {
    // Malformed/system message: no usable From, so nothing is being impersonated.
    // Return-Path and smtp.mailfrom merely disagree with each other, which fires
    // envelopeSender.domainDisagreement — a consistency signal that never compares
    // to From. Without the From guard this would emit a high spoof with
    // fromDomain:null; the visible-From-spoof premise requires a visible From.
    const result = analyzeWithComposites({
      headers: {
        "message-id": "<id@a.test>",
        "return-path": "<bounce@a.test>",
        "authentication-results": `${TRUSTED_ID}; spf=fail smtp.mailfrom=b.test`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.fromDomain).toBeNull();
    // The envelope-sender disagreement is present as a base consistency signal...
    expect(result.signals.map((s) => s.key)).toContain("envelopeSender.domainDisagreement");
    // ...but it must not be escalated to a From-spoof verdict.
    expect(
      compositeSignals(result.signals).map((s) => s.key),
    ).not.toContain("composite.unauthenticatedFromSpoof");
  });
});

describe("composite.authenticatedDisplayNameSpoof", () => {
  it("fires medium when an authenticated message's display name addresses another domain", () => {
    const result = analyzeWithComposites({
      headers: {
        from: '"security@paypal.com" <alerts@example.com>',
        "message-id": "<id@example.com>",
        "authentication-results": `${TRUSTED_ID}; dmarc=pass header.from=example.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.authentication.anyAuthAligned).toBe(true);
    const signals = compositeSignals(result.signals);
    const spoof = signals.find((s) => s.key === "composite.authenticatedDisplayNameSpoof");
    expect(spoof?.severity).toBe("medium");
    expect(spoof?.data?.fromDomain).toBe("example.com");
    expect(spoof?.data?.mismatchedDomains).toEqual(["paypal.com"]);
    // The affirmation must be withheld when the display name is misleading.
    expect(signals.map((s) => s.key)).not.toContain(
      "composite.alignedAuthenticationConfirmed",
    );
  });

  it("stays silent when the authenticated message has no misleading display name", () => {
    const result = analyzeWithComposites({
      headers: {
        from: "Example Support <support@example.com>",
        "message-id": "<id@example.com>",
        "authentication-results": `${TRUSTED_ID}; dmarc=pass header.from=example.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(
      compositeSignals(result.signals).map((s) => s.key),
    ).not.toContain("composite.authenticatedDisplayNameSpoof");
  });

  it("does not fire when the display name's domain matches the From domain", () => {
    const result = analyzeWithComposites({
      headers: {
        from: '"help@example.com" <support@example.com>',
        "message-id": "<id@example.com>",
        "authentication-results": `${TRUSTED_ID}; dmarc=pass header.from=example.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(
      compositeSignals(result.signals).map((s) => s.key),
    ).not.toContain("composite.authenticatedDisplayNameSpoof");
  });

  it("does not fire on an unauthenticated message (left to the spoof/base signals)", () => {
    const result = analyzeWithComposites({
      headers: {
        from: '"security@paypal.com" <alerts@example.com>',
        "message-id": "<id@example.com>",
        "authentication-results": `${TRUSTED_ID}; dmarc=fail header.from=example.com; spf=fail smtp.mailfrom=example.com; dkim=fail header.d=example.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(
      compositeSignals(result.signals).map((s) => s.key),
    ).not.toContain("composite.authenticatedDisplayNameSpoof");
  });
});

describe("composite.alignedAuthenticationConfirmed (false-positive mitigation)", () => {
  it("affirms a clean, aligned, trusted message", () => {
    const result = analyzeWithComposites({
      headers: {
        from: "Example Support <support@example.com>",
        "message-id": "<id@example.com>",
        "return-path": "<bounce@example.com>",
        "reply-to": "<reply@example.com>",
        "authentication-results": `${TRUSTED_ID}; dmarc=pass header.from=example.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    const signals = compositeSignals(result.signals);
    expect(signals).toHaveLength(1);
    const signal = signals[0];
    expect(signal?.key).toBe("composite.alignedAuthenticationConfirmed");
    expect(signal?.severity).toBe("info");
    expect(signal?.data?.anyAlignedDkimPass).toBe(true);
    expect(signal?.data?.dmarcPass).toBe(true);
  });

  it("is NOT attacker-triggerable: a spoofer who cannot align gets no affirmation", () => {
    // The attacker controls evil.test but spoofs From example.com. They can stamp
    // their own untrusted header, but cannot align trusted auth to example.com, so
    // the mitigation withholds — the core safeguard against laundering a spoof.
    const result = analyzeWithComposites({
      headers: {
        from: "Example <notice@example.com>",
        "message-id": "<id@example.com>",
        "authentication-results": [
          "relay.evil.test; dmarc=pass header.from=example.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com",
        ],
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.authentication.anyAuthAligned).toBe(false);
    expect(
      compositeSignals(result.signals).map((s) => s.key),
    ).not.toContain("composite.alignedAuthenticationConfirmed");
  });

  it("withholds the affirmation when any consistency signal co-occurs", () => {
    // Aligned DKIM pass authenticates From, but the Reply-To diverges; the message
    // is not unambiguously clean, so it is not affirmed.
    const result = analyzeWithComposites({
      headers: {
        from: "Example <notice@example.com>",
        "message-id": "<id@example.com>",
        "reply-to": "<reply@evil.test>",
        "authentication-results": `${TRUSTED_ID}; dmarc=pass header.from=example.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.authentication.anyAuthAligned).toBe(true);
    const keys = compositeSignals(result.signals).map((s) => s.key);
    expect(keys).not.toContain("composite.alignedAuthenticationConfirmed");
  });

  it("withholds the affirmation when a co-occurring method failed", () => {
    // DKIM aligns (so anyAuthAligned is true) but SPF failed for the same From
    // domain; an auth-failure signal withholds the all-clear.
    const result = analyzeWithComposites({
      headers: {
        from: "Example <notice@example.com>",
        "message-id": "<id@example.com>",
        "return-path": "<bounce@example.com>",
        "authentication-results": `${TRUSTED_ID}; spf=fail smtp.mailfrom=example.com; dkim=pass header.d=example.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.authentication.anyAuthAligned).toBe(true);
    expect(
      compositeSignals(result.signals).map((s) => s.key),
    ).not.toContain("composite.alignedAuthenticationConfirmed");
  });
});

describe("runCompositeRules — separated API and trust recomputation", () => {
  const input: AnalyzeInput = {
    headers: {
      from: "Example <notice@example.com>",
      "message-id": "<spoof@evil.test>",
      "return-path": "<bounce@evil.test>",
      "authentication-results":
        "mx.example.net; dmarc=fail header.from=example.com; spf=fail smtp.mailfrom=evil.test; dkim=fail header.d=evil.test",
    },
  };

  it("recovers the spoof when trust is declared at rule time, matching analyzeMessage", () => {
    const metrics = extractMetrics(input);
    const baseSignals = runRules(metrics, { trustedAuthservIds: [TRUSTED_ID] });
    const composite = runCompositeRules(metrics, baseSignals, {
      trustedAuthservIds: [TRUSTED_ID],
    });
    expect(composite.map((s) => s.key)).toContain("composite.unauthenticatedFromSpoof");

    const viaAnalyze = analyzeMessage(
      { ...input, options: { trustedAuthservIds: [TRUSTED_ID] } },
      defaultRules,
      undefined,
      defaultCompositeRules,
    );
    expect(compositeSignals(viaAnalyze.signals)).toEqual(composite);
  });

  it("stays silent when the spoof-bearing authserv-id is untrusted at rule time", () => {
    const metrics = extractMetrics(input);
    const baseSignals = runRules(metrics, { trustedAuthservIds: ["other.example.org"] });
    const composite = runCompositeRules(metrics, baseSignals, {
      trustedAuthservIds: ["other.example.org"],
    });
    expect(composite.map((s) => s.key)).not.toContain("composite.unauthenticatedFromSpoof");
  });
});

describe("composite rules in isolation", () => {
  it("each evaluate is a pure function with stable identity", () => {
    expect(unauthenticatedFromSpoofRule.key).toBe("composite.unauthenticatedFromSpoof");
    expect(authenticatedDisplayNameSpoofRule.key).toBe(
      "composite.authenticatedDisplayNameSpoof",
    );
    expect(alignedAuthenticationConfirmedRule.key).toBe(
      "composite.alignedAuthenticationConfirmed",
    );
  });
});

describe("composite — serializable fixtures", () => {
  for (const fixture of [unauthSpoof, displayNameSpoof, confirmed]) {
    it(`matches fixture: ${fixture.description.slice(0, 48)}…`, () => {
      const result = analyzeMessage(
        fixture.input,
        defaultRules,
        undefined,
        defaultCompositeRules,
      );
      const roundTripped: AnalyzeResult = JSON.parse(JSON.stringify(result));
      expect(roundTripped).toEqual(fixture.expected);
    });
  }
});
