import { describe, expect, it } from "vitest";
import {
  alignedAuthenticationConfirmedRule,
  analyzeMessage,
  ARC_TRUSTED_FORWARDING_CONTEXT_KEY,
  authenticatedDisplayNameSpoofRule,
  defaultCompositeRules,
  defaultRules,
  delegatedDkimAlignedRouteConsistentRule,
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

  it("stays silent on a trusted aggregate DMARC pass for the From despite an identifier mismatch", () => {
    // The trusted verifier reports only an aggregate `dmarc=pass header.from=example.com`
    // (no SPF/DKIM method lines), so anyAuthAligned is vacuously false. A different
    // Message-ID host is a benign mismatch; because the trusted verifier vouched DMARC
    // passed for the visible From, this must not escalate to an unauthenticated spoof.
    const result = analyzeWithComposites({
      headers: {
        from: "Example <notice@example.com>",
        "message-id": "<id@mailer.example.net>",
        "authentication-results": `${TRUSTED_ID}; dmarc=pass header.from=example.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.authentication.anyAuthAligned).toBe(false);
    expect(result.metrics.authentication.dmarcPass).toBe(true);
    // The Message-ID mismatch is present as a base consistency signal...
    expect(result.signals.map((s) => s.key)).toContain("messageId.domainMismatch");
    // ...but the trusted aligned DMARC pass authenticates the From, so no composite.
    expect(
      compositeSignals(result.signals).map((s) => s.key),
    ).not.toContain("composite.unauthenticatedFromSpoof");
  });

  it("still fires when a trusted DMARC pass is for a different header.from than the visible From", () => {
    // A trusted DMARC pass whose header.from is not the visible From is itself a spoof
    // tell, not authentication of the From. With the visible From unauthenticated and an
    // authoritative Message-ID mismatch, the composite must still fire.
    const result = analyzeWithComposites({
      headers: {
        from: "Example <notice@example.com>",
        "message-id": "<spoof@evil.test>",
        "authentication-results": `${TRUSTED_ID}; dmarc=pass header.from=evil.test`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.authentication.anyAuthAligned).toBe(false);
    expect(
      compositeSignals(result.signals).map((s) => s.key),
    ).toContain("composite.unauthenticatedFromSpoof");
  });

  it("stays silent on a trusted aggregate DMARC pass for the From's organization (PSL-aware)", () => {
    // The trusted verifier reports only an aggregate `dmarc=pass header.from=example.co.jp`
    // for a visible From of `news.example.co.jp` — the relaxed-aligned subdomain case. The
    // SPF/DKIM-derived organizational.anyAuthAligned cannot see the bare DMARC pass, but the
    // verifier vouched DMARC passed for the same registrable domain, so with a resolver the
    // composite must not escalate the benign Message-ID-host mismatch to a spoof.
    const PSL: Record<string, string> = {
      "example.co.jp": "example.co.jp",
      "news.example.co.jp": "example.co.jp",
    };
    const input: AnalyzeInput = {
      headers: {
        from: "Example <notice@news.example.co.jp>",
        "message-id": "<id@mailer.example.net>",
        "authentication-results": `${TRUSTED_ID}; dmarc=pass header.from=example.co.jp`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    };
    const withResolver = analyzeMessage(input, defaultRules, {
      getRegistrableDomain: (domain) => PSL[domain] ?? null,
    }, defaultCompositeRules);
    expect(withResolver.metrics.authentication.anyAuthAligned).toBe(false);
    expect(withResolver.metrics.authentication.organizational.anyAuthAligned).toBe(false);
    expect(withResolver.metrics.authentication.organizational.dmarcPassAligned).toBe(true);
    expect(withResolver.signals.map((s) => s.key)).toContain("messageId.domainMismatch");
    expect(
      compositeSignals(withResolver.signals).map((s) => s.key),
    ).not.toContain("composite.unauthenticatedFromSpoof");

    // Without a resolver the organizational view degrades to exact comparison: the bare
    // aggregate pass is for a different exact domain, so dmarcPassAligned is false and the
    // composite still fires — confirming the suppression is resolver-driven, not unconditional.
    const noResolver = analyzeMessage(input, defaultRules, undefined, defaultCompositeRules);
    expect(noResolver.metrics.authentication.organizational.dmarcPassAligned).toBe(false);
    expect(
      compositeSignals(noResolver.signals).map((s) => s.key),
    ).toContain("composite.unauthenticatedFromSpoof");
  });

  it("omits forged untrusted-header signals from contributingSignals", () => {
    // An authoritative Message-ID mismatch triggers the composite. Alongside it, an
    // untrusted forged header injects `dkim=pass header.d=evil.test` (a forge-able
    // dkim.domainMismatch) and claims its own auth failure. Neither was accepted as
    // evidence, so neither key may appear in the rationale trace.
    const result = analyzeWithComposites({
      headers: {
        from: "Example <notice@example.com>",
        "message-id": "<spoof@evil.test>",
        "authentication-results": [
          `${TRUSTED_ID}; dmarc=fail header.from=example.com`,
          "relay.evil.test; dkim=pass header.d=evil.test; spf=fail smtp.mailfrom=evil.test",
        ],
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    const signal = compositeSignals(result.signals).find(
      (s) => s.key === "composite.unauthenticatedFromSpoof",
    );
    expect(signal).toBeDefined();
    const contributing = signal?.data?.contributingSignals as string[];
    // The authoritative message-header mismatch and the trusted DMARC failure justified it.
    expect(contributing).toContain("messageId.domainMismatch");
    expect(contributing).toContain("auth.method.failure");
    // The forge-able dkim.domainMismatch from the untrusted header is present as a base
    // signal but was rejected as evidence, so it must not be traced as a contributor.
    expect(result.signals.map((s) => s.key)).toContain("dkim.domainMismatch");
    expect(contributing).not.toContain("dkim.domainMismatch");
    // The untrusted smtp.mailfrom mismatch is likewise excluded.
    expect(contributing).not.toContain("smtpMailfrom.domainMismatch");
  });

  // Forwarding / list guardrail (issue #86). Legitimate forwarding reproduces the
  // "no aligned auth + divergent envelope" shape; a rule-time-trusted ARC pass
  // suppresses it, but only when the caller has opted into the ARC forwarding-trust
  // policy (arc=pass alone is attacker-sealable and proves only chain integrity).
  const forwardHeaders = {
    from: "Example <notice@example.com>",
    "message-id": "<id@example.com>",
    "return-path": "<bounce@forwarder.test>",
    "authentication-results": `${TRUSTED_ID}; arc=pass; spf=fail smtp.mailfrom=forwarder.test; dkim=fail header.d=example.com`,
  };
  const arcForwardingOptions = {
    trustedAuthservIds: [TRUSTED_ID],
    context: { [ARC_TRUSTED_FORWARDING_CONTEXT_KEY]: true },
  };

  it("suppresses on a trusted ARC pass when the caller opts into ARC forwarding trust", () => {
    // Rakumail/docomo-style forward: the visible From is the untouched author
    // (example.com), the relay rewrote the envelope (Return-Path / smtp.mailfrom now
    // name the forwarder) so SPF fails and nothing aligns — exactly the spoof shape —
    // but the recipient's trusted verifier validated the ARC chain (arc=pass) and the
    // caller has declared that its trusted arc=pass means validated trusted forwarding.
    const result = analyzeWithComposites({
      headers: forwardHeaders,
      options: arcForwardingOptions,
    });
    expect(result.metrics.authentication.anyAuthAligned).toBe(false);
    expect(
      compositeSignals(result.signals).map((s) => s.key),
    ).not.toContain("composite.unauthenticatedFromSpoof");

    // Drop only the arc=pass and the very same message fires — proving the
    // suppression is ARC-driven, not an accident of the other headers.
    const withoutArc = analyzeWithComposites({
      headers: {
        ...forwardHeaders,
        "authentication-results": `${TRUSTED_ID}; spf=fail smtp.mailfrom=forwarder.test; dkim=fail header.d=example.com`,
      },
      options: arcForwardingOptions,
    });
    expect(
      compositeSignals(withoutArc.signals).map((s) => s.key),
    ).toContain("composite.unauthenticatedFromSpoof");
  });

  it("does not suppress on a trusted ARC pass without the caller's opt-in (arc=pass is attacker-sealable)", () => {
    // Same trusted arc=pass, but the caller has NOT opted into the ARC
    // forwarding-trust policy. Because a direct spoofer can seal its own valid ARC
    // set and make a trusted verifier stamp arc=pass, an unconditional suppression
    // would be a one-header bypass — so the direct spoof must still fire.
    const result = analyzeWithComposites({
      headers: forwardHeaders,
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.authentication.anyAuthAligned).toBe(false);
    expect(
      compositeSignals(result.signals).map((s) => s.key),
    ).toContain("composite.unauthenticatedFromSpoof");
  });

  it("does not suppress on an untrusted ARC pass (attacker-forged forwarding claim)", () => {
    // The arc=pass is asserted by an untrusted relay the attacker controls, not by
    // the recipient's trusted verifier. It must not buy a bypass, so the direct spoof
    // still fires.
    const result = analyzeWithComposites({
      headers: {
        from: "Example <notice@example.com>",
        "message-id": "<id@example.com>",
        "return-path": "<bounce@evil.test>",
        "authentication-results": [
          `${TRUSTED_ID}; spf=fail smtp.mailfrom=evil.test; dkim=fail header.d=evil.test`,
          "relay.evil.test; arc=pass",
        ],
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(
      compositeSignals(result.signals).map((s) => s.key),
    ).toContain("composite.unauthenticatedFromSpoof");
  });

  it("does not suppress on forge-able List / Resent headers alone", () => {
    // List-Id and Resent-* are free-text headers an attacker can staple onto a spoof.
    // Without a trusted arc=pass they must not suppress the signal — otherwise any
    // spoofer gets a one-header bypass.
    const result = analyzeWithComposites({
      headers: {
        from: "Example <notice@example.com>",
        "message-id": "<spoof@evil.test>",
        "return-path": "<bounce@evil.test>",
        "list-id": "Newsletter <news.example.com>",
        "list-unsubscribe": "<mailto:unsub@evil.test>",
        "resent-from": "Forwarder <fwd@forwarder.test>",
        "authentication-results": `${TRUSTED_ID}; dmarc=fail header.from=example.com; spf=fail smtp.mailfrom=evil.test; dkim=fail header.d=evil.test`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    const signal = compositeSignals(result.signals).find(
      (s) => s.key === "composite.unauthenticatedFromSpoof",
    );
    expect(signal).toBeDefined();
    expect(signal?.severity).toBe("high");
  });

  it("absence of forwarding evidence does not suppress the direct spoof", () => {
    // No List/ARC/Resent context at all: the guard must be inert and the direct
    // unauthenticated From spoof must still fire at high severity.
    const result = analyzeWithComposites({
      headers: {
        from: "Example <notice@example.com>",
        "message-id": "<spoof@evil.test>",
        "return-path": "<bounce@evil.test>",
        "authentication-results": `${TRUSTED_ID}; dmarc=fail header.from=example.com; spf=fail smtp.mailfrom=evil.test; dkim=fail header.d=evil.test`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    const signal = compositeSignals(result.signals).find(
      (s) => s.key === "composite.unauthenticatedFromSpoof",
    );
    expect(signal?.severity).toBe("high");
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

  it("fires on an aligned DMARC-only pass (trusted aggregate authenticates the From)", () => {
    // The trusted verifier reports only an aggregate `dmarc=pass header.from=example.com`
    // (no SPF/DKIM method lines), so anyAuthAligned is vacuously false. DMARC still
    // only passes on an aligned identifier, so the From is authenticated and an
    // authenticated display-name spoof must be recognized here too.
    const result = analyzeWithComposites({
      headers: {
        from: '"security@paypal.com" <alerts@example.com>',
        "message-id": "<id@example.com>",
        "authentication-results": `${TRUSTED_ID}; dmarc=pass header.from=example.com`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.authentication.anyAuthAligned).toBe(false);
    const spoof = compositeSignals(result.signals).find(
      (s) => s.key === "composite.authenticatedDisplayNameSpoof",
    );
    expect(spoof?.severity).toBe("medium");
    expect(spoof?.data?.fromDomain).toBe("example.com");
    expect(spoof?.data?.mismatchedDomains).toEqual(["paypal.com"]);
  });

  it("fires on a relaxed-aligned subdomain From (DKIM header.d on the registrable domain, PSL-aware)", () => {
    // From `news.example.co.jp` with a trusted `dkim=pass header.d=example.co.jp` is
    // DMARC-relaxed authenticated for its organization, even though the exact-domain
    // anyAuthAligned reads the subdomain difference as unaligned. The borrowed display
    // name `security@paypal.com` must therefore still surface — the same message that
    // the unauthenticatedFromSpoof composite already treats as authenticated must not
    // slip past this authenticated display-name spoof.
    const PSL: Record<string, string> = {
      "example.co.jp": "example.co.jp",
      "news.example.co.jp": "example.co.jp",
    };
    const input: AnalyzeInput = {
      headers: {
        from: '"security@paypal.com" <alerts@news.example.co.jp>',
        "message-id": "<id@news.example.co.jp>",
        "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=example.co.jp`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    };
    const withResolver = analyzeMessage(input, defaultRules, {
      getRegistrableDomain: (domain) => PSL[domain] ?? null,
    }, defaultCompositeRules);
    // Exact alignment reads the subdomain signature as unaligned; the organizational
    // (relaxed) view recognizes it as authenticated.
    expect(withResolver.metrics.authentication.anyAuthAligned).toBe(false);
    expect(withResolver.metrics.authentication.organizational.anyAuthAligned).toBe(true);
    const spoof = compositeSignals(withResolver.signals).find(
      (s) => s.key === "composite.authenticatedDisplayNameSpoof",
    );
    expect(spoof?.severity).toBe("medium");
    expect(spoof?.data?.mismatchedDomains).toEqual(["paypal.com"]);
    // The same authenticated message must not also read as an unauthenticated spoof.
    expect(
      compositeSignals(withResolver.signals).map((s) => s.key),
    ).not.toContain("composite.unauthenticatedFromSpoof");

    // Without a resolver the organizational view degrades to exact comparison, so the
    // subdomain signature is unaligned and this gate stays shut — confirming the
    // recognition is resolver-driven, not unconditional.
    const noResolver = analyzeMessage(input, defaultRules, undefined, defaultCompositeRules);
    expect(noResolver.metrics.authentication.organizational.anyAuthAligned).toBe(false);
    expect(
      compositeSignals(noResolver.signals).map((s) => s.key),
    ).not.toContain("composite.authenticatedDisplayNameSpoof");
  });

  it("does not treat a trusted DMARC pass for a different header.from as authenticating", () => {
    // A trusted `dmarc=pass header.from=evil.test` does not authenticate the visible
    // From (example.com) — it is the dmarc.headerFromMismatch spoof tell, not a
    // positive-auth gate, so this composite stays silent.
    const result = analyzeWithComposites({
      headers: {
        from: '"security@paypal.com" <alerts@example.com>',
        "message-id": "<id@example.com>",
        "authentication-results": `${TRUSTED_ID}; dmarc=pass header.from=evil.test`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.authentication.anyAuthAligned).toBe(false);
    expect(
      compositeSignals(result.signals).map((s) => s.key),
    ).not.toContain("composite.authenticatedDisplayNameSpoof");
  });

  it("does not treat an untrusted DMARC-only pass as authenticating", () => {
    // An attacker can stamp an untrusted aggregate `dmarc=pass header.from=example.com`,
    // so it must not open this positive-auth gate.
    const result = analyzeWithComposites({
      headers: {
        from: '"security@paypal.com" <alerts@example.com>',
        "message-id": "<id@example.com>",
        "authentication-results": "relay.evil.test; dmarc=pass header.from=example.com",
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.authentication.anyAuthAligned).toBe(false);
    expect(
      compositeSignals(result.signals).map((s) => s.key),
    ).not.toContain("composite.authenticatedDisplayNameSpoof");
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

  // The ARC forwarding guard must resolve trust the same rule-time way the rest of
  // the composite does. messageScopedMetrics recomputes metrics.authentication for
  // rule-time trust but does NOT rewrite metrics.authenticationResults[].trusted, so
  // a guard reading the stale extraction-time flag would disagree with analyzeMessage
  // through the split API.
  const arcForwardInput: AnalyzeInput = {
    headers: {
      from: "Example <notice@example.com>",
      "message-id": "<id@example.com>",
      "return-path": "<bounce@forwarder.test>",
      "authentication-results": `${TRUSTED_ID}; arc=pass; spf=fail smtp.mailfrom=forwarder.test; dkim=fail header.d=example.com`,
    },
  };

  it("resolves ARC forwarding trust at rule time, not from the extracted header.trusted flag", () => {
    // Extract without declaring trust: every header gets trusted=false baked in.
    const metrics = extractMetrics(arcForwardInput);
    expect(metrics.authenticationResults.every((h) => h.trusted === false)).toBe(true);

    // Declare trust and the ARC opt-in at rule time. Even though the extracted
    // header.trusted is stale (false), the guard resolves trust from the rule-time
    // options and suppresses, matching analyzeMessage.
    const ruleTimeOptions = {
      trustedAuthservIds: [TRUSTED_ID],
      context: { [ARC_TRUSTED_FORWARDING_CONTEXT_KEY]: true },
    };
    const baseSignals = runRules(metrics, ruleTimeOptions);
    const composite = runCompositeRules(metrics, baseSignals, ruleTimeOptions);
    expect(composite.map((s) => s.key)).not.toContain("composite.unauthenticatedFromSpoof");

    const viaAnalyze = analyzeMessage(
      { ...arcForwardInput, options: ruleTimeOptions },
      defaultRules,
      undefined,
      defaultCompositeRules,
    );
    expect(compositeSignals(viaAnalyze.signals)).toEqual(composite);
  });

  it("does not let a stale extracted trusted flag activate the ARC guard when that id is untrusted at rule time", () => {
    // Two AR headers: an ARC-bearing header from "arc.example" and a sender-auth
    // header from TRUSTED_ID whose trusted, passing/failing SPF supplies the spoof
    // basis. Extraction trusts both, so arc.example's header.trusted is baked true.
    const splitInput: AnalyzeInput = {
      headers: {
        from: "Example <notice@example.com>",
        "message-id": "<id@example.com>",
        "return-path": "<bounce@forwarder.test>",
        "authentication-results": [
          "arc.example; arc=pass",
          `${TRUSTED_ID}; spf=fail smtp.mailfrom=forwarder.test; dkim=fail header.d=example.com`,
        ],
      },
    };
    const metrics = extractMetrics({
      ...splitInput,
      options: { trustedAuthservIds: ["arc.example", TRUSTED_ID] },
    });
    const arcHeader = metrics.authenticationResults.find((h) => h.authservId === "arc.example");
    expect(arcHeader?.trusted).toBe(true);

    // At rule time only TRUSTED_ID is trusted — arc.example is dropped — while the
    // caller opts into ARC forwarding trust. The ARC-bearing header is no longer
    // trusted for this evaluation, so the stale baked flag must not activate the
    // guard: the spoof still fires. (A guard reading header.trusted would suppress.)
    const ruleTimeOptions = {
      trustedAuthservIds: [TRUSTED_ID],
      context: { [ARC_TRUSTED_FORWARDING_CONTEXT_KEY]: true },
    };
    const baseSignals = runRules(metrics, ruleTimeOptions);
    const composite = runCompositeRules(metrics, baseSignals, ruleTimeOptions);
    expect(composite.map((s) => s.key)).toContain("composite.unauthenticatedFromSpoof");

    const viaAnalyze = analyzeMessage(
      { ...splitInput, options: ruleTimeOptions },
      defaultRules,
      undefined,
      defaultCompositeRules,
    );
    expect(compositeSignals(viaAnalyze.signals)).toEqual(composite);
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
    expect(delegatedDkimAlignedRouteConsistentRule.key).toBe(
      "composite.delegatedDkimAlignedRouteConsistent",
    );
  });
});

describe("composite.delegatedDkimAlignedRouteConsistent", () => {
  // Shared base: From-aligned DKIM pass, delegated ESP envelope (smtp.mailfrom
  // is the ESP's domain, not the From domain), route-consistent Message-ID.
  const ESP_DOMAIN = "esp.example.net";
  const FROM_DOMAIN = "newsletter.example.com";

  function makeInput(extra: Record<string, string>): AnalyzeInput {
    return {
      headers: {
        from: `Sender <news@${FROM_DOMAIN}>`,
        "message-id": `<abc123@${ESP_DOMAIN}>`,
        "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=${FROM_DOMAIN}; spf=pass smtp.mailfrom=bounce@${ESP_DOMAIN}`,
        ...extra,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    };
  }

  it("fires info for a legitimate delegated newsletter with List headers", () => {
    const input = makeInput({ "list-id": `<news.${FROM_DOMAIN}>` });
    const result = analyzeWithComposites(input);
    const keys = compositeSignals(result.signals).map((s) => s.key);
    expect(keys).toContain("composite.delegatedDkimAlignedRouteConsistent");
  });

  it("fires for List-Unsubscribe as well", () => {
    const input = makeInput({ "list-unsubscribe": `<https://esp.example.net/unsub>` });
    const result = analyzeWithComposites(input);
    const keys = compositeSignals(result.signals).map((s) => s.key);
    expect(keys).toContain("composite.delegatedDkimAlignedRouteConsistent");
  });

  it("stays silent without List headers — disposable-domain abuse surface", () => {
    // Same routing pattern but no list headers → should NOT fire.
    const input = makeInput({});
    const result = analyzeWithComposites(input);
    const keys = compositeSignals(result.signals).map((s) => s.key);
    expect(keys).not.toContain("composite.delegatedDkimAlignedRouteConsistent");
  });

  it("stays silent when smtp.mailfrom matches From domain (no delegation)", () => {
    // No SPF mismatch → not a delegated sender pattern.
    const input: AnalyzeInput = {
      headers: {
        from: `Sender <news@${FROM_DOMAIN}>`,
        "message-id": `<abc123@${FROM_DOMAIN}>`,
        "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=${FROM_DOMAIN}; spf=pass smtp.mailfrom=bounce@${FROM_DOMAIN}`,
        "list-id": `<news.${FROM_DOMAIN}>`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    };
    const result = analyzeWithComposites(input);
    const keys = compositeSignals(result.signals).map((s) => s.key);
    expect(keys).not.toContain("composite.delegatedDkimAlignedRouteConsistent");
  });

  it("stays silent when trusted-pass SPF matches From even if a failed SPF line creates an apparent mismatch", () => {
    // The authenticated (trusted, passing) SPF smtp.mailfrom is the From domain,
    // meaning there is no real delegation. A failed SPF record with a different
    // domain would make smtpMailfromDomainMatchesFromDomain=false, which must not
    // be enough to trigger the mitigation.
    const input: AnalyzeInput = {
      headers: {
        from: `Sender <news@${FROM_DOMAIN}>`,
        "message-id": `<abc123@${ESP_DOMAIN}>`,
        "authentication-results": [
          `${TRUSTED_ID}; spf=pass smtp.mailfrom=bounce@${FROM_DOMAIN}; dkim=pass header.d=${FROM_DOMAIN}`,
          `${TRUSTED_ID}; spf=fail smtp.mailfrom=bounce@${ESP_DOMAIN}`,
        ].join("\r\n\t"),
        "list-id": `<news.${FROM_DOMAIN}>`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    };
    const result = analyzeWithComposites(input);
    const keys = compositeSignals(result.signals).map((s) => s.key);
    expect(keys).not.toContain("composite.delegatedDkimAlignedRouteConsistent");
  });

  it("stays silent without aligned DKIM pass", () => {
    // DKIM fails → no cryptographic evidence of From-domain authority.
    const input: AnalyzeInput = {
      headers: {
        from: `Sender <news@${FROM_DOMAIN}>`,
        "message-id": `<abc123@${ESP_DOMAIN}>`,
        "authentication-results": `${TRUSTED_ID}; dkim=fail header.d=${FROM_DOMAIN}; spf=pass smtp.mailfrom=bounce@${ESP_DOMAIN}`,
        "list-id": `<news.${FROM_DOMAIN}>`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    };
    const result = analyzeWithComposites(input);
    const keys = compositeSignals(result.signals).map((s) => s.key);
    expect(keys).not.toContain("composite.delegatedDkimAlignedRouteConsistent");
  });

  it("stays silent when Message-ID domain is unrelated to smtp.mailfrom", () => {
    // Message-ID from a third domain → route inconsistency → no mitigation.
    const input: AnalyzeInput = {
      headers: {
        from: `Sender <news@${FROM_DOMAIN}>`,
        "message-id": `<abc123@unrelated.example.org>`,
        "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=${FROM_DOMAIN}; spf=pass smtp.mailfrom=bounce@${ESP_DOMAIN}`,
        "list-id": `<news.${FROM_DOMAIN}>`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    };
    const result = analyzeWithComposites(input);
    const keys = compositeSignals(result.signals).map((s) => s.key);
    expect(keys).not.toContain("composite.delegatedDkimAlignedRouteConsistent");
  });

  it("spam-like self-signed route-consistent mail cannot obtain the mitigation without List headers", () => {
    // A disposable-domain spammer controls spam.test, produces aligned DKIM, and
    // stamps a matching Message-ID — but sends no list headers.
    const input: AnalyzeInput = {
      headers: {
        from: `Sender <info@spam.test>`,
        "message-id": `<xyz@spam.test>`,
        "authentication-results": `${TRUSTED_ID}; dkim=pass header.d=spam.test; spf=pass smtp.mailfrom=bounce@spam-infra.test`,
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    };
    // smtp.mailfrom matches From (no mismatch) → silent for that reason too,
    // but the key point is the List header guard.
    const result = analyzeWithComposites(input);
    const keys = compositeSignals(result.signals).map((s) => s.key);
    expect(keys).not.toContain("composite.delegatedDkimAlignedRouteConsistent");
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
