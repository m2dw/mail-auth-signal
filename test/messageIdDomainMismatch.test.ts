import { describe, expect, it } from "vitest";
import {
  analyzeMessage,
  extractDomainFromMailbox,
  extractDomainFromMessageId,
  extractMetrics,
  messageIdDomainMismatchRule,
} from "../src/index.js";
import type { AnalyzeInput, AnalyzeResult, Signal } from "../src/index.js";
import match from "./fixtures/messageid-domain-match.json" with { type: "json" };
import mismatch from "./fixtures/messageid-domain-mismatch.json" with { type: "json" };
import missing from "./fixtures/messageid-domain-missing.json" with { type: "json" };

const TRUSTED_ID = "mx.example.net";

/**
 * Build a message with the given From and Message-ID and a trusted, all-passing
 * Authentication-Results header so the other default rules stay silent and the
 * From-vs-Message-ID consistency signal is isolated.
 */
function message(from: string | null, messageId: string | null): AnalyzeInput {
  const headers: Record<string, string> = {
    "authentication-results": `${TRUSTED_ID}; dmarc=pass header.from=example.com; spf=pass smtp.mailfrom=example.com`,
  };
  if (from !== null) headers["from"] = from;
  if (messageId !== null) headers["message-id"] = messageId;
  return { headers, options: { trustedAuthservIds: [TRUSTED_ID] } };
}

/** The messageId.* consistency signals only (drops the Authentication-Results auth.* family). */
function mismatchSignals(result: AnalyzeResult): Signal[] {
  return result.signals.filter((signal) => signal.key.startsWith("messageId."));
}

describe("messageIdDomainMismatchRule — matching domains stay silent", () => {
  it("emits no signal when From and Message-ID domains are identical", () => {
    const result = analyzeMessage(message("Example <a@example.com>", "<id@example.com>"));
    expect(result.metrics.messageIdDomainMatchesFromDomain).toBe(true);
    expect(mismatchSignals(result)).toEqual([]);
  });

  it("normalizes casing before comparing (no false mismatch)", () => {
    const result = analyzeMessage(message("Example <a@Example.COM>", "<id@example.com>"));
    expect(result.metrics.fromDomain).toBe("example.com");
    expect(result.metrics.messageIdDomain).toBe("example.com");
    expect(result.metrics.messageIdDomainMatchesFromDomain).toBe(true);
    expect(mismatchSignals(result)).toEqual([]);
  });

  it("normalizes folded/whitespaced headers and a trailing dot before comparing", () => {
    const result = analyzeMessage(
      message("Example Sender\r\n <a@example.com.>", "  <id@example.com>  "),
    );
    expect(result.metrics.fromDomain).toBe("example.com");
    expect(result.metrics.messageIdDomain).toBe("example.com");
    expect(mismatchSignals(result)).toEqual([]);
  });
});

describe("messageIdDomainMismatchRule — mismatched domains", () => {
  it("emits one low-severity signal carrying both normalized domains", () => {
    const result = analyzeMessage(message("Example <a@example.com>", "<id@mailer.example.net>"));
    expect(result.metrics.messageIdDomainMatchesFromDomain).toBe(false);

    const signals = mismatchSignals(result);
    expect(signals).toHaveLength(1);
    expect(signals[0]).toEqual({
      key: "messageId.domainMismatch",
      category: "consistency",
      severity: "low",
      message: "Message-ID domain differs from the From domain.",
      data: {
        fromDomain: "example.com",
        messageIdDomain: "mailer.example.net",
        mismatchedDomains: ["mailer.example.net"],
      },
    });
  });

  it("treats a parent/subdomain pair as a mismatch (exact comparison only)", () => {
    const result = analyzeMessage(message("Example <a@example.com>", "<id@mail.example.com>"));
    expect(result.metrics.messageIdDomainMatchesFromDomain).toBe(false);
    expect(mismatchSignals(result)).toHaveLength(1);
  });
});

describe("messageIdDomainMismatchRule — missing input stays silent", () => {
  it("skips the comparison when From is absent", () => {
    const result = analyzeMessage(message(null, "<id@mailer.example.net>"));
    expect(result.metrics.fromDomain).toBeNull();
    expect(result.metrics.messageIdDomainMatchesFromDomain).toBeNull();
    expect(mismatchSignals(result)).toEqual([]);
  });

  it("skips the comparison when Message-ID is absent", () => {
    const result = analyzeMessage(message("Example <a@example.com>", null));
    expect(result.metrics.messageIdDomain).toBeNull();
    expect(result.metrics.messageIdDomainMatchesFromDomain).toBeNull();
    expect(mismatchSignals(result)).toEqual([]);
  });
});

describe("messageIdDomainMismatchRule — malformed input avoids noisy signals", () => {
  it("yields no domain (and no signal) for a From with no parseable address", () => {
    const result = analyzeMessage(message("Example Sender (no address here)", "<id@example.com>"));
    expect(result.metrics.fromDomain).toBeNull();
    expect(result.metrics.messageIdDomainMatchesFromDomain).toBeNull();
    expect(mismatchSignals(result)).toEqual([]);
  });

  it("yields no domain (and no signal) for a Message-ID with no '@'", () => {
    const result = analyzeMessage(message("Example <a@example.com>", "<no-at-sign-here>"));
    expect(result.metrics.messageIdDomain).toBeNull();
    expect(result.metrics.messageIdDomainMatchesFromDomain).toBeNull();
    expect(mismatchSignals(result)).toEqual([]);
  });

  it("ignores a dotless host (e.g. localhost) rather than reporting a mismatch", () => {
    const result = analyzeMessage(message("Example <a@example.com>", "<id@localhost>"));
    expect(result.metrics.messageIdDomain).toBeNull();
    expect(result.metrics.messageIdDomainMatchesFromDomain).toBeNull();
    expect(mismatchSignals(result)).toEqual([]);
  });

  it("resolves a multi-'@' Message-ID to its real trailing domain", () => {
    // Hardened extraction: the bogus middle '@' must not span into the domain.
    expect(extractDomainFromMessageId("<a@b@example.com>")).toBe("example.com");
    const result = analyzeMessage(message("Example <a@example.com>", "<a@b@example.com>"));
    expect(result.metrics.messageIdDomainMatchesFromDomain).toBe(true);
    expect(mismatchSignals(result)).toEqual([]);
  });

  it("does not fabricate a domain from a multi-'@' angle-addr mailbox", () => {
    expect(extractDomainFromMailbox("<a@b@example.com>")).toBeNull();
  });
});

describe("messageIdDomainMismatchRule — rule in isolation", () => {
  it("reads only the precomputed metric, emitting nothing when it is not false", () => {
    const quiet = extractMetrics(message("Example <a@example.com>", "<id@example.com>"));
    expect(messageIdDomainMismatchRule.evaluate({ metrics: quiet, options: {} })).toEqual([]);

    const noisy = extractMetrics(message("Example <a@example.com>", "<id@mailer.example.net>"));
    expect(messageIdDomainMismatchRule.evaluate({ metrics: noisy, options: {} })).toHaveLength(1);
  });
});

describe("messageIdDomainMismatchRule — serializable fixtures", () => {
  for (const fixture of [match, mismatch, missing]) {
    it(`matches fixture: ${fixture.description.slice(0, 48)}…`, () => {
      const result = analyzeMessage(fixture.input);
      const roundTripped: AnalyzeResult = JSON.parse(JSON.stringify(result));
      expect(roundTripped).toEqual(fixture.expected);
    });
  }
});
