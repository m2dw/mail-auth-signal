import { describe, expect, it } from "vitest";
import {
  analyzeMessage,
  extractDomainsFromMailboxList,
  extractMetrics,
  replyToDomainMismatchRule,
} from "../src/index.js";
import type { AnalyzeInput, AnalyzeResult, Signal } from "../src/index.js";
import match from "./fixtures/replyto-domain-match.json" with { type: "json" };
import mismatch from "./fixtures/replyto-domain-mismatch.json" with { type: "json" };
import missing from "./fixtures/replyto-domain-missing.json" with { type: "json" };

const TRUSTED_ID = "mx.example.net";

/**
 * Build a message with the given From and Reply-To and a trusted, all-passing
 * Authentication-Results header (plus a From-aligned Message-ID) so the other
 * default rules stay silent and the From-vs-Reply-To consistency signal is
 * isolated. Reply-To accepts a string or an array of header values to exercise
 * repeated headers; null omits the header entirely.
 */
function message(from: string | null, replyTo: string | string[] | null): AnalyzeInput {
  const headers: Record<string, string | string[]> = {
    "message-id": "<id@example.com>",
    "authentication-results": `${TRUSTED_ID}; dmarc=pass header.from=example.com; spf=pass smtp.mailfrom=example.com`,
  };
  if (from !== null) headers["from"] = from;
  if (replyTo !== null) headers["reply-to"] = replyTo;
  return { headers, options: { trustedAuthservIds: [TRUSTED_ID] } };
}

/** The replyTo.* consistency signals only (drops auth.* and authResults.*). */
function replyToSignals(result: AnalyzeResult): Signal[] {
  return result.signals.filter((signal) => signal.key.startsWith("replyTo."));
}

describe("replyToDomainMismatchRule — matching domains stay silent", () => {
  it("emits no signal when From and Reply-To domains are identical", () => {
    const result = analyzeMessage(message("Example <a@example.com>", "Support <s@example.com>"));
    expect(result.metrics.replyToDomains).toEqual(["example.com"]);
    expect(result.metrics.replyToDomainMatchesFromDomain).toBe(true);
    expect(replyToSignals(result)).toEqual([]);
  });

  it("normalizes casing before comparing (no false mismatch)", () => {
    const result = analyzeMessage(message("Example <a@Example.COM>", "Support <s@EXAMPLE.com>"));
    expect(result.metrics.fromDomain).toBe("example.com");
    expect(result.metrics.replyToDomains).toEqual(["example.com"]);
    expect(result.metrics.replyToDomainMatchesFromDomain).toBe(true);
    expect(replyToSignals(result)).toEqual([]);
  });

  it("normalizes folded/whitespaced headers and a trailing dot before comparing", () => {
    const result = analyzeMessage(
      message("Example Sender\r\n <a@example.com.>", "  Support <s@example.com>  "),
    );
    expect(result.metrics.fromDomain).toBe("example.com");
    expect(result.metrics.replyToDomains).toEqual(["example.com"]);
    expect(replyToSignals(result)).toEqual([]);
  });

  it("stays silent when every mailbox in a multi-mailbox Reply-To matches From", () => {
    const result = analyzeMessage(
      message("Example <a@example.com>", "One <one@example.com>, Two <two@example.com>"),
    );
    // Repeated matching domains are deduplicated to a single entry.
    expect(result.metrics.replyToDomains).toEqual(["example.com"]);
    expect(result.metrics.replyToDomainMatchesFromDomain).toBe(true);
    expect(replyToSignals(result)).toEqual([]);
  });
});

describe("replyToDomainMismatchRule — mismatched domains", () => {
  it("emits one low-severity signal carrying the From and Reply-To domains", () => {
    const result = analyzeMessage(message("Example <a@example.com>", "Billing <b@evil.test>"));
    expect(result.metrics.replyToDomainMatchesFromDomain).toBe(false);

    const signals = replyToSignals(result);
    expect(signals).toHaveLength(1);
    expect(signals[0]).toEqual({
      key: "replyTo.domainMismatch",
      severity: "low",
      message: "Reply-To domain differs from the From domain.",
      data: {
        fromDomain: "example.com",
        replyToDomains: ["evil.test"],
        mismatchedDomains: ["evil.test"],
      },
    });
  });

  it("treats a parent/subdomain pair as a mismatch (exact comparison only)", () => {
    const result = analyzeMessage(message("Example <a@example.com>", "Support <s@mail.example.com>"));
    expect(result.metrics.replyToDomainMatchesFromDomain).toBe(false);
    expect(replyToSignals(result)).toHaveLength(1);
  });

  it("flags when only one of several Reply-To mailboxes diverges from From", () => {
    const result = analyzeMessage(
      message("Example <a@example.com>", "Real <r@example.com>, Lure <l@evil.test>"),
    );
    expect(result.metrics.replyToDomains).toEqual(["example.com", "evil.test"]);
    expect(result.metrics.replyToDomainMatchesFromDomain).toBe(false);

    const signals = replyToSignals(result);
    expect(signals).toHaveLength(1);
    expect(signals[0]?.data).toEqual({
      fromDomain: "example.com",
      replyToDomains: ["example.com", "evil.test"],
      mismatchedDomains: ["evil.test"],
    });
  });

  it("collects domains across repeated Reply-To headers", () => {
    const result = analyzeMessage(
      message("Example <a@example.com>", ["a@example.com", "b@evil.test"]),
    );
    expect(result.metrics.replyToDomains).toEqual(["example.com", "evil.test"]);
    expect(result.metrics.replyToDomainMatchesFromDomain).toBe(false);
    expect(replyToSignals(result)).toHaveLength(1);
  });
});

describe("replyToDomainMismatchRule — missing input stays silent", () => {
  it("skips the comparison when Reply-To is absent (no noisy signal)", () => {
    const result = analyzeMessage(message("Example <a@example.com>", null));
    expect(result.metrics.replyToDomains).toEqual([]);
    expect(result.metrics.replyToDomainMatchesFromDomain).toBeNull();
    expect(replyToSignals(result)).toEqual([]);
  });

  it("skips the comparison when From is absent", () => {
    const result = analyzeMessage(message(null, "Billing <b@evil.test>"));
    expect(result.metrics.fromDomain).toBeNull();
    expect(result.metrics.replyToDomains).toEqual(["evil.test"]);
    expect(result.metrics.replyToDomainMatchesFromDomain).toBeNull();
    expect(replyToSignals(result)).toEqual([]);
  });
});

describe("replyToDomainMismatchRule — malformed input avoids noisy signals", () => {
  it("yields no domain (and no signal) for a Reply-To with no parseable address", () => {
    const result = analyzeMessage(message("Example <a@example.com>", "Support (no address here)"));
    expect(result.metrics.replyToDomains).toEqual([]);
    expect(result.metrics.replyToDomainMatchesFromDomain).toBeNull();
    expect(replyToSignals(result)).toEqual([]);
  });

  it("ignores a dotless host (e.g. localhost) rather than reporting a mismatch", () => {
    const result = analyzeMessage(message("Example <a@example.com>", "Support <s@localhost>"));
    expect(result.metrics.replyToDomains).toEqual([]);
    expect(result.metrics.replyToDomainMatchesFromDomain).toBeNull();
    expect(replyToSignals(result)).toEqual([]);
  });

  it("drops only the malformed mailbox, keeping a valid sibling's domain", () => {
    const result = analyzeMessage(
      message("Example <a@example.com>", "broken-no-at, Lure <l@evil.test>"),
    );
    expect(result.metrics.replyToDomains).toEqual(["evil.test"]);
    expect(result.metrics.replyToDomainMatchesFromDomain).toBe(false);
    expect(replyToSignals(result)).toHaveLength(1);
  });

  it("does not fabricate a domain from a multi-'@' angle-addr mailbox", () => {
    expect(extractDomainsFromMailboxList("<a@b@example.com>")).toEqual([]);
  });

  it("does not let a comma inside a quoted display name fabricate a domain", () => {
    // "Doe, John" splits into a `"Doe` fragment (no address) and a ` John" <…>`
    // fragment that still resolves to the real domain.
    expect(extractDomainsFromMailboxList('"Doe, John" <john@example.com>')).toEqual(["example.com"]);
  });

  it("does not extract an email-like fragment from a quoted display name with a comma", () => {
    // The quoted display name embeds both an email-like string and a comma. A
    // naive comma split would yield a `"billing@evil.test` fragment that
    // resolves to evil.test, fabricating a mismatch even though the only real
    // reply target is alice@example.com.
    expect(
      extractDomainsFromMailboxList('"billing@evil.test, Alice" <alice@example.com>'),
    ).toEqual(["example.com"]);
  });

  it("emits no mismatch signal for a quoted-comma display name that hides an email", () => {
    const result = analyzeMessage(
      message("Example <a@example.com>", '"billing@evil.test, Alice" <alice@example.com>'),
    );
    expect(result.metrics.replyToDomains).toEqual(["example.com"]);
    expect(result.metrics.replyToDomainMatchesFromDomain).toBe(true);
    expect(replyToSignals(result)).toEqual([]);
  });

  it("honors a backslash-escaped quote inside a display name", () => {
    // The escaped quote must not close the quoted string early, so the embedded
    // comma stays inside the display name and no bogus domain is extracted.
    expect(
      extractDomainsFromMailboxList('"a\\" b@evil.test, c" <real@example.com>'),
    ).toEqual(["example.com"]);
  });
});

describe("replyToDomainMismatchRule — rule in isolation", () => {
  it("reads only the precomputed metric, emitting nothing when it is not false", () => {
    const quiet = extractMetrics(message("Example <a@example.com>", "Support <s@example.com>"));
    expect(replyToDomainMismatchRule.evaluate({ metrics: quiet, options: {} })).toEqual([]);

    const missingReplyTo = extractMetrics(message("Example <a@example.com>", null));
    expect(replyToDomainMismatchRule.evaluate({ metrics: missingReplyTo, options: {} })).toEqual([]);

    const noisy = extractMetrics(message("Example <a@example.com>", "Billing <b@evil.test>"));
    expect(replyToDomainMismatchRule.evaluate({ metrics: noisy, options: {} })).toHaveLength(1);
  });
});

describe("replyToDomainMismatchRule — serializable fixtures", () => {
  for (const fixture of [match, mismatch, missing]) {
    it(`matches fixture: ${fixture.description.slice(0, 48)}…`, () => {
      const result = analyzeMessage(fixture.input);
      const roundTripped: AnalyzeResult = JSON.parse(JSON.stringify(result));
      expect(roundTripped).toEqual(fixture.expected);
    });
  }
});
