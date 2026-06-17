import { describe, expect, it } from "vitest";
import {
  analyzeMessage,
  dmarcHeaderFromMismatchRule,
  extractDmarcHeaderFromDomain,
  extractMetrics,
  runRules,
} from "../src/index.js";
import type { AnalyzeInput, AnalyzeResult, Signal } from "../src/index.js";
import match from "./fixtures/dmarc-headerfrom-match.json" with { type: "json" };
import mismatch from "./fixtures/dmarc-headerfrom-mismatch.json" with { type: "json" };
import untrusted from "./fixtures/dmarc-headerfrom-untrusted.json" with { type: "json" };

const TRUSTED_ID = "mx.example.net";

/**
 * Build a message with the given From and a single trusted Authentication-Results
 * header whose SPF smtp.mailfrom, DKIM header.d, and Message-ID are From-aligned
 * (so the other default rules stay silent) plus an optional DMARC clause. `dmarc`
 * is the raw method text, e.g. "dmarc=pass header.from=example.com"; null omits
 * DMARC entirely.
 */
function message(from: string | null, dmarc: string | null): AnalyzeInput {
  const dmarcClause = dmarc === null ? "" : ` ${dmarc};`;
  const headers: Record<string, string> = {
    "message-id": "<id@example.com>",
    "authentication-results": `${TRUSTED_ID};${dmarcClause} spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com;`,
  };
  if (from !== null) headers["from"] = from;
  return { headers, options: { trustedAuthservIds: [TRUSTED_ID] } };
}

/** The dmarc.* consistency signals only (drops auth.* and authResults.*). */
function dmarcSignals(result: AnalyzeResult): Signal[] {
  return result.signals.filter((signal) => signal.key.startsWith("dmarc."));
}

describe("extractDmarcHeaderFromDomain", () => {
  it("reads a bare header.from domain", () => {
    expect(extractDmarcHeaderFromDomain("example.com")).toBe("example.com");
  });

  it("normalizes casing, surrounding whitespace, and a trailing dot", () => {
    expect(extractDmarcHeaderFromDomain("  Example.COM.  ")).toBe("example.com");
  });

  it("returns null for a missing value", () => {
    expect(extractDmarcHeaderFromDomain(null)).toBeNull();
  });

  it("ignores a dotless host rather than fabricating a domain", () => {
    expect(extractDmarcHeaderFromDomain("localhost")).toBeNull();
  });

  it("rejects a value that carries a local part (header.from is a bare domain)", () => {
    expect(extractDmarcHeaderFromDomain("notice@example.com")).toBeNull();
  });

  it("rejects a value with embedded whitespace or angle brackets", () => {
    expect(extractDmarcHeaderFromDomain("exa mple.com")).toBeNull();
    expect(extractDmarcHeaderFromDomain("<example.com>")).toBeNull();
  });

  it("does not pull a domain out of an RFC 5322 comment", () => {
    expect(extractDmarcHeaderFromDomain("(evil.test)")).toBeNull();
  });
});

describe("dmarcHeaderFromMismatchRule — aligned header.from stays silent", () => {
  it("emits no signal when a trusted, passing DMARC header.from matches From", () => {
    const result = analyzeMessage(message("Example <a@example.com>", "dmarc=pass header.from=example.com"));
    expect(result.metrics.dmarcHeaderFromDomains).toEqual(["example.com"]);
    expect(result.metrics.dmarcHeaderFromMatchesFromDomain).toBe(true);
    expect(dmarcSignals(result)).toEqual([]);
  });

  it("normalizes casing and a trailing dot before comparing (no false mismatch)", () => {
    const result = analyzeMessage(
      message("Example <a@Example.COM>", "dmarc=pass header.from=EXAMPLE.com."),
    );
    expect(result.metrics.fromDomain).toBe("example.com");
    expect(result.metrics.dmarcHeaderFromDomains).toEqual(["example.com"]);
    expect(result.metrics.dmarcHeaderFromMatchesFromDomain).toBe(true);
    expect(dmarcSignals(result)).toEqual([]);
  });
});

describe("dmarcHeaderFromMismatchRule — mismatched header.from", () => {
  it("emits one low-severity signal carrying the From and header.from domains", () => {
    const result = analyzeMessage(message("Example <a@example.com>", "dmarc=pass header.from=evil.test"));
    expect(result.metrics.dmarcHeaderFromMatchesFromDomain).toBe(false);

    const signals = dmarcSignals(result);
    expect(signals).toEqual([
      {
        key: "dmarc.headerFromMismatch",
        severity: "low",
        message: "DMARC header.from domain differs from the visible From domain.",
        data: {
          fromDomain: "example.com",
          dmarcHeaderFromDomains: ["evil.test"],
          mismatchedDomains: ["evil.test"],
        },
      },
    ]);
  });

  it("treats a subdomain of From as a mismatch (exact comparison only)", () => {
    const result = analyzeMessage(message("Example <a@example.com>", "dmarc=pass header.from=mail.example.com"));
    expect(result.metrics.dmarcHeaderFromMatchesFromDomain).toBe(false);
    expect(dmarcSignals(result)).toHaveLength(1);
  });

  it("flags when only one of several trusted+passing header.from values diverges from From", () => {
    const result = analyzeMessage({
      headers: {
        from: "Example <a@example.com>",
        "message-id": "<id@example.com>",
        "authentication-results": [
          "mx.example.net; dmarc=pass header.from=example.com; dmarc=pass header.from=evil.test",
        ],
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.dmarcHeaderFromDomains).toEqual(["example.com", "evil.test"]);
    expect(result.metrics.dmarcHeaderFromMatchesFromDomain).toBe(false);

    const signals = dmarcSignals(result);
    expect(signals).toHaveLength(1);
    expect(signals[0]?.data).toEqual({
      fromDomain: "example.com",
      dmarcHeaderFromDomains: ["example.com", "evil.test"],
      mismatchedDomains: ["evil.test"],
    });
  });

  it("collects header.from across multiple trusted Authentication-Results headers", () => {
    const result = analyzeMessage({
      headers: {
        from: "Example <a@example.com>",
        "message-id": "<id@example.com>",
        "authentication-results": [
          "mx.example.net; dmarc=pass header.from=example.com",
          "mx.example.net; dmarc=pass header.from=evil.test",
        ],
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.dmarcHeaderFromDomains).toEqual(["example.com", "evil.test"]);
    expect(result.metrics.dmarcHeaderFromMatchesFromDomain).toBe(false);
    expect(dmarcSignals(result)).toHaveLength(1);
  });
});

describe("dmarcHeaderFromMismatchRule — failed DMARC never creates a consistency verdict", () => {
  // A non-pass DMARC vouches for nothing, so its header.from must not enter the
  // comparison — neither a false alignment nor a fabricated mismatch.
  for (const result of ["fail", "temperror", "permerror", "none"]) {
    it(`excludes a header.from from a dmarc=${result} result that matches From`, () => {
      const analysis = analyzeMessage(
        message("Example <a@example.com>", `dmarc=${result} header.from=example.com`),
      );
      expect(analysis.metrics.dmarcHeaderFromDomains).toEqual([]);
      expect(analysis.metrics.dmarcHeaderFromMatchesFromDomain).toBeNull();
      expect(dmarcSignals(analysis)).toEqual([]);
    });

    it(`excludes a header.from from a dmarc=${result} result that differs from From (no noisy mismatch)`, () => {
      const analysis = analyzeMessage(
        message("Example <a@example.com>", `dmarc=${result} header.from=evil.test`),
      );
      expect(analysis.metrics.dmarcHeaderFromDomains).toEqual([]);
      expect(analysis.metrics.dmarcHeaderFromMatchesFromDomain).toBeNull();
      expect(dmarcSignals(analysis)).toEqual([]);
    });
  }

  it("keeps only the passing result when a pass and a fail share the message", () => {
    const result = analyzeMessage({
      headers: {
        from: "Example <a@example.com>",
        "message-id": "<id@example.com>",
        "authentication-results": [
          "mx.example.net; dmarc=fail header.from=evil.test; dmarc=pass header.from=example.com",
        ],
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.dmarcHeaderFromDomains).toEqual(["example.com"]);
    expect(result.metrics.dmarcHeaderFromMatchesFromDomain).toBe(true);
    expect(dmarcSignals(result)).toEqual([]);
  });
});

describe("dmarcHeaderFromMismatchRule — untrusted DMARC context is excluded entirely", () => {
  it("does not collect header.from from an untrusted header, even when it mismatches From", () => {
    // header.from is not cryptographic, so a forge-able untrusted header's value
    // is just the attacker's assertion; it must not manufacture a mismatch.
    const result = analyzeMessage({
      headers: {
        from: "Example <a@example.com>",
        "message-id": "<id@example.com>",
        "authentication-results": ["relay.evil.test; dmarc=pass header.from=evil.test"],
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.dmarcHeaderFromDomains).toEqual([]);
    expect(result.metrics.dmarcHeaderFromMatchesFromDomain).toBeNull();
    expect(dmarcSignals(result)).toEqual([]);
    expect(result.signals.map((s) => s.key)).toContain("authResults.untrustedAuthservId");
  });

  it("collects only the trusted header when a trusted and an untrusted header disagree", () => {
    const result = analyzeMessage({
      headers: {
        from: "Example <a@example.com>",
        "message-id": "<id@example.com>",
        "authentication-results": [
          "relay.evil.test; dmarc=pass header.from=attacker.test",
          "mx.example.net; dmarc=pass header.from=example.com",
        ],
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.dmarcHeaderFromDomains).toEqual(["example.com"]);
    expect(result.metrics.dmarcHeaderFromMatchesFromDomain).toBe(true);
    expect(dmarcSignals(result)).toEqual([]);
  });
});

describe("dmarcHeaderFromMismatchRule — missing/malformed input stays silent", () => {
  it("skips the comparison when no DMARC result is present", () => {
    const result = analyzeMessage(message("Example <a@example.com>", null));
    expect(result.metrics.dmarcHeaderFromDomains).toEqual([]);
    expect(result.metrics.dmarcHeaderFromMatchesFromDomain).toBeNull();
    expect(dmarcSignals(result)).toEqual([]);
  });

  it("skips the comparison when a passing DMARC carries no header.from", () => {
    const result = analyzeMessage(message("Example <a@example.com>", "dmarc=pass"));
    expect(result.metrics.dmarcHeaderFromDomains).toEqual([]);
    expect(result.metrics.dmarcHeaderFromMatchesFromDomain).toBeNull();
    expect(dmarcSignals(result)).toEqual([]);
  });

  it("skips the comparison when From is absent", () => {
    const result = analyzeMessage(message(null, "dmarc=pass header.from=evil.test"));
    expect(result.metrics.fromDomain).toBeNull();
    expect(result.metrics.dmarcHeaderFromDomains).toEqual(["evil.test"]);
    expect(result.metrics.dmarcHeaderFromMatchesFromDomain).toBeNull();
    expect(dmarcSignals(result)).toEqual([]);
  });

  it("ignores a dotless header.from (e.g. localhost) rather than reporting a mismatch", () => {
    const result = analyzeMessage(message("Example <a@example.com>", "dmarc=pass header.from=localhost"));
    expect(result.metrics.dmarcHeaderFromDomains).toEqual([]);
    expect(result.metrics.dmarcHeaderFromMatchesFromDomain).toBeNull();
    expect(dmarcSignals(result)).toEqual([]);
  });

  it("ignores a property-shaped comment after an aligned header.from (reads the real value)", () => {
    // The comment carries its own `header.from=evil.test`, but comments are RFC
    // 5322 CFWS and are stripped before parsing, so the real value wins. It aligns
    // with From, so the rule stays silent.
    const result = analyzeMessage(
      message("Example <a@example.com>", "dmarc=pass header.from=example.com (header.from=evil.test)"),
    );
    expect(result.metrics.dmarcHeaderFromDomains).toEqual(["example.com"]);
    expect(result.metrics.dmarcHeaderFromMatchesFromDomain).toBe(true);
    expect(dmarcSignals(result)).toEqual([]);
  });

  it("reads the real header.from, not a comment, when the comment hides the genuine mismatch", () => {
    // `header.from=evil.test (header.from=example.com )` is the attacker pattern:
    // the real evaluated domain is evil.test, but a comment supplies a From-aligned
    // token. Comments are stripped before parsing, so the genuine mismatch surfaces.
    const result = analyzeMessage(
      message("Example <a@example.com>", "dmarc=pass header.from=evil.test (header.from=example.com )"),
    );
    expect(result.metrics.dmarcHeaderFromDomains).toEqual(["evil.test"]);
    expect(result.metrics.dmarcHeaderFromMatchesFromDomain).toBe(false);
    expect(dmarcSignals(result)).toHaveLength(1);
    expect(dmarcSignals(result)[0]?.data).toEqual({
      fromDomain: "example.com",
      dmarcHeaderFromDomains: ["evil.test"],
      mismatchedDomains: ["evil.test"],
    });
  });
});

describe("dmarcHeaderFromMismatchRule — rule in isolation", () => {
  it("falls back to baked trust with no override, emitting nothing when From aligns", () => {
    const quiet = extractMetrics(message("Example <a@example.com>", "dmarc=pass header.from=example.com"));
    expect(dmarcHeaderFromMismatchRule.evaluate({ metrics: quiet, options: {} })).toEqual([]);

    const missingDmarc = extractMetrics(message("Example <a@example.com>", null));
    expect(dmarcHeaderFromMismatchRule.evaluate({ metrics: missingDmarc, options: {} })).toEqual([]);

    const noisy = extractMetrics(message("Example <a@example.com>", "dmarc=pass header.from=evil.test"));
    expect(dmarcHeaderFromMismatchRule.evaluate({ metrics: noisy, options: {} })).toHaveLength(1);
  });
});

describe("dmarcHeaderFromMismatchRule — trust declared at rule time (separated API)", () => {
  // A caller may extract metrics without trust and only declare trustedAuthservIds
  // when calling runRules. The rule must recompute trust then, matching what
  // analyzeMessage reports, rather than dropping the header.from baked as untrusted.
  const input = {
    headers: {
      from: "Example <a@example.com>",
      "message-id": "<id@example.com>",
      "authentication-results": "mx.example.net; dmarc=pass header.from=evil.test;",
    },
  };

  it("recovers a mismatch when trust is passed to runRules after metric extraction", () => {
    const metrics = extractMetrics(input);
    // Extracted without trust, so the baked metric drops the untrusted header.from.
    expect(metrics.dmarcHeaderFromDomains).toEqual([]);
    expect(metrics.dmarcHeaderFromMatchesFromDomain).toBeNull();

    const signals = runRules(metrics, { trustedAuthservIds: [TRUSTED_ID] });
    const dmarc = signals.filter((signal) => signal.key === "dmarc.headerFromMismatch");
    expect(dmarc).toEqual([
      {
        key: "dmarc.headerFromMismatch",
        severity: "low",
        message: "DMARC header.from domain differs from the visible From domain.",
        data: {
          fromDomain: "example.com",
          dmarcHeaderFromDomains: ["evil.test"],
          mismatchedDomains: ["evil.test"],
        },
      },
    ]);
  });

  it("matches what analyzeMessage reports for the same trusted input", () => {
    const viaSeparated = runRules(extractMetrics(input), { trustedAuthservIds: [TRUSTED_ID] });
    const viaAnalyze = analyzeMessage({ ...input, options: { trustedAuthservIds: [TRUSTED_ID] } }).signals;
    const onlyDmarc = (signals: Signal[]) => signals.filter((s) => s.key.startsWith("dmarc."));
    expect(onlyDmarc(viaSeparated)).toEqual(onlyDmarc(viaAnalyze));
  });

  it("stays silent when the header.from-bearing authserv-id is still untrusted at rule time", () => {
    const signals = runRules(extractMetrics(input), { trustedAuthservIds: ["other.example.org"] });
    expect(signals.filter((s) => s.key === "dmarc.headerFromMismatch")).toEqual([]);
  });
});

describe("dmarcHeaderFromMismatchRule — serializable fixtures", () => {
  for (const fixture of [match, mismatch, untrusted]) {
    it(`matches fixture: ${fixture.description.slice(0, 48)}…`, () => {
      const result = analyzeMessage(fixture.input);
      const roundTripped: AnalyzeResult = JSON.parse(JSON.stringify(result));
      expect(roundTripped).toEqual(fixture.expected);
    });
  }
});
