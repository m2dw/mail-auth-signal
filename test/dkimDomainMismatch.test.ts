import { describe, expect, it } from "vitest";
import {
  analyzeMessage,
  dkimDomainMismatchRule,
  extractDkimSigningDomain,
  extractMetrics,
} from "../src/index.js";
import type { AnalyzeInput, AnalyzeResult, Signal } from "../src/index.js";
import match from "./fixtures/dkim-domain-match.json" with { type: "json" };
import mismatch from "./fixtures/dkim-domain-mismatch.json" with { type: "json" };
import mixed from "./fixtures/dkim-domain-mixed.json" with { type: "json" };

const TRUSTED_ID = "mx.example.net";

/**
 * Build a message with the given From and a single trusted Authentication-Results
 * header whose SPF smtp.mailfrom and Message-ID are From-aligned (so the other
 * default rules stay silent) plus an optional DKIM clause. `dkim` is the raw
 * method text, e.g. "dkim=pass header.d=example.com"; null omits DKIM entirely.
 */
function message(from: string | null, dkim: string | null): AnalyzeInput {
  const dkimClause = dkim === null ? "" : ` ${dkim};`;
  const headers: Record<string, string> = {
    "message-id": "<id@example.com>",
    "authentication-results": `${TRUSTED_ID}; dmarc=pass header.from=example.com; spf=pass smtp.mailfrom=example.com;${dkimClause}`,
  };
  if (from !== null) headers["from"] = from;
  return { headers, options: { trustedAuthservIds: [TRUSTED_ID] } };
}

/** The dkim.* consistency signals only (drops auth.* and authResults.*). */
function dkimSignals(result: AnalyzeResult): Signal[] {
  return result.signals.filter((signal) => signal.key.startsWith("dkim."));
}

describe("extractDkimSigningDomain", () => {
  it("reads a bare signing domain", () => {
    expect(extractDkimSigningDomain("example.com")).toBe("example.com");
  });

  it("normalizes casing, surrounding whitespace, and a trailing dot", () => {
    expect(extractDkimSigningDomain("  Example.COM.  ")).toBe("example.com");
  });

  it("returns null for a missing value", () => {
    expect(extractDkimSigningDomain(null)).toBeNull();
  });

  it("ignores a dotless host rather than fabricating a domain", () => {
    expect(extractDkimSigningDomain("localhost")).toBeNull();
  });

  it("rejects a value that carries a local part (header.d is a bare domain)", () => {
    expect(extractDkimSigningDomain("bounce@example.com")).toBeNull();
  });

  it("rejects a value with embedded whitespace or angle brackets", () => {
    expect(extractDkimSigningDomain("exa mple.com")).toBeNull();
    expect(extractDkimSigningDomain("<example.com>")).toBeNull();
  });

  it("does not pull a domain out of an RFC 5322 comment", () => {
    expect(extractDkimSigningDomain("(evil.test)")).toBeNull();
  });

  it("rejects a value carrying a stray paren rather than accepting it as a domain", () => {
    // A closing paren is outside the host charset, so a value like `evil.test)`
    // is rejected rather than accepted as a signing domain.
    expect(extractDkimSigningDomain("evil.test)")).toBeNull();
  });
});

describe("dkimDomainMismatchRule — aligned DKIM stays silent", () => {
  it("emits no signal when a passing DKIM header.d matches From", () => {
    const result = analyzeMessage(message("Example <a@example.com>", "dkim=pass header.d=example.com"));
    expect(result.metrics.dkimDomains).toEqual(["example.com"]);
    expect(result.metrics.dkimDomainMatchesFromDomain).toBe(true);
    expect(dkimSignals(result)).toEqual([]);
  });

  it("normalizes casing and a trailing dot before comparing (no false mismatch)", () => {
    const result = analyzeMessage(
      message("Example <a@Example.COM>", "dkim=pass header.d=EXAMPLE.com."),
    );
    expect(result.metrics.fromDomain).toBe("example.com");
    expect(result.metrics.dkimDomains).toEqual(["example.com"]);
    expect(result.metrics.dkimDomainMatchesFromDomain).toBe(true);
    expect(dkimSignals(result)).toEqual([]);
  });
});

describe("dkimDomainMismatchRule — mismatched signing domain", () => {
  it("emits one low-severity signal carrying the From and DKIM domains", () => {
    const result = analyzeMessage(message("Example <a@example.com>", "dkim=pass header.d=evil.test"));
    expect(result.metrics.dkimDomainMatchesFromDomain).toBe(false);

    const signals = dkimSignals(result);
    expect(signals).toEqual([
      {
        key: "dkim.domainMismatch",
        severity: "low",
        message: "DKIM header.d signing domain differs from the From domain.",
        data: {
          fromDomain: "example.com",
          dkimDomains: ["evil.test"],
          mismatchedDomains: ["evil.test"],
        },
      },
    ]);
  });

  it("treats a subdomain of From as a mismatch (exact comparison only)", () => {
    const result = analyzeMessage(message("Example <a@example.com>", "dkim=pass header.d=mail.example.com"));
    expect(result.metrics.dkimDomainMatchesFromDomain).toBe(false);
    expect(dkimSignals(result)).toHaveLength(1);
  });

  it("flags when only one of several passing DKIM signatures diverges from From", () => {
    const result = analyzeMessage({
      headers: {
        from: "Example <a@example.com>",
        "message-id": "<id@example.com>",
        "authentication-results": [
          "mx.example.net; dkim=pass header.d=example.com; dkim=pass header.d=evil.test",
        ],
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.dkimDomains).toEqual(["example.com", "evil.test"]);
    expect(result.metrics.dkimDomainMatchesFromDomain).toBe(false);

    const signals = dkimSignals(result);
    expect(signals).toHaveLength(1);
    expect(signals[0]?.data).toEqual({
      fromDomain: "example.com",
      dkimDomains: ["example.com", "evil.test"],
      mismatchedDomains: ["evil.test"],
    });
  });

  it("collects passing header.d across multiple Authentication-Results headers", () => {
    const result = analyzeMessage({
      headers: {
        from: "Example <a@example.com>",
        "message-id": "<id@example.com>",
        "authentication-results": [
          "mx.example.net; dkim=pass header.d=example.com",
          "mx.example.net; dkim=pass header.d=evil.test",
        ],
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.dkimDomains).toEqual(["example.com", "evil.test"]);
    expect(result.metrics.dkimDomainMatchesFromDomain).toBe(false);
    expect(dkimSignals(result)).toHaveLength(1);
  });
});

describe("dkimDomainMismatchRule — failed/error DKIM never creates an alignment verdict", () => {
  // A broken signature authenticates nothing, so its header.d must not enter the
  // comparison — neither as a false alignment nor as a fabricated mismatch.
  for (const result of ["fail", "temperror", "permerror", "neutral", "none"]) {
    it(`excludes a header.d from a dkim=${result} signature that matches From`, () => {
      const analysis = analyzeMessage(
        message("Example <a@example.com>", `dkim=${result} header.d=example.com`),
      );
      expect(analysis.metrics.dkimDomains).toEqual([]);
      expect(analysis.metrics.dkimDomainMatchesFromDomain).toBeNull();
      expect(dkimSignals(analysis)).toEqual([]);
    });

    it(`excludes a header.d from a dkim=${result} signature that differs from From (no noisy mismatch)`, () => {
      const analysis = analyzeMessage(
        message("Example <a@example.com>", `dkim=${result} header.d=evil.test`),
      );
      expect(analysis.metrics.dkimDomains).toEqual([]);
      expect(analysis.metrics.dkimDomainMatchesFromDomain).toBeNull();
      expect(dkimSignals(analysis)).toEqual([]);
    });
  }

  it("keeps only the passing signature when a pass and a fail share the message", () => {
    const result = analyzeMessage({
      headers: {
        from: "Example <a@example.com>",
        "message-id": "<id@example.com>",
        "authentication-results": [
          "mx.example.net; dkim=fail header.d=evil.test; dkim=pass header.d=example.com",
        ],
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.dkimDomains).toEqual(["example.com"]);
    expect(result.metrics.dkimDomainMatchesFromDomain).toBe(true);
    expect(dkimSignals(result)).toEqual([]);
  });
});

describe("dkimDomainMismatchRule — missing/malformed input stays silent", () => {
  it("skips the comparison when no DKIM result is present", () => {
    const result = analyzeMessage(message("Example <a@example.com>", null));
    expect(result.metrics.dkimDomains).toEqual([]);
    expect(result.metrics.dkimDomainMatchesFromDomain).toBeNull();
    expect(dkimSignals(result)).toEqual([]);
  });

  it("skips the comparison when a passing DKIM carries no header.d", () => {
    const result = analyzeMessage(message("Example <a@example.com>", "dkim=pass"));
    expect(result.metrics.dkimDomains).toEqual([]);
    expect(result.metrics.dkimDomainMatchesFromDomain).toBeNull();
    expect(dkimSignals(result)).toEqual([]);
  });

  it("skips the comparison when From is absent", () => {
    const result = analyzeMessage(message(null, "dkim=pass header.d=evil.test"));
    expect(result.metrics.fromDomain).toBeNull();
    expect(result.metrics.dkimDomains).toEqual(["evil.test"]);
    expect(result.metrics.dkimDomainMatchesFromDomain).toBeNull();
    expect(dkimSignals(result)).toEqual([]);
  });

  it("ignores a dotless header.d (e.g. localhost) rather than reporting a mismatch", () => {
    const result = analyzeMessage(message("Example <a@example.com>", "dkim=pass header.d=localhost"));
    expect(result.metrics.dkimDomains).toEqual([]);
    expect(result.metrics.dkimDomainMatchesFromDomain).toBeNull();
    expect(dkimSignals(result)).toEqual([]);
  });

  it("ignores a property-shaped comment after an aligned header.d (reads the real signer)", () => {
    // The comment carries its own `header.d=evil.test`, but comments are RFC 5322
    // CFWS and are stripped before parsing, so the real signing domain wins. It
    // aligns with From, so the rule stays silent.
    const result = analyzeMessage(
      message("Example <a@example.com>", "dkim=pass header.d=example.com (header.d=evil.test)"),
    );
    expect(result.metrics.dkimDomains).toEqual(["example.com"]);
    expect(result.metrics.dkimDomainMatchesFromDomain).toBe(true);
    expect(dkimSignals(result)).toEqual([]);
  });

  it("reads the real header.d, not a comment, when the comment hides the genuine mismatch", () => {
    // `header.d=evil.test (header.d=example.com )` is the attacker pattern: the
    // real signer is evil.test, but a comment supplies a From-aligned token.
    // Comments are stripped before parsing, so the genuine mismatch surfaces
    // rather than being suppressed by the comment's property-shaped text.
    const result = analyzeMessage(
      message("Example <a@example.com>", "dkim=pass header.d=evil.test (header.d=example.com )"),
    );
    expect(result.metrics.dkimDomains).toEqual(["evil.test"]);
    expect(result.metrics.dkimDomainMatchesFromDomain).toBe(false);
    expect(dkimSignals(result)).toHaveLength(1);
    expect(dkimSignals(result)[0]?.data).toEqual({
      fromDomain: "example.com",
      dkimDomains: ["evil.test"],
      mismatchedDomains: ["evil.test"],
    });
  });
});

describe("dkimDomainMismatchRule — trust is flagged separately, not folded into this hint", () => {
  it("still reports the mismatch for an untrusted source, alongside the untrusted-source signal", () => {
    // header.d is read from every header, trusted or not, so the consistency hint
    // fires; untrustedAuthservIdRule independently flags the forge-able source.
    const result = analyzeMessage({
      headers: {
        from: "Example <a@example.com>",
        "message-id": "<id@example.com>",
        "authentication-results": ["relay.evil.test; dkim=pass header.d=evil.test"],
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.dkimDomains).toEqual(["evil.test"]);
    expect(result.metrics.dkimDomainMatchesFromDomain).toBe(false);
    expect(dkimSignals(result)).toHaveLength(1);
    expect(result.signals.map((s) => s.key)).toContain("authResults.untrustedAuthservId");
  });
});

describe("dkimDomainMismatchRule — rule in isolation", () => {
  it("reads only the precomputed metric, emitting nothing when it is not false", () => {
    const quiet = extractMetrics(message("Example <a@example.com>", "dkim=pass header.d=example.com"));
    expect(dkimDomainMismatchRule.evaluate({ metrics: quiet, options: {} })).toEqual([]);

    const missingDkim = extractMetrics(message("Example <a@example.com>", null));
    expect(dkimDomainMismatchRule.evaluate({ metrics: missingDkim, options: {} })).toEqual([]);

    const noisy = extractMetrics(message("Example <a@example.com>", "dkim=pass header.d=evil.test"));
    expect(dkimDomainMismatchRule.evaluate({ metrics: noisy, options: {} })).toHaveLength(1);
  });
});

describe("dkimDomainMismatchRule — serializable fixtures", () => {
  for (const fixture of [match, mismatch, mixed]) {
    it(`matches fixture: ${fixture.description.slice(0, 48)}…`, () => {
      const result = analyzeMessage(fixture.input);
      const roundTripped: AnalyzeResult = JSON.parse(JSON.stringify(result));
      expect(roundTripped).toEqual(fixture.expected);
    });
  }
});
