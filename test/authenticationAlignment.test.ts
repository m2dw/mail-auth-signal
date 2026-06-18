import { describe, expect, it } from "vitest";
import {
  analyzeMessage,
  collectAuthenticationAlignment,
  extractMetrics,
  parseAuthenticationResults,
  runRules,
} from "../src/index.js";
import type { AnalyzeInput, AnalyzeResult, AuthenticationAlignment, Rule } from "../src/index.js";
import headeriFixture from "./fixtures/auth-alignment-headeri.json" with { type: "json" };

const TRUSTED_ID = "mx.example.net";

/** A message with the given From and a single trusted Authentication-Results header. */
function trustedMessage(from: string | null, authResults: string): AnalyzeInput {
  const headers: Record<string, string> = {
    "message-id": "<id@example.com>",
    "authentication-results": authResults,
  };
  if (from !== null) headers["from"] = from;
  return { headers, options: { trustedAuthservIds: [TRUSTED_ID] } };
}

const FROM = "Example <a@example.com>";

describe("authentication metrics — Layer 1 raw results are faithful and trust-tagged", () => {
  it("records every DMARC/SPF/DKIM result with its identifiers and trust", () => {
    const { authentication } = extractMetrics(
      trustedMessage(
        FROM,
        `${TRUSTED_ID}; dmarc=pass header.from=example.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com header.i=@example.com`,
      ),
    );

    expect(authentication.dmarcResults).toEqual([
      { result: "pass", headerFrom: "example.com", trusted: true },
    ]);
    expect(authentication.spfResults).toEqual([
      { result: "pass", smtpMailfrom: "example.com", trusted: true },
    ]);
    expect(authentication.dkimResults).toEqual([
      { result: "pass", headerD: "example.com", headerI: "example.com", trusted: true },
    ]);
  });

  it("normalizes a DKIM header.i AUID (user@domain or @domain) to its domain", () => {
    const userForm = extractMetrics(
      trustedMessage(FROM, `${TRUSTED_ID}; dkim=pass header.d=example.com header.i=news@mail.example.com`),
    );
    expect(userForm.authentication.dkimResults[0]?.headerI).toBe("mail.example.com");

    const bareAt = extractMetrics(
      trustedMessage(FROM, `${TRUSTED_ID}; dkim=pass header.d=example.com header.i=@example.com`),
    );
    expect(bareAt.authentication.dkimResults[0]?.headerI).toBe("example.com");
  });

  it("keeps non-pass results in Layer 1 (a softfail/none/fail is still reported, just not aligned)", () => {
    const { authentication } = extractMetrics(
      trustedMessage(FROM, `${TRUSTED_ID}; spf=softfail smtp.mailfrom=fwd.example.org; dkim=neutral header.d=example.com`),
    );
    expect(authentication.spfResults).toEqual([
      { result: "softfail", smtpMailfrom: "fwd.example.org", trusted: true },
    ]);
    expect(authentication.dkimResults).toEqual([
      { result: "neutral", headerD: "example.com", headerI: null, trusted: true },
    ]);
  });

  it("counts trusted vs untrusted Authentication-Results headers", () => {
    const { authentication } = extractMetrics({
      headers: {
        from: FROM,
        "authentication-results": [
          `${TRUSTED_ID}; dmarc=pass header.from=example.com`,
          "relay.evil.test; dmarc=pass header.from=evil.test",
        ],
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });

    expect(authentication.trustedHeaderCount).toBe(1);
    expect(authentication.untrustedHeaderCount).toBe(1);
    // Both results are recorded, each tagged with the trust of its source header.
    expect(authentication.dmarcResults).toEqual([
      { result: "pass", headerFrom: "example.com", trusted: true },
      { result: "pass", headerFrom: "evil.test", trusted: false },
    ]);
  });
});

describe("authentication metrics — Layer 2 alignment on a clean message", () => {
  it("reports every flag true when SPF, DKIM, and DMARC pass and align with From", () => {
    const { authentication } = extractMetrics(
      trustedMessage(
        FROM,
        `${TRUSTED_ID}; dmarc=pass header.from=example.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com`,
      ),
    );

    expect(authentication.spfAlignedWithFrom).toBe(true);
    expect(authentication.dkimAlignedWithFrom).toBe(true);
    expect(authentication.anyAlignedSpfPass).toBe(true);
    expect(authentication.anyAlignedDkimPass).toBe(true);
    expect(authentication.dmarcPass).toBe(true);
    expect(authentication.anyAuthAligned).toBe(true);
  });
});

describe("authentication metrics — any-aligned vs all-aligned DKIM", () => {
  it("distinguishes 'any aligned DKIM pass' from 'every DKIM aligned'", () => {
    // Two passing signatures: the author domain aligns, a third-party signer does not.
    const { authentication } = extractMetrics(
      trustedMessage(FROM, `${TRUSTED_ID}; dkim=pass header.d=example.com; dkim=pass header.d=mailer.test`),
    );

    // DMARC's DKIM leg passes on a single aligned signature, so "any" is true...
    expect(authentication.anyAlignedDkimPass).toBe(true);
    // ...but not every signing domain matches, so the all-match view is false.
    expect(authentication.dkimAlignedWithFrom).toBe(false);
    expect(authentication.anyAuthAligned).toBe(true);
  });
});

describe("authentication metrics — Layer 2 excludes forge-able and non-authenticating results", () => {
  it("excludes passing results from an untrusted header (a forge-able stamp must not read as aligned)", () => {
    const input: AnalyzeInput = {
      headers: {
        from: FROM,
        "authentication-results":
          "relay.evil.test; dmarc=pass header.from=example.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com",
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    };
    const { authentication } = extractMetrics(input);

    // Layer 1 still records the claims, tagged untrusted.
    expect(authentication.untrustedHeaderCount).toBe(1);
    expect(authentication.dkimResults[0]?.trusted).toBe(false);
    // Layer 2 treats them as no evidence at all.
    expect(authentication.spfAlignedWithFrom).toBeNull();
    expect(authentication.dkimAlignedWithFrom).toBeNull();
    expect(authentication.anyAlignedSpfPass).toBe(false);
    expect(authentication.anyAlignedDkimPass).toBe(false);
    expect(authentication.dmarcPass).toBe(false);
    expect(authentication.anyAuthAligned).toBe(false);
  });

  it("excludes non-pass results (softfail/fail/none authenticate nothing)", () => {
    const { authentication } = extractMetrics(
      trustedMessage(
        FROM,
        `${TRUSTED_ID}; dmarc=fail header.from=example.com; spf=softfail smtp.mailfrom=example.com; dkim=fail header.d=example.com`,
      ),
    );

    expect(authentication.spfAlignedWithFrom).toBeNull();
    expect(authentication.dkimAlignedWithFrom).toBeNull();
    expect(authentication.anyAlignedSpfPass).toBe(false);
    expect(authentication.anyAlignedDkimPass).toBe(false);
    expect(authentication.dmarcPass).toBe(false);
    expect(authentication.anyAuthAligned).toBe(false);
  });

  it("reads a non-aligned SPF pass as unaligned, not as no-data", () => {
    const { authentication } = extractMetrics(
      trustedMessage(FROM, `${TRUSTED_ID}; spf=pass smtp.mailfrom=evil.test; dkim=pass header.d=example.com`),
    );

    expect(authentication.spfAlignedWithFrom).toBe(false);
    expect(authentication.anyAlignedSpfPass).toBe(false);
    // DKIM still aligns, so the message is DMARC-style aligned overall.
    expect(authentication.dkimAlignedWithFrom).toBe(true);
    expect(authentication.anyAuthAligned).toBe(true);
  });
});

describe("authentication metrics — missing comparison context stays null/false, never a false positive", () => {
  it("leaves alignment null and the any-flags false when From is absent", () => {
    const { authentication } = extractMetrics(
      trustedMessage(
        null,
        `${TRUSTED_ID}; dmarc=pass header.from=example.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com`,
      ),
    );

    expect(authentication.spfAlignedWithFrom).toBeNull();
    expect(authentication.dkimAlignedWithFrom).toBeNull();
    expect(authentication.anyAlignedSpfPass).toBe(false);
    expect(authentication.anyAlignedDkimPass).toBe(false);
    // dmarcPass is independent of From and stays true.
    expect(authentication.dmarcPass).toBe(true);
    expect(authentication.anyAuthAligned).toBe(false);
  });

  it("reports all-empty Layer 1 and null/false Layer 2 when there is no Authentication-Results header", () => {
    const { authentication } = extractMetrics({ headers: { from: FROM } });

    expect(authentication.trustedHeaderCount).toBe(0);
    expect(authentication.untrustedHeaderCount).toBe(0);
    expect(authentication.dmarcResults).toEqual([]);
    expect(authentication.spfResults).toEqual([]);
    expect(authentication.dkimResults).toEqual([]);
    expect(authentication.spfAlignedWithFrom).toBeNull();
    expect(authentication.dkimAlignedWithFrom).toBeNull();
    expect(authentication.anyAuthAligned).toBe(false);
  });
});

describe("collectAuthenticationAlignment — trust supplied at call time", () => {
  // The helper takes an isTrusted predicate rather than reading header.trusted, so a
  // caller can recompute alignment after declaring trust later (mirrors the dmarc rule).
  const header = parseAuthenticationResults(
    "mx.example.net; dmarc=pass header.from=example.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com",
    [],
  );

  it("treats results as aligned only once the predicate marks the header trusted", () => {
    const untrusted = collectAuthenticationAlignment([header], "example.com", () => false);
    expect(untrusted.anyAuthAligned).toBe(false);
    expect(untrusted.dmarcPass).toBe(false);

    const trusted = collectAuthenticationAlignment([header], "example.com", () => true);
    expect(trusted.anyAlignedSpfPass).toBe(true);
    expect(trusted.anyAlignedDkimPass).toBe(true);
    expect(trusted.dmarcPass).toBe(true);
    expect(trusted.anyAuthAligned).toBe(true);
  });
});

describe("authentication metrics — header-scoped rules see a per-header projection", () => {
  // A header-scoped rule reading metrics.authentication must see only the current
  // header's results, not the message-wide projection cached at extraction time.
  // Two trusted headers: the first aligns SPF/DKIM with From, the second does not.
  const TWO_HEADERS: AnalyzeInput = {
    headers: {
      from: FROM,
      "authentication-results": [
        `${TRUSTED_ID}; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com`,
        `${TRUSTED_ID}; spf=pass smtp.mailfrom=evil.test; dkim=pass header.d=evil.test`,
      ],
    },
    options: { trustedAuthservIds: [TRUSTED_ID] },
  };

  /** Records the authentication projection each header-scoped invocation observes. */
  function captureRule(sink: AuthenticationAlignment[]): Rule {
    return {
      key: "test.captureAuthentication",
      scope: "header",
      evaluate({ metrics }) {
        sink.push(metrics.authentication);
        return [];
      },
    };
  }

  it("narrows metrics.authentication to the current header, not all headers", () => {
    const seen: AuthenticationAlignment[] = [];
    const metrics = extractMetrics(TWO_HEADERS);
    runRules(metrics, TWO_HEADERS.options, [captureRule(seen)]);

    expect(seen).toHaveLength(2);
    // First header: aligned with From.
    expect(seen[0]?.anyAuthAligned).toBe(true);
    expect(seen[0]?.dkimAlignedWithFrom).toBe(true);
    expect(seen[0]?.dkimResults).toHaveLength(1);
    expect(seen[0]?.dkimResults[0]?.headerD).toBe("example.com");
    // Second header: passing but unaligned — must not inherit the first header's alignment.
    expect(seen[1]?.anyAuthAligned).toBe(false);
    expect(seen[1]?.dkimAlignedWithFrom).toBe(false);
    expect(seen[1]?.dkimResults).toHaveLength(1);
    expect(seen[1]?.dkimResults[0]?.headerD).toBe("evil.test");
    // Each invocation counts only its own header, never all of them.
    expect(seen[0]?.trustedHeaderCount).toBe(1);
    expect(seen[1]?.trustedHeaderCount).toBe(1);
  });

  it("resolves trust from trustedAuthservIds declared to runRules after extraction", () => {
    // Extract without trust, then declare it to runRules: the per-header projection
    // must recover trust (mirroring the dmarc header.from rule), not stay untrusted.
    const seen: AuthenticationAlignment[] = [];
    const metricsNoTrust = extractMetrics({ headers: TWO_HEADERS.headers });
    expect(metricsNoTrust.authentication.anyAuthAligned).toBe(false);

    runRules(metricsNoTrust, { trustedAuthservIds: [TRUSTED_ID] }, [captureRule(seen)]);
    expect(seen[0]?.anyAuthAligned).toBe(true);
    expect(seen[0]?.trustedHeaderCount).toBe(1);
    expect(seen[1]?.anyAuthAligned).toBe(false);
  });
});

describe("authentication metrics — analyzeMessage surfaces the block alongside signals", () => {
  it("attaches authentication to metrics without changing the signal set", () => {
    const result = analyzeMessage(
      trustedMessage(
        FROM,
        `${TRUSTED_ID}; dmarc=pass header.from=example.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com`,
      ),
    );
    expect(result.metrics.authentication.anyAuthAligned).toBe(true);
    expect(result.signals).toEqual([]);
  });

  it("matches the serializable fixture (header.i + multi-signature alignment)", () => {
    const result = analyzeMessage(headeriFixture.input);
    const roundTripped: AnalyzeResult = JSON.parse(JSON.stringify(result));
    expect(roundTripped).toEqual(headeriFixture.expected);
  });
});
