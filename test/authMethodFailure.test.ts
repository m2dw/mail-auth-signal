import { describe, expect, it } from "vitest";
import { analyzeMessage, extractMetrics, runRules } from "../src/index.js";
import type { AnalyzeResult, Signal, SignalSeverity } from "../src/index.js";
import dmarcFailTrusted from "./fixtures/dmarc-fail-trusted.json" with { type: "json" };
import dmarcFailUntrusted from "./fixtures/dmarc-fail.json" with { type: "json" };
import spfSoftfail from "./fixtures/spf-softfail.json" with { type: "json" };
import dkimFail from "./fixtures/dkim-fail.json" with { type: "json" };

const TRUSTED_ID = "mx.example.net";

/** Build a message with a single Authentication-Results header carrying `ar`. */
function message(ar: string, trusted: boolean) {
  return {
    headers: {
      from: "Example Sender <notice@example.com>",
      // Matches the From domain so the Message-ID rule stays quiet and the
      // Authentication-Results failure family is isolated.
      "message-id": "<abc123@example.com>",
      "authentication-results": [`${TRUSTED_ID}; ${ar}`],
    },
    ...(trusted ? { options: { trustedAuthservIds: [TRUSTED_ID] } } : {}),
  };
}

/** The auth.<method>.<result> signals only (drops authResults.* and others). */
function methodFailures(result: AnalyzeResult): Signal[] {
  return result.signals.filter((signal) => signal.key.startsWith("auth."));
}

describe("authMethodFailureRule — trusted, authoritative results", () => {
  const cases: Array<{ ar: string; key: string; severity: SignalSeverity }> = [
    { ar: "spf=fail smtp.mailfrom=example.com", key: "auth.spf.fail", severity: "medium" },
    { ar: "spf=softfail smtp.mailfrom=example.com", key: "auth.spf.softfail", severity: "low" },
    { ar: "spf=temperror smtp.mailfrom=example.com", key: "auth.spf.temperror", severity: "low" },
    { ar: "spf=permerror smtp.mailfrom=example.com", key: "auth.spf.permerror", severity: "low" },
    { ar: "dkim=fail header.d=example.com", key: "auth.dkim.fail", severity: "medium" },
    { ar: "dkim=temperror header.d=example.com", key: "auth.dkim.temperror", severity: "low" },
    { ar: "dkim=permerror header.d=example.com", key: "auth.dkim.permerror", severity: "low" },
    { ar: "dmarc=fail header.from=example.com", key: "auth.dmarc.fail", severity: "high" },
    { ar: "dmarc=temperror header.from=example.com", key: "auth.dmarc.temperror", severity: "low" },
    { ar: "dmarc=permerror header.from=example.com", key: "auth.dmarc.permerror", severity: "low" },
  ];

  for (const { ar, key, severity } of cases) {
    it(`reports ${key} as ${severity}`, () => {
      const signals = methodFailures(analyzeMessage(message(ar, true)));
      expect(signals).toHaveLength(1);
      expect(signals[0]?.key).toBe(key);
      expect(signals[0]?.severity).toBe(severity);
      expect(signals[0]?.data?.trusted).toBe(true);
    });
  }

  it("escalates DMARC fail above a plain SPF/DKIM fail", () => {
    const dmarc = methodFailures(analyzeMessage(message("dmarc=fail header.from=example.com", true)));
    const spf = methodFailures(analyzeMessage(message("spf=fail smtp.mailfrom=example.com", true)));
    expect(dmarc[0]?.severity).toBe("high");
    expect(spf[0]?.severity).toBe("medium");
  });
});

describe("authMethodFailureRule — untrusted results are non-authoritative", () => {
  it("never escalates above low, even for DMARC fail, when the source is untrusted", () => {
    for (const ar of [
      "spf=fail smtp.mailfrom=example.com",
      "dkim=fail header.d=example.com",
      "dmarc=fail header.from=example.com",
    ]) {
      const signals = methodFailures(analyzeMessage(message(ar, false)));
      expect(signals).toHaveLength(1);
      expect(signals[0]?.severity).toBe("low");
      expect(signals[0]?.data?.trusted).toBe(false);
    }
  });
});

describe("authMethodFailureRule — non-failures stay silent", () => {
  for (const ar of [
    "spf=pass smtp.mailfrom=example.com",
    "dkim=pass header.d=example.com",
    "dmarc=pass header.from=example.com",
    "spf=none smtp.mailfrom=example.com",
    "spf=neutral smtp.mailfrom=example.com",
  ]) {
    it(`emits no method-failure signal for "${ar}"`, () => {
      expect(methodFailures(analyzeMessage(message(ar, true)))).toEqual([]);
    });
  }
});

describe("authMethodFailureRule — trust resolved from runRules options", () => {
  it("uses trustedAuthservIds passed to runRules, not the baked-in metric", () => {
    // Metrics extracted WITHOUT trust context; trust declared only at rule time.
    const metrics = extractMetrics(message("dmarc=fail header.from=example.com", false));
    expect(metrics.authenticationResults[0]?.trusted).toBe(false);

    const trusted = runRules(metrics, { trustedAuthservIds: [TRUSTED_ID] }).filter((s) =>
      s.key.startsWith("auth."),
    );
    expect(trusted[0]?.severity).toBe("high");
    expect(trusted[0]?.data?.trusted).toBe(true);

    const untrusted = runRules(metrics, {}).filter((s) => s.key.startsWith("auth."));
    expect(untrusted[0]?.severity).toBe("low");
    expect(untrusted[0]?.data?.trusted).toBe(false);
  });
});

describe("authMethodFailureRule — multiple methods in one header", () => {
  it("emits one signal per failing method, in header order", () => {
    const signals = methodFailures(
      analyzeMessage(
        message(
          "dmarc=fail header.from=example.com; spf=fail smtp.mailfrom=example.com; dkim=pass header.d=example.com",
          true,
        ),
      ),
    );
    expect(signals.map((s) => [s.key, s.severity])).toEqual([
      ["auth.dmarc.fail", "high"],
      ["auth.spf.fail", "medium"],
    ]);
  });
});

describe("authMethodFailureRule — serializable fixtures", () => {
  for (const fixture of [dmarcFailTrusted, dmarcFailUntrusted, spfSoftfail, dkimFail]) {
    it(`matches fixture: ${fixture.description.slice(0, 48)}…`, () => {
      const result = analyzeMessage(fixture.input);
      const roundTripped: AnalyzeResult = JSON.parse(JSON.stringify(result));
      expect(roundTripped).toEqual(fixture.expected);
    });
  }
});
