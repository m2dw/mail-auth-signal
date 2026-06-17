import { describe, expect, it } from "vitest";
import {
  analyzeMessage,
  defaultRules,
  extractDomainFromMailbox,
  extractMetrics,
  parseAuthenticationResults,
  runRules,
} from "../src/index.js";
import type { AnalyzeResult, Rule } from "../src/index.js";
import expectedDmarcFail from "./fixtures/dmarc-fail.json" with { type: "json" };

describe("domain extraction", () => {
  it("prefers the angle-bracket address over display-name text", () => {
    expect(extractDomainFromMailbox('"trusted@example.com" <attacker@evil.test>')).toBe("evil.test");
  });
});

describe("Authentication-Results parsing", () => {
  it("extracts authserv-id, methods, results, and properties", () => {
    const parsed = parseAuthenticationResults(
      "mx.example.net; dmarc=fail header.from=example.com; spf=pass smtp.mailfrom=mailer.example.com",
      ["mx.example.net"],
    );

    expect(parsed.authservId).toBe("mx.example.net");
    expect(parsed.trusted).toBe(true);
    expect(parsed.methods).toEqual([
      { method: "dmarc", result: "fail", properties: { "header.from": "example.com" } },
      { method: "spf", result: "pass", properties: { "smtp.mailfrom": "mailer.example.com" } },
    ]);
  });
});

describe("analyzeMessage", () => {
  it("returns structured metrics and signals", () => {
    const result = analyzeMessage({
      headers: {
        from: "Example Sender <notice@example.com>",
        "message-id": "<abc123@mailer.example.net>",
        "authentication-results": [
          "mx.example.net; dmarc=fail header.from=example.com; spf=pass smtp.mailfrom=example.com",
        ],
      },
      options: { trustedAuthservIds: ["mx.example.net"] },
    });

    expect(result.metrics.fromDomain).toBe("example.com");
    expect(result.metrics.messageIdDomain).toBe("mailer.example.net");
    expect(result.metrics.messageIdDomainMatchesFromDomain).toBe(false);
    expect(result.signals.map((signal) => signal.key)).toEqual([
      "auth.method.failure",
      "messageId.domainMismatch",
    ]);
  });

  it("reports missing Authentication-Results", () => {
    const result = analyzeMessage({
      headers: {
        from: "Example Sender <notice@example.com>",
      },
    });

    expect(result.signals[0]?.key).toBe("auth.results.missing");
    expect(result.signals[0]?.category).toBe("absence");
  });
});

describe("analysis API boundary", () => {
  const dmarcFailInput = {
    headers: {
      from: "Example Sender <notice@example.com>",
      "message-id": "<abc123@mailer.example.net>",
      "authentication-results": [
        "mx.example.net; dmarc=fail header.from=example.com; spf=pass smtp.mailfrom=example.com",
      ],
    },
    options: { trustedAuthservIds: ["mx.example.net"] },
  };

  it("extracts metrics without applying any interpretation", () => {
    const metrics = extractMetrics(dmarcFailInput);

    expect(metrics.fromDomain).toBe("example.com");
    expect(metrics.messageIdDomain).toBe("mailer.example.net");
    expect(metrics.authenticationResults[0]?.trusted).toBe(true);
    expect("signals" in metrics).toBe(false);
  });

  it("runs rules over already-extracted metrics (separable halves)", () => {
    const metrics = extractMetrics(dmarcFailInput);
    const signals = runRules(metrics, dmarcFailInput.options);

    expect(signals.map((signal) => signal.key)).toEqual([
      "auth.method.failure",
      "messageId.domainMismatch",
    ]);
  });

  it("honors trustedAuthservIds passed to runRules, not the baked-in metric", () => {
    // Caller uses the separated API: extract metrics WITHOUT trust context, then
    // declare the authserv-id trusted only when running rules. The untrusted
    // signal must reflect the options handed to runRules, not header.trusted.
    const metrics = extractMetrics({ headers: dmarcFailInput.headers });

    expect(metrics.authenticationResults[0]?.trusted).toBe(false);

    const trustedSignals = runRules(metrics, { trustedAuthservIds: ["mx.example.net"] });
    expect(trustedSignals.map((signal) => signal.key)).not.toContain(
      "auth.results.untrusted",
    );

    const untrustedSignals = runRules(metrics, {});
    expect(untrustedSignals.map((signal) => signal.key)).toContain(
      "auth.results.untrusted",
    );
  });

  it("preserves trust from metrics when runRules options are omitted", () => {
    // Caller extracts metrics WITH trust context, then uses the separated API
    // as runRules(metrics) without re-passing options. The baked-in
    // header.trusted must still be honored so this matches analyzeMessage and
    // does not report the already-trusted header as untrusted.
    const metrics = extractMetrics(dmarcFailInput);
    expect(metrics.authenticationResults[0]?.trusted).toBe(true);

    const separated = runRules(metrics);
    const viaAnalyze = analyzeMessage(dmarcFailInput).signals;

    expect(separated.map((signal) => signal.key)).not.toContain(
      "auth.results.untrusted",
    );
    expect(separated).toEqual(viaAnalyze);
  });

  it("keeps per-header signal ordering for multiple Authentication-Results", () => {
    // A trusted first header that fails SPF and an untrusted second header that
    // fails DKIM. The first header's failure must precede the second header's
    // untrusted signal, rather than all untrusted signals being grouped first.
    const input = {
      headers: {
        from: "Example Sender <notice@example.com>",
        "message-id": "<abc123@example.com>",
        "authentication-results": [
          "mx.example.net; spf=fail smtp.mailfrom=example.com",
          "relay.evil.test; dkim=fail header.d=example.com",
        ],
      },
      options: { trustedAuthservIds: ["mx.example.net"] },
    };

    const fromAnalyze = analyzeMessage(input).signals.map((signal) => signal.key);
    const fromRunRules = runRules(extractMetrics(input), input.options).map(
      (signal) => signal.key,
    );

    // Both Authentication-Results failures now share the stable auth.method.failure
    // key; the per-header ordering still places the first header's failure ahead of
    // the second header's untrusted-source signal and its own failure.
    expect(fromAnalyze).toEqual([
      "auth.method.failure",
      "auth.results.untrusted",
      "auth.method.failure",
    ]);
    expect(fromRunRules).toEqual(fromAnalyze);
  });

  it("lets callers target a narrowed rule set", () => {
    const onlyDomainMismatch = defaultRules.filter(
      (rule) => rule.key === "messageId.domainMismatch",
    );
    const result = analyzeMessage(dmarcFailInput, onlyDomainMismatch);

    expect(result.signals.map((signal) => signal.key)).toEqual(["messageId.domainMismatch"]);
    // Metrics are unaffected by which rules ran.
    expect(result.metrics.authenticationResults[0]?.methods).toHaveLength(2);
  });

  it("evaluates a caller-supplied custom rule against the stable RuleContext", () => {
    const fromDomainRule: Rule = {
      key: "demo.fromDomainPresent",
      evaluate({ metrics, options }) {
        if (!metrics.fromDomain) return [];
        return [
          {
            key: "demo.fromDomainPresent",
            severity: "info",
            message: `From domain is ${metrics.fromDomain}.`,
            data: { trustedCount: options.trustedAuthservIds?.length ?? 0 },
          },
        ];
      },
    };

    const result = analyzeMessage(dmarcFailInput, [fromDomainRule]);

    expect(result.signals).toEqual([
      {
        key: "demo.fromDomainPresent",
        severity: "info",
        message: "From domain is example.com.",
        data: { trustedCount: 1 },
      },
    ]);
  });

  it("produces JSON-serializable output matching the published fixture", () => {
    const result = analyzeMessage(expectedDmarcFail.input);
    // Round-trip through JSON proves the result carries no functions or
    // non-serializable values, which fixtures and cross-language ports rely on.
    const roundTripped: AnalyzeResult = JSON.parse(JSON.stringify(result));

    expect(roundTripped).toEqual(expectedDmarcFail.expected);
  });
});

