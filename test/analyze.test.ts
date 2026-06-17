import { describe, expect, it } from "vitest";
import { analyzeMessage, extractDomainFromMailbox, parseAuthenticationResults } from "../src/index.js";

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
      "auth.dmarc.fail",
      "messageId.domainMismatch",
    ]);
  });

  it("reports missing Authentication-Results", () => {
    const result = analyzeMessage({
      headers: {
        from: "Example Sender <notice@example.com>",
      },
    });

    expect(result.signals[0]?.key).toBe("authResults.missing");
  });
});

