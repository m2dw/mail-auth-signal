import { describe, expect, it } from "vitest";
import {
  analyzeMessage,
  envelopeSenderDisagreementRule,
  extractEnvelopeSenderDomain,
  extractMetrics,
  isNullReversePath,
  returnPathDomainMismatchRule,
  smtpMailfromDomainMismatchRule,
} from "../src/index.js";
import type { AnalyzeInput, AnalyzeResult, Signal } from "../src/index.js";
import returnpathMatch from "./fixtures/returnpath-domain-match.json" with { type: "json" };
import returnpathMismatch from "./fixtures/returnpath-domain-mismatch.json" with { type: "json" };
import returnpathNull from "./fixtures/returnpath-null-reverse-path.json" with { type: "json" };
import returnpathMissing from "./fixtures/returnpath-missing.json" with { type: "json" };
import smtpMismatch from "./fixtures/smtpmailfrom-domain-mismatch.json" with { type: "json" };
import disagreement from "./fixtures/envelope-sender-disagreement.json" with { type: "json" };

const TRUSTED_ID = "mx.example.net";

/**
 * Build a message with the given From, Return-Path, and SPF smtp.mailfrom on an
 * otherwise clean, trusted, all-passing header (with a From-aligned Message-ID)
 * so the unrelated default rules stay silent and the envelope-sender signals are
 * isolated. `mailfrom` injects the SPF result's smtp.mailfrom property; null
 * omits the SPF method entirely. `returnPath` null omits the header.
 */
function message(
  from: string | null,
  returnPath: string | null,
  mailfrom: string | null,
): AnalyzeInput {
  const spf = mailfrom === null ? "" : ` spf=pass smtp.mailfrom=${mailfrom};`;
  const headers: Record<string, string> = {
    "message-id": "<id@example.com>",
    "authentication-results": `${TRUSTED_ID}; dmarc=pass header.from=example.com;${spf} dkim=pass header.d=example.com`,
  };
  if (from !== null) headers["from"] = from;
  if (returnPath !== null) headers["return-path"] = returnPath;
  return { headers, options: { trustedAuthservIds: [TRUSTED_ID] } };
}

/** The envelope-sender consistency signals only (returnPath/smtpMailfrom/envelopeSender). */
function envelopeSignals(result: AnalyzeResult): Signal[] {
  return result.signals.filter((signal) =>
    /^(returnPath|smtpMailfrom|envelopeSender)\./.test(signal.key),
  );
}

describe("extractEnvelopeSenderDomain", () => {
  it("reads an angle-addr reverse-path", () => {
    expect(extractEnvelopeSenderDomain("<bounce@example.com>")).toBe("example.com");
  });

  it("reads a bare addr-spec", () => {
    expect(extractEnvelopeSenderDomain("bounce@example.com")).toBe("example.com");
  });

  it("reads a bare domain (smtp.mailfrom may omit the local part)", () => {
    expect(extractEnvelopeSenderDomain("example.com")).toBe("example.com");
  });

  it("normalizes casing, surrounding whitespace, and a trailing dot", () => {
    expect(extractEnvelopeSenderDomain("  <Bounce@Example.COM.>  ")).toBe("example.com");
  });

  it("returns null for the null reverse-path", () => {
    expect(extractEnvelopeSenderDomain("<>")).toBeNull();
  });

  it("returns null for a missing value", () => {
    expect(extractEnvelopeSenderDomain(null)).toBeNull();
  });

  it("ignores a dotless host rather than fabricating a domain", () => {
    expect(extractEnvelopeSenderDomain("postmaster@localhost")).toBeNull();
    expect(extractEnvelopeSenderDomain("localhost")).toBeNull();
  });

  it("does not fabricate a domain from a malformed multi-'@' value", () => {
    expect(extractEnvelopeSenderDomain("<a@b@example.com>")).toBeNull();
  });

  it("does not pull a domain out of an RFC 5322 comment", () => {
    expect(extractEnvelopeSenderDomain("(billing@evil.test) <bounce@example.com>")).toBe(
      "example.com",
    );
  });

  it("rejects a value whose domain part carries embedded whitespace", () => {
    expect(extractEnvelopeSenderDomain("<bounce@exa mple.com>")).toBeNull();
  });
});

describe("isNullReversePath", () => {
  it("is true only for an explicit `<>` (whitespace tolerated)", () => {
    expect(isNullReversePath("<>")).toBe(true);
    expect(isNullReversePath("  <>  ")).toBe(true);
  });

  it("is false for a missing header or a real reverse-path", () => {
    expect(isNullReversePath(null)).toBe(false);
    expect(isNullReversePath("<bounce@example.com>")).toBe(false);
  });
});

describe("returnPathDomainMismatchRule", () => {
  it("stays silent when Return-Path domain matches From", () => {
    const result = analyzeMessage(message("Example <a@example.com>", "<bounce@example.com>", "example.com"));
    expect(result.metrics.returnPathDomain).toBe("example.com");
    expect(result.metrics.returnPathDomainMatchesFromDomain).toBe(true);
    expect(envelopeSignals(result)).toEqual([]);
  });

  it("normalizes casing/whitespace before comparing (no false mismatch)", () => {
    const result = analyzeMessage(
      message("Example <a@Example.COM>", "  <Bounce@EXAMPLE.com.>  ", "example.com"),
    );
    expect(result.metrics.returnPathDomain).toBe("example.com");
    expect(result.metrics.returnPathDomainMatchesFromDomain).toBe(true);
    expect(envelopeSignals(result)).toEqual([]);
  });

  it("emits one low-severity signal when Return-Path domain differs from From", () => {
    // No smtp.mailfrom so only the Return-Path rule can fire.
    const result = analyzeMessage(message("Example <a@example.com>", "<bounce@evil.test>", null));
    expect(result.metrics.returnPathDomainMatchesFromDomain).toBe(false);
    const signals = envelopeSignals(result);
    expect(signals).toEqual([
      {
        key: "returnPath.domainMismatch",
        severity: "low",
        message: "Return-Path domain differs from the From domain.",
        data: { fromDomain: "example.com", returnPathDomain: "evil.test" },
      },
    ]);
  });

  it("treats a subdomain of From as a mismatch (exact comparison only)", () => {
    const result = analyzeMessage(message("Example <a@example.com>", "<bounce@mail.example.com>", null));
    expect(result.metrics.returnPathDomainMatchesFromDomain).toBe(false);
    expect(envelopeSignals(result)).toHaveLength(1);
  });

  it("stays silent for a missing Return-Path", () => {
    const result = analyzeMessage(message("Example <a@example.com>", null, "example.com"));
    expect(result.metrics.returnPathDomain).toBeNull();
    expect(result.metrics.returnPathNullReversePath).toBe(false);
    expect(result.metrics.returnPathDomainMatchesFromDomain).toBeNull();
    expect(
      result.signals.some((signal) => signal.key === "returnPath.domainMismatch"),
    ).toBe(false);
  });

  it("stays silent for a null reverse-path (bounce), flagging it in metrics", () => {
    const result = analyzeMessage(message("Example <a@example.com>", "<>", null));
    expect(result.metrics.returnPathDomain).toBeNull();
    expect(result.metrics.returnPathNullReversePath).toBe(true);
    expect(result.metrics.returnPathDomainMatchesFromDomain).toBeNull();
    expect(envelopeSignals(result)).toEqual([]);
  });

  it("stays silent when From is absent", () => {
    const result = analyzeMessage(message(null, "<bounce@evil.test>", null));
    expect(result.metrics.fromDomain).toBeNull();
    expect(result.metrics.returnPathDomain).toBe("evil.test");
    expect(result.metrics.returnPathDomainMatchesFromDomain).toBeNull();
    expect(envelopeSignals(result)).toEqual([]);
  });
});

describe("smtpMailfromDomainMismatchRule", () => {
  it("stays silent when smtp.mailfrom matches From", () => {
    const result = analyzeMessage(message("Example <a@example.com>", null, "example.com"));
    expect(result.metrics.smtpMailfromDomains).toEqual(["example.com"]);
    expect(result.metrics.smtpMailfromDomainMatchesFromDomain).toBe(true);
    expect(envelopeSignals(result)).toEqual([]);
  });

  it("emits one low-severity signal when smtp.mailfrom differs from From", () => {
    const result = analyzeMessage(message("Example <a@example.com>", null, "evil.test"));
    expect(result.metrics.smtpMailfromDomainMatchesFromDomain).toBe(false);
    const signals = envelopeSignals(result);
    expect(signals).toEqual([
      {
        key: "smtpMailfrom.domainMismatch",
        severity: "low",
        message: "SPF smtp.mailfrom domain differs from the From domain.",
        data: {
          fromDomain: "example.com",
          smtpMailfromDomains: ["evil.test"],
          mismatchedDomains: ["evil.test"],
        },
      },
    ]);
  });

  it("stays silent when no SPF result carries smtp.mailfrom", () => {
    const result = analyzeMessage(message("Example <a@example.com>", null, null));
    expect(result.metrics.smtpMailfromDomains).toEqual([]);
    expect(result.metrics.smtpMailfromDomainMatchesFromDomain).toBeNull();
    expect(envelopeSignals(result)).toEqual([]);
  });

  it("treats a null `<>` smtp.mailfrom as no domain (stays silent)", () => {
    const result = analyzeMessage(message("Example <a@example.com>", null, "<>"));
    expect(result.metrics.smtpMailfromDomains).toEqual([]);
    expect(result.metrics.smtpMailfromDomainMatchesFromDomain).toBeNull();
    expect(envelopeSignals(result)).toEqual([]);
  });

  it("collects smtp.mailfrom across multiple Authentication-Results headers and flags one divergent value", () => {
    const result = analyzeMessage({
      headers: {
        from: "Example <a@example.com>",
        "message-id": "<id@example.com>",
        "authentication-results": [
          "mx.example.net; spf=pass smtp.mailfrom=example.com",
          "mx.example.net; spf=pass smtp.mailfrom=evil.test",
        ],
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.smtpMailfromDomains).toEqual(["example.com", "evil.test"]);
    expect(result.metrics.smtpMailfromDomainMatchesFromDomain).toBe(false);
    const signals = result.signals.filter((s) => s.key === "smtpMailfrom.domainMismatch");
    expect(signals).toHaveLength(1);
    expect(signals[0]?.data).toEqual({
      fromDomain: "example.com",
      smtpMailfromDomains: ["example.com", "evil.test"],
      mismatchedDomains: ["evil.test"],
    });
  });

  it("reads the smtp.mailfrom regardless of the SPF result (even on fail)", () => {
    const result = analyzeMessage({
      headers: {
        from: "Example <a@example.com>",
        "message-id": "<id@example.com>",
        "authentication-results": ["mx.example.net; spf=fail smtp.mailfrom=evil.test"],
      },
      options: { trustedAuthservIds: [TRUSTED_ID] },
    });
    expect(result.metrics.smtpMailfromDomains).toEqual(["evil.test"]);
    expect(result.metrics.smtpMailfromDomainMatchesFromDomain).toBe(false);
  });
});

describe("envelopeSenderDisagreementRule", () => {
  it("flags when Return-Path and smtp.mailfrom disagree with each other", () => {
    const result = analyzeMessage(message("Example <a@example.com>", "<bounce@example.com>", "evil.test"));
    expect(result.metrics.envelopeSenderDomainsAgree).toBe(false);
    const signals = result.signals.filter((s) => s.key === "envelopeSender.domainDisagreement");
    expect(signals).toEqual([
      {
        key: "envelopeSender.domainDisagreement",
        severity: "low",
        message: "Return-Path domain differs from the SPF smtp.mailfrom domain.",
        data: {
          returnPathDomain: "example.com",
          smtpMailfromDomains: ["evil.test"],
          disagreeingDomains: ["evil.test"],
        },
      },
    ]);
  });

  it("stays silent when the two envelope sources agree", () => {
    const result = analyzeMessage(message("Example <a@example.com>", "<bounce@example.com>", "example.com"));
    expect(result.metrics.envelopeSenderDomainsAgree).toBe(true);
    expect(
      result.signals.some((s) => s.key === "envelopeSender.domainDisagreement"),
    ).toBe(false);
  });

  it("stays silent when only one envelope source is present", () => {
    const onlyReturnPath = analyzeMessage(message("Example <a@example.com>", "<bounce@example.com>", null));
    expect(onlyReturnPath.metrics.envelopeSenderDomainsAgree).toBeNull();

    const onlyMailfrom = analyzeMessage(message("Example <a@example.com>", null, "example.com"));
    expect(onlyMailfrom.metrics.envelopeSenderDomainsAgree).toBeNull();

    for (const result of [onlyReturnPath, onlyMailfrom]) {
      expect(
        result.signals.some((s) => s.key === "envelopeSender.domainDisagreement"),
      ).toBe(false);
    }
  });
});

describe("envelope-sender rules — in isolation", () => {
  it("each rule reads only its precomputed metric", () => {
    const quiet = extractMetrics(message("Example <a@example.com>", "<bounce@example.com>", "example.com"));
    expect(returnPathDomainMismatchRule.evaluate({ metrics: quiet, options: {} })).toEqual([]);
    expect(smtpMailfromDomainMismatchRule.evaluate({ metrics: quiet, options: {} })).toEqual([]);
    expect(envelopeSenderDisagreementRule.evaluate({ metrics: quiet, options: {} })).toEqual([]);

    const returnPathNoisy = extractMetrics(message("Example <a@example.com>", "<bounce@evil.test>", null));
    expect(returnPathDomainMismatchRule.evaluate({ metrics: returnPathNoisy, options: {} })).toHaveLength(1);

    const mailfromNoisy = extractMetrics(message("Example <a@example.com>", null, "evil.test"));
    expect(smtpMailfromDomainMismatchRule.evaluate({ metrics: mailfromNoisy, options: {} })).toHaveLength(1);

    const disagree = extractMetrics(message("Example <a@example.com>", "<bounce@example.com>", "evil.test"));
    expect(envelopeSenderDisagreementRule.evaluate({ metrics: disagree, options: {} })).toHaveLength(1);
  });
});

describe("envelope-sender rules — serializable fixtures", () => {
  for (const fixture of [
    returnpathMatch,
    returnpathMismatch,
    returnpathNull,
    returnpathMissing,
    smtpMismatch,
    disagreement,
  ]) {
    it(`matches fixture: ${fixture.description.slice(0, 48)}…`, () => {
      const result = analyzeMessage(fixture.input);
      const roundTripped: AnalyzeResult = JSON.parse(JSON.stringify(result));
      expect(roundTripped).toEqual(fixture.expected);
    });
  }
});
