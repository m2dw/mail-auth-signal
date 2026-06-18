import { describe, expect, it } from "vitest";
import { analyzeMessage } from "../src/index.js";
import type {
  AnalyzeInput,
  AnalyzeResult,
  SignalCategory,
  SignalSeverity,
} from "../src/index.js";

import authResultsMissing from "./fixtures/parity/auth-results-missing.json" with { type: "json" };
import authUntrustedSource from "./fixtures/parity/auth-untrusted-source.json" with { type: "json" };
import authSpfFail from "./fixtures/parity/auth-spf-fail-trusted.json" with { type: "json" };
import authDkimFail from "./fixtures/parity/auth-dkim-fail-trusted.json" with { type: "json" };
import authDmarcFail from "./fixtures/parity/auth-dmarc-fail-trusted.json" with { type: "json" };
import messageIdMismatch from "./fixtures/parity/messageid-domain-mismatch.json" with { type: "json" };
import replyToMismatch from "./fixtures/parity/replyto-domain-mismatch.json" with { type: "json" };
import returnPathMismatch from "./fixtures/parity/returnpath-domain-mismatch.json" with { type: "json" };
import smtpMailfromMismatch from "./fixtures/parity/smtpmailfrom-domain-mismatch.json" with { type: "json" };
import dkimMismatch from "./fixtures/parity/dkim-domain-mismatch.json" with { type: "json" };
import dmarcHeaderFromMismatch from "./fixtures/parity/dmarc-headerfrom-mismatch.json" with { type: "json" };
import envelopeDisagreement from "./fixtures/parity/envelope-sender-disagreement.json" with { type: "json" };
import combinedSpoof from "./fixtures/parity/combined-spoof.json" with { type: "json" };
import cleanPass from "./fixtures/parity/clean-pass.json" with { type: "json" };

/**
 * A parity fixture freezes the analyzer's output for one sanitized, minimal
 * message so future rule changes that drift from the copied Thunderbird detection
 * behavior are caught. See test/fixtures/parity/README.md for the conventions and
 * how to add a case.
 */
type ParityFixture = {
  /** The rule family the fixture is the canonical example of, or "combined"/"none". */
  family: string;
  /**
   * Signal keys other than `family` that this case legitimately co-emits because
   * they are inherently coupled and cannot be isolated away (e.g. an envelope
   * disagreement with a From-aligned Return-Path forces an smtp.mailfrom/From
   * mismatch too). `auth.results.untrusted` is always allowed and need not be
   * listed.
   */
  allowedCompanions?: string[];
  description: string;
  input: AnalyzeInput;
  expected: AnalyzeResult;
};

/**
 * The whole parity corpus. Each fixture is imported statically (Node JSON import
 * assertions) so the suite stays runtime-neutral and needs no filesystem access.
 */
const fixtures: ParityFixture[] = [
  authResultsMissing,
  authUntrustedSource,
  authSpfFail,
  authDkimFail,
  authDmarcFail,
  messageIdMismatch,
  replyToMismatch,
  returnPathMismatch,
  smtpMailfromMismatch,
  dkimMismatch,
  dmarcHeaderFromMismatch,
  envelopeDisagreement,
  combinedSpoof,
  cleanPass,
] as unknown as ParityFixture[];

/** Every metric key extractMetrics produces; a fixture must pin all of them. */
const METRIC_KEYS: readonly string[] = [
  "fromDomain",
  "messageIdDomain",
  "messageIdDomainMatchesFromDomain",
  "replyToDomains",
  "replyToDomainMatchesFromDomain",
  "returnPathDomain",
  "returnPathNullReversePath",
  "returnPathDomainMatchesFromDomain",
  "smtpMailfromDomains",
  "smtpMailfromDomainMatchesFromDomain",
  "envelopeSenderDomainsAgree",
  "dkimDomains",
  "dkimDomainMatchesFromDomain",
  "dmarcHeaderFromDomains",
  "dmarcHeaderFromMatchesFromDomain",
  "authentication",
  "authenticationResults",
];

const SEVERITIES: readonly SignalSeverity[] = ["info", "low", "medium", "high"];
const CATEGORIES: readonly SignalCategory[] = [
  "absence",
  "trust",
  "auth-failure",
  "consistency",
];

/**
 * Every copied rule family the parity corpus must keep represented. If a family
 * is added to defaultRules, a parity fixture exercising it should be added here
 * too so the corpus never silently loses coverage of a shipped rule.
 */
const REQUIRED_FAMILY_KEYS: readonly string[] = [
  "auth.results.missing",
  "auth.results.untrusted",
  "auth.method.failure",
  "messageId.domainMismatch",
  "replyTo.domainMismatch",
  "returnPath.domainMismatch",
  "smtpMailfrom.domainMismatch",
  "dkim.domainMismatch",
  "dmarc.headerFromMismatch",
  "envelopeSender.domainDisagreement",
];

describe("parity fixtures — analyzer output is frozen", () => {
  for (const fixture of fixtures) {
    it(`reproduces: ${fixture.description.slice(0, 56)}…`, () => {
      const result = analyzeMessage(fixture.input);
      // Round-trip through JSON to prove the result is fully serializable (no
      // functions, no undefined-only fields) — the property fixtures and any
      // cross-language port rely on.
      const roundTripped: AnalyzeResult = JSON.parse(JSON.stringify(result));
      expect(roundTripped).toEqual(fixture.expected);
    });
  }
});

describe("parity fixtures — stable metric shape", () => {
  for (const fixture of fixtures) {
    it(`pins every metric key: ${fixture.family}`, () => {
      const metricKeys = Object.keys(fixture.expected.metrics).sort();
      expect(metricKeys).toEqual([...METRIC_KEYS].sort());
    });
  }
});

describe("parity fixtures — stable signal payload shape", () => {
  for (const fixture of fixtures) {
    it(`every signal carries a valid key/category/severity/message: ${fixture.family}`, () => {
      for (const signal of fixture.expected.signals) {
        expect(typeof signal.key).toBe("string");
        expect(signal.key.length).toBeGreaterThan(0);
        expect(CATEGORIES).toContain(signal.category);
        expect(SEVERITIES).toContain(signal.severity);
        expect(typeof signal.message).toBe("string");
        expect(signal.message.length).toBeGreaterThan(0);
        if (signal.data !== undefined) {
          expect(typeof signal.data).toBe("object");
          expect(Array.isArray(signal.data)).toBe(false);
          expect(signal.data).not.toBeNull();
        }
      }
    });
  }
});

describe("parity fixtures — single-family fixtures are canonical for their family", () => {
  for (const fixture of fixtures) {
    if (fixture.family === "combined" || fixture.family === "none") continue;
    it(`only emits its declared family (plus trust/companions): ${fixture.family}`, () => {
      const keys = new Set(fixture.expected.signals.map((signal) => signal.key));
      const allowed = new Set([
        fixture.family,
        // The trust source is flagged separately, so it may always co-occur.
        "auth.results.untrusted",
        ...(fixture.allowedCompanions ?? []),
      ]);
      for (const key of keys) {
        expect(allowed.has(key)).toBe(true);
      }
      expect(keys.has(fixture.family)).toBe(true);
    });
  }
});

describe("parity fixtures — corpus coverage", () => {
  const emittedKeys = new Set(
    fixtures.flatMap((fixture) => fixture.expected.signals.map((signal) => signal.key)),
  );

  for (const family of REQUIRED_FAMILY_KEYS) {
    it(`covers the ${family} family at least once`, () => {
      expect(emittedKeys.has(family)).toBe(true);
    });
  }

  it("includes a fully silent baseline (no signals on clean mail)", () => {
    const silent = fixtures.filter((fixture) => fixture.expected.signals.length === 0);
    expect(silent.length).toBeGreaterThan(0);
  });
});
