import { describe, expect, it } from "vitest";
import { computeLexicalHeuristics, computeRandomLookingCandidate } from "../src/index.js";
import type { LexicalHeuristics } from "../src/index.js";
import fixture from "./fixtures/lexical-heuristics.json" with { type: "json" };

describe("computeLexicalHeuristics — hand-computed fixtures", () => {
  for (const testCase of fixture.cases) {
    it(`matches fixture: ${testCase.label}`, () => {
      const heuristics = computeLexicalHeuristics(testCase.input);
      // Round-trip through JSON to prove the result is fully serializable, the way
      // a caller logging or persisting metrics relies on.
      const roundTripped: LexicalHeuristics = JSON.parse(JSON.stringify(heuristics));
      expect(roundTripped).toEqual(testCase.expected);
    });
  }
});

describe("computeLexicalHeuristics — policy-neutral invariants", () => {
  it("keeps every floating-point field within its documented range", () => {
    for (const token of ["", "a", "paypa1-login", "RANDOMxyzABC", "x9z8q2w1", "café-déjà"]) {
      const h = computeLexicalHeuristics(token);
      expect(h.normalizedEntropy).toBeGreaterThanOrEqual(0);
      expect(h.normalizedEntropy).toBeLessThanOrEqual(1);
      expect(h.vowelRatio).toBeGreaterThanOrEqual(0);
      expect(h.vowelRatio).toBeLessThanOrEqual(1);
      expect(h.digitRatio).toBeGreaterThanOrEqual(0);
      expect(h.digitRatio).toBeLessThanOrEqual(1);
      expect(h.hyphenRatio).toBeGreaterThanOrEqual(0);
      expect(h.hyphenRatio).toBeLessThanOrEqual(1);
      expect(h.uniqueCharRatio).toBeGreaterThanOrEqual(0);
      expect(h.uniqueCharRatio).toBeLessThanOrEqual(1);
      expect(h.shannonEntropy).toBeGreaterThanOrEqual(0);
      expect(h.maxHexRun).toBeGreaterThanOrEqual(0);
      expect(h.maxHexRun).toBeLessThanOrEqual([...token].length);
    }
  });

  it("derives digit and hyphen ratios from length, matching the raw counts", () => {
    // "secure-paypal-1" has 2 hyphens and 1 digit over 15 codepoints.
    const h = computeLexicalHeuristics("secure-paypal-1");
    expect(h.hyphenRatio).toBe(0.1333);
    expect(h.digitRatio).toBe(0.0667);
  });

  it("measures the longest hex run, stopping at the first non-hex character", () => {
    // "go" is non-hex, then "0ff1ce" is six consecutive hex chars (0,f,f,1,c,e).
    expect(computeLexicalHeuristics("go0ff1ce").maxHexRun).toBe(6);
    // A hyphen and the non-hex letters 's','t','u','w' break every would-be run.
    expect(computeLexicalHeuristics("switch-bot").maxHexRun).toBe(1);
  });

  it("treats vowels case-insensitively", () => {
    expect(computeLexicalHeuristics("AEIOU")).toMatchObject({ vowelRatio: 1, maxConsonantRun: 0 });
  });

  it("counts the longest repeated-character run, not the total", () => {
    // "aabbba": runs are aa(2), bbb(3), a(1) → longest is 3.
    expect(computeLexicalHeuristics("aabbba").maxRepeatedCharRun).toBe(3);
  });

  it("counts a digit/letter switch in either direction", () => {
    // "1a2b3c": 1→a, a→2, 2→b, b→3, 3→c = 5 transitions.
    expect(computeLexicalHeuristics("1a2b3c").letterDigitTransitions).toBe(5);
  });

  it("does not count digit-to-digit or letter-to-letter as a transition", () => {
    expect(computeLexicalHeuristics("12ab").letterDigitTransitions).toBe(1);
  });

  it("exposes alpha length and the y-inclusive vowel count/ratio", () => {
    // "xyz": 3 letters, the single 'y' counts as a vowel only for the y-inclusive
    // fields (vowelRatio stays 0 because it excludes y).
    const h = computeLexicalHeuristics("xyz");
    expect(h.alphaLength).toBe(3);
    expect(h.vowelCount).toBe(1);
    expect(h.vowelRatioAlphaOnly).toBe(0.3333);
    expect(h.vowelRatio).toBe(0);
  });

  it("reports the raw hyphen and unique-character counts behind the ratios", () => {
    const h = computeLexicalHeuristics("a-b-c");
    expect(h.hyphenCount).toBe(2);
    expect(h.uniqueCharCount).toBe(4);
  });

  it("counts symbol-skipping letter/digit transitions across separators", () => {
    // "ab-12": the hyphen is skipped, so the letter->digit class change still
    // counts once, where the adjacency-based letterDigitTransitions sees none.
    const h = computeLexicalHeuristics("ab-12");
    expect(h.letterDigitTransitionCount).toBe(1);
    expect(h.letterDigitTransitions).toBe(0);
  });

  it("requires a digit in the run for hasLongHexLikeRun, unlike maxHexRun", () => {
    // "deadbeef" is eight hex letters but carries no digit, so it reads as a word.
    const word = computeLexicalHeuristics("deadbeef");
    expect(word.maxHexRun).toBe(8);
    expect(word.hasLongHexLikeRun).toBe(false);
    // "0ff1ce" mixes digits into the hex run — a six-char hash/GUID-fragment shape.
    expect(computeLexicalHeuristics("0ff1ce").hasLongHexLikeRun).toBe(true);
    // A two-character "1a" pair is below the run-length floor.
    expect(computeLexicalHeuristics("1a-zz").hasLongHexLikeRun).toBe(false);
    // The add-on floor is 6: a digit-bearing run of length 5 like "abc12" stays
    // false so short ordinary fragments do not read as hash/GUID positives.
    expect(computeLexicalHeuristics("abc12").hasLongHexLikeRun).toBe(false);
    expect(computeLexicalHeuristics("abc123").hasLongHexLikeRun).toBe(true);
  });
});

describe("computeRandomLookingCandidate", () => {
  it("flags long machine-generated shapes", () => {
    // High digit ratio + frequent letter/digit alternation.
    expect(computeRandomLookingCandidate("x9z8q2w1")).toBe(true);
    // Long hex run (a hash / GUID fragment).
    expect(computeRandomLookingCandidate("deadbeef")).toBe(true);
    expect(computeRandomLookingCandidate("a1b2c3d4e5")).toBe(true);
    // Low vowel ratio paired with a long consonant run (unpronounceable cluster).
    expect(computeRandomLookingCandidate("qwrtplkjhg")).toBe(true);
    // Separator-padded alternation: the symbol-skipping transition count folds in
    // the Layer 3 parity metric so "ab-1-cd-2-ef" still reads as alternating even
    // though no letter and digit are ever adjacent.
    expect(computeRandomLookingCandidate("ab-1-cd-2-ef")).toBe(true);
  });

  it("does not flag short tokens even when their shape looks random", () => {
    // Same alternating shape as "x9z8q2w1" but below the length floor.
    expect(computeRandomLookingCandidate("x9z8")).toBe(false);
    expect(computeRandomLookingCandidate("dead")).toBe(false);
  });

  it("restores parity with the add-on's structurally separable random checks", () => {
    // Add-on positives the previous length>=8 / consonant-run>=5 thresholds missed:
    // "mpqxyt" is a length-6 all-consonant label (vowel ratio 0, consonant run 6).
    expect(computeRandomLookingCandidate("mpqxyt")).toBe(true);
    // "CAQLEV" matches the add-on's letters-only uppercase rule.
    expect(computeRandomLookingCandidate("CAQLEV")).toBe(true);
    // The length-6 floor still does not flag a short pronounceable word.
    expect(computeRandomLookingCandidate("github")).toBe(false);
  });

  it("treats structurally word-like gibberish as caller-owned without a model", () => {
    // "wlikqkgi" (vowel ratio 0.25, consonant run 4) is indistinguishable by shape
    // from the real word "switchbot" (vowel ratio 0.22, consonant run 4), so the
    // structural default flags neither.
    expect(computeRandomLookingCandidate("wlikqkgi")).toBe(false);
    expect(computeRandomLookingCandidate("switchbot")).toBe(false);

    // A caller-supplied naturalness model closes the parity gap: the gibberish is
    // rejected as unnatural and flagged, while the real word stays false.
    const naturalWords = new Set(["switchbot"]);
    const isNatural = (token: string) => naturalWords.has(token.toLowerCase());
    expect(computeRandomLookingCandidate("wlikqkgi", { isNatural })).toBe(true);
    expect(computeRandomLookingCandidate("switchbot", { isNatural })).toBe(false);
    // The model is consulted only for word-shaped tokens; a hex/digit token is
    // already flagged structurally regardless of the model's opinion.
    expect(computeRandomLookingCandidate("deadbeef", { isNatural })).toBe(true);
  });

  it("does not flag known false-positive brand and word labels", () => {
    // Regression cases from the add-on's history: low vowel ratio but a short
    // consonant run, no digits, no hex run, no letter/digit alternation.
    for (const label of [
      "switchbot",
      "crowdworks",
      "newsletter",
      "marketing",
      "information",
      "github",
      "salesforce",
    ]) {
      expect(computeRandomLookingCandidate(label), label).toBe(false);
    }
  });

  it("does not flag a long hyphenated brand label (hyphenation alone is not randomness)", () => {
    expect(computeRandomLookingCandidate("secure-paypal-login")).toBe(false);
  });

  it("returns false for an empty token", () => {
    expect(computeRandomLookingCandidate("")).toBe(false);
  });
});
