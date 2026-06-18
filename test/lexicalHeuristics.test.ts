import { describe, expect, it } from "vitest";
import { computeLexicalHeuristics } from "../src/index.js";
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
      expect(h.uniqueCharRatio).toBeGreaterThanOrEqual(0);
      expect(h.uniqueCharRatio).toBeLessThanOrEqual(1);
      expect(h.shannonEntropy).toBeGreaterThanOrEqual(0);
    }
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
});
