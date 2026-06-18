import { describe, expect, it } from "vitest";
import { computeJaro, computeJaroWinkler } from "../src/index.js";
import fixture from "./fixtures/jaro-winkler.json" with { type: "json" };

describe("computeJaro / computeJaroWinkler — hand-computed fixtures", () => {
  for (const testCase of fixture.cases) {
    it(`jaro: ${testCase.label}`, () => {
      expect(computeJaro(testCase.a, testCase.b)).toBe(testCase.jaro);
    });
    it(`jaroWinkler: ${testCase.label}`, () => {
      expect(computeJaroWinkler(testCase.a, testCase.b)).toBe(testCase.jaroWinkler);
    });
  }
});

describe("computeJaro — policy-neutral invariants", () => {
  it("result is always in [0, 1]", () => {
    const pairs: [string, string][] = [
      ["", ""],
      ["", "a"],
      ["a", ""],
      ["a", "b"],
      ["abc", "abc"],
      ["MARTHA", "MARHTA"],
      ["hello", "world"],
      ["x9z8q2w1", "w2q8z9x1"],
    ];
    for (const [a, b] of pairs) {
      const result = computeJaro(a, b);
      expect(result).toBeGreaterThanOrEqual(0);
      expect(result).toBeLessThanOrEqual(1);
    }
  });

  it("is symmetric: computeJaro(a, b) === computeJaro(b, a)", () => {
    const pairs: [string, string][] = [
      ["MARTHA", "MARHTA"],
      ["DWAYNE", "DUANE"],
      ["DIXON", "DICKSONX"],
      ["hello", "world"],
      ["", "abc"],
    ];
    for (const [a, b] of pairs) {
      expect(computeJaro(a, b)).toBe(computeJaro(b, a));
    }
  });

  it("single differing character — no overlap at same position with window=0 for length 1", () => {
    expect(computeJaro("a", "b")).toBe(0);
  });

  it("is codepoint-based: Unicode characters are each counted as one unit", () => {
    // "café" vs "cafe": c, a, f match; é ≠ e → m=3, window=1, l=3
    // jaro = (3/4 + 3/4 + 3/3) / 3 = (0.75 + 0.75 + 1) / 3 = 5/6 ≈ 0.8333
    const result = computeJaro("café", "cafe");
    expect(result).toBeGreaterThan(0);
    expect(result).toBeLessThan(1);
    // The comparison must treat 'é' as a single codepoint, not as two code units
    expect(computeJaro("café", "café")).toBe(1);
  });
});

describe("computeJaroWinkler — policy-neutral invariants", () => {
  it("result is always in [0, 1] for the default scaling factor", () => {
    const pairs: [string, string][] = [
      ["", ""],
      ["", "a"],
      ["MARTHA", "MARHTA"],
      ["DWAYNE", "DUANE"],
      ["hello", "world"],
    ];
    for (const [a, b] of pairs) {
      const result = computeJaroWinkler(a, b);
      expect(result).toBeGreaterThanOrEqual(0);
      expect(result).toBeLessThanOrEqual(1);
    }
  });

  it("is symmetric with the default scaling factor", () => {
    const pairs: [string, string][] = [
      ["MARTHA", "MARHTA"],
      ["DWAYNE", "DUANE"],
      ["hello", "world"],
    ];
    for (const [a, b] of pairs) {
      expect(computeJaroWinkler(a, b)).toBe(computeJaroWinkler(b, a));
    }
  });

  it("prefix bonus increases similarity relative to bare Jaro when strings share a prefix", () => {
    // Any pair with a non-empty common prefix and jaro < 1 must have jw > jaro
    const pairs: [string, string][] = [
      ["MARTHA", "MARHTA"],
      ["DWAYNE", "DUANE"],
      ["DIXON", "DICKSONX"],
    ];
    for (const [a, b] of pairs) {
      const jaro = computeJaro(a, b);
      const jw = computeJaroWinkler(a, b);
      expect(jw).toBeGreaterThan(jaro);
    }
  });

  it("prefix bonus is capped at 4 characters", () => {
    // "ABCDE" vs "ABCDZ": first 4 chars match (ABCD), 5th differs (E vs Z)
    // window = max(5,5)/2-1 = 1
    // Matching: A(0),B(1),C(2),D(3) match at positions 0-3; E(4) looks at [3..4]: D(matched),Z no match
    // m=4, t=0; jaro = (4/5 + 4/5 + 4/4) / 3 = (0.8+0.8+1)/3 = 2.6/3 ≈ 0.8667
    // l=4 (A,B,C,D match; E≠Z) — prefix capped at 4
    // jw = 0.8667 + 4*0.1*(1-0.8667) = 0.8667 + 0.4*0.1333 = 0.8667 + 0.0533 = 0.92
    expect(computeJaroWinkler("ABCDE", "ABCDZ")).toBe(0.92);

    // "ABCDEF" vs "ABCDEZ": same first 4 chars matched by window but prefix l is still 4 (not 5)
    // because ABCDE vs ABCDEZ: A=A,B=B,C=C,D=D,E=E but 6th char F≠Z. However we need
    // to compare with a 5-char identical prefix to confirm the cap. Use "ABCDEF" vs "ABCDEZ":
    // prefix: A,B,C,D,E — 5 match, but capped at 4.
    const jwFivePrefixMatch = computeJaroWinkler("ABCDEF", "ABCDEZ");
    const jwFourPrefixMatch = computeJaroWinkler("ABCDE", "ABCDZ");
    // Both have 4 prefix chars contributing to the bonus (cap at 4 vs cap at 4)
    // The l*p*(1-jaro) term is the same for both if jaro happens to be the same — but the
    // key invariant is that adding a 5th matching prefix char does NOT increase jw further.
    // We verify by showing the 5-prefix result does not exceed what l=4 gives.
    const jaroSixSix = computeJaro("ABCDEF", "ABCDEZ");
    const expectedFivePrefix = jaroSixSix + 4 * 0.1 * (1 - jaroSixSix);
    expect(jwFivePrefixMatch).toBeCloseTo(expectedFivePrefix, 4);
    // And the 4-prefix result does match
    expect(jwFourPrefixMatch).toBeCloseTo(computeJaro("ABCDE", "ABCDZ") + 4 * 0.1 * (1 - computeJaro("ABCDE", "ABCDZ")), 4);
  });

  it("custom prefixScalingFactor changes the bonus proportionally", () => {
    // With p=0, the Jaro-Winkler score equals the Jaro score regardless of prefix
    expect(computeJaroWinkler("MARTHA", "MARHTA", 0)).toBe(computeJaro("MARTHA", "MARHTA"));

    // With p=0.2 (double the default 0.1), the bonus is doubled
    const jaro = computeJaro("MARTHA", "MARHTA"); // 0.9444, l=3
    const jwDefault = computeJaroWinkler("MARTHA", "MARHTA", 0.1);
    const jwDouble = computeJaroWinkler("MARTHA", "MARHTA", 0.2);
    // bonus at p=0.1: 3*0.1*(1-jaro); bonus at p=0.2: 3*0.2*(1-jaro) = double
    const bonusDefault = jwDefault - jaro;
    const bonusDouble = jwDouble - jaro;
    expect(bonusDouble).toBeCloseTo(bonusDefault * 2, 4);
  });

  it("jaroWinkler >= jaro always (with non-negative scaling factor)", () => {
    const pairs: [string, string][] = [
      ["MARTHA", "MARHTA"],
      ["DWAYNE", "DUANE"],
      ["", ""],
      ["", "abc"],
      ["abc", "xyz"],
    ];
    for (const [a, b] of pairs) {
      expect(computeJaroWinkler(a, b)).toBeGreaterThanOrEqual(computeJaro(a, b));
    }
  });
});
