import { describe, expect, it } from "vitest";
import {
  computeLexicalHeuristics,
  computePronounceability,
  computeRandomLookingCandidate,
  isLikelyNaturalToken,
} from "../src/index.js";
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

  it("does not flag readable run-4 words with a low vowel ratio (false-positive guard)", () => {
    // Regression for issue #87: a readable word can pair a run-4 consonant cluster
    // with a vowel ratio below the pronounceable floor, so pronounceability cannot
    // vouch for it. `strength` (`ngth` = run 4, A/E/I/O/U ratio 1/8) is the reviewer's
    // example; `blindspots` (`ndsp` = run 4, ratio 0.2) is a readable compound word.
    // The run floor is 5, so neither reaches the low-vowel branch and neither is
    // flagged on shape alone — leaving run-4 word-shaped tokens to a caller's corpus.
    expect(computePronounceability("strength").looksPronounceable).toBe(false);
    expect(computeRandomLookingCandidate("strength")).toBe(false);
    expect(computeRandomLookingCandidate("blindspots")).toBe(false);

    // A vowel-starved label with a run of 5 or more is still flagged: the run-5+
    // shape is not shared with readable words, so it needs no pronounceability guard.
    expect(computePronounceability("qwrtplkjhg").looksPronounceable).toBe(false);
    expect(computeRandomLookingCandidate("qwrtplkjhg")).toBe(true);
  });

  it("does not flag pronounceable labels where `y` acts as a vowel", () => {
    // `y` counts as a consonant for maxConsonantRun, so ordinary words that use `y`
    // as a vowel can inflate a run and drop the A/E/I/O/U vowel ratio below the floor.
    // `crypto` (run `crypt` = 5, A/E/I/O/U ratio 1/6) reaches the low-vowel branch,
    // but reading `y` as a vowel leaves only short non-`y` runs (`cr`/`pt` = 2), so it
    // clears the guard and is not flagged. `python` and `system` (run 4) stay below
    // the run floor entirely.
    for (const label of ["crypto", "python", "system"]) {
      expect(computePronounceability(label).looksPronounceable, label).toBe(false);
      expect(computeRandomLookingCandidate(label), label).toBe(false);
    }

    // The guard is narrow: a generated label whose only vowel-shaped character is a
    // single `y` still has a real vowel ratio at or below the floor and stays flagged.
    expect(computeRandomLookingCandidate("mpqxyt")).toBe(true);
  });

  it("keeps the y-guard from exempting generated consonant runs (issue #87)", () => {
    // Regression: a label with one real vowel plus a single `y` (`mpqxyta`,
    // vowelRatio 1/7, maxConsonantRun 6) must stay flagged. A y-inclusive vowel-ratio
    // guard wrongly cleared it because 2/7 exceeds the 0.2 floor, but reading `y` as a
    // vowel still leaves a `mpqx` = 4 non-`y` run — longer than a genuine y-as-vowel
    // word (`crypto`: 2, `strychnine`: `str`/`chn` = 3) — so the lone `y` must not
    // rescue it.
    expect(computePronounceability("mpqxyta").looksPronounceable).toBe(false);
    expect(computeRandomLookingCandidate("mpqxyta")).toBe(true);

    // The exemption still holds for a real word whose non-`y` clusters stay short,
    // even at the run-3 ceiling: `strychnine` (real vowels i/e, run `strych` = 6,
    // non-`y` runs `str`/`chn` = 3) is not flagged, while a vowel-free run (`mpqxyt`)
    // is not rescued at all because the guard requires a real A/E/I/O/U vowel.
    expect(computeRandomLookingCandidate("strychnine")).toBe(false);
    expect(computeRandomLookingCandidate("mpqxyt")).toBe(true);
  });

  it("still flags vowel-free y-heavy all-consonant runs", () => {
    // Regression guard: the y-inclusive vowel-ratio veto must not rescue labels with
    // no A/E/I/O/U vowel at all. `bcyydf` (y-inclusive ratio 2/6) and `yyyyyy`
    // (y-inclusive ratio 6/6) both sit above the floor, but their real vowel ratio is
    // 0 and `y` only reads as a vowel by absence of any other. Both are all-consonant
    // (maxConsonantRun 6) and unpronounceable, so they stay flagged and keep feeding
    // the random-looking local/domain-label composites.
    for (const label of ["bcyydf", "yyyyyy"]) {
      expect(computePronounceability(label).looksPronounceable, label).toBe(false);
      expect(computeRandomLookingCandidate(label), label).toBe(true);
    }
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
      "anthropic",
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

describe("computePronounceability", () => {
  it("treats readable brand-like labels as pronounceable", () => {
    // The issue-87 regression set: readable, brand-like or compound-word labels
    // that a naive vowel/consonant-run rule can mistake for random. Each keeps a
    // short consonant cluster and enough vowels, so the guard vouches for them.
    for (const label of [
      "anthropic",
      "crowdworks",
      "switchbot",
      "github",
      "salesforce",
      "newsletter",
      "marketing",
      "information",
    ]) {
      expect(computePronounceability(label).looksPronounceable, label).toBe(true);
    }
  });

  it("does not vouch for vowel-starved or long-consonant-cluster tokens", () => {
    // No vowel at all — an unpronounceable consonant pile.
    expect(computePronounceability("mpqxyt").looksPronounceable).toBe(false);
    expect(computePronounceability("qwrtplkjhg").looksPronounceable).toBe(false);
    // A vowel exists but the consonant cluster is too long to pronounce.
    expect(computePronounceability("eabcdfghi").looksPronounceable).toBe(false);
    // Vowel ratio below the floor (one vowel in an alphabet-style run).
    expect(computePronounceability("bcdefgh").looksPronounceable).toBe(false);
    // A vowel-free token has no syllable structure.
    expect(computePronounceability("").looksPronounceable).toBe(false);
  });

  it("reports the structural fields it derives the verdict from", () => {
    // "anthropic": 9 letters, vowels a/o/i, one vowel per group (3 syllables),
    // longest consonant cluster "nthr" = 4.
    expect(computePronounceability("anthropic")).toEqual({
      alphaLength: 9,
      vowelCount: 3,
      vowelRatio: 0.3333,
      syllableEstimate: 3,
      maxConsonantCluster: 4,
      looksPronounceable: true,
    });
  });

  it("classifies y as a consonant and ignores non-letters when clustering", () => {
    // "system": "syst" is a 4-consonant cluster because y extends the run rather
    // than breaking it (as a vowel it would cap the cluster at 2).
    expect(computePronounceability("system").maxConsonantCluster).toBe(4);
    // A hyphen resets the cluster the way maxConsonantRun does, so "ab-cd" never
    // forms a run longer than each side.
    expect(computePronounceability("ab-cd").maxConsonantCluster).toBe(2);
  });
});

describe("isLikelyNaturalToken as a data-free naturalness guard", () => {
  it("keeps readable brand-like labels from being flagged on the naturalness path", () => {
    // A crude word-list model that has never seen these labels would reject them
    // and turn them into random-looking candidates. Passing the data-free
    // isLikelyNaturalToken instead accepts any pronounceable token, so the
    // issue-87 false positives stay unflagged even on the corpus-dependent path.
    for (const label of ["anthropic", "crowdworks", "switchbot"]) {
      expect(isLikelyNaturalToken(label), label).toBe(true);
      expect(
        computeRandomLookingCandidate(label, { isNatural: isLikelyNaturalToken }),
        label,
      ).toBe(false);
    }
  });

  it("keeps y-as-vowel words natural so passing it as isNatural does not re-flag them", () => {
    // Regression for issue #87 review: computePronounceability counts `y` as a
    // consonant, so these readable labels read unpronounceable on their own. The
    // structural detector's low-vowel branch already exempts them via its y-guard,
    // and isLikelyNaturalToken must agree — otherwise a caller that followed the docs
    // and passed it as isNatural would see them re-flagged on the corpus branch.
    for (const label of ["crypto", "python", "system", "strychnine"]) {
      expect(isLikelyNaturalToken(label), label).toBe(true);
      expect(
        computeRandomLookingCandidate(label, { isNatural: isLikelyNaturalToken }),
        label,
      ).toBe(false);
    }
    // The rescue stays narrow: a vowel-free label reads `y` as a vowel only by the
    // absence of any real vowel, so it is not vouched for and stays flagged.
    for (const label of ["mpqxyt", "bcyydf", "yyyyyy"]) {
      expect(isLikelyNaturalToken(label), label).toBe(false);
    }
  });

  it("still flags generated labels regardless of the naturalness model", () => {
    // Vowel-starved generated shapes are not pronounceable and fire on their own
    // structural branch.
    for (const label of ["x9z8q2w1", "mpqxyt"]) {
      expect(isLikelyNaturalToken(label), label).toBe(false);
      expect(
        computeRandomLookingCandidate(label, { isNatural: isLikelyNaturalToken }),
        label,
      ).toBe(true);
    }
    // The digit/hex/alternation/uppercase branches are intentionally *not* guarded
    // by pronounceability: a hex fragment (`deadbeef`) and a shouty all-caps token
    // (`CAQLEV`) both read as pronounceable *shapes*, yet stay flagged because
    // those shapes are machine-generated markers regardless of syllable structure.
    for (const label of ["deadbeef", "CAQLEV"]) {
      expect(isLikelyNaturalToken(label), label).toBe(true);
      expect(
        computeRandomLookingCandidate(label, { isNatural: isLikelyNaturalToken }),
        label,
      ).toBe(true);
    }
    // An all-letter token the structural low-vowel band misses (its vowel ratio is
    // fine) but whose long consonant cluster gives it away is caught via the
    // naturalness path once isLikelyNaturalToken declines to vouch for it.
    expect(computeRandomLookingCandidate("eabcdfghi")).toBe(false);
    expect(
      computeRandomLookingCandidate("eabcdfghi", { isNatural: isLikelyNaturalToken }),
    ).toBe(true);
  });
});
