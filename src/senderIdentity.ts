import { computeDisplayNameBrandInference } from "./brandInference.js";
import {
  allDomainsMatch,
  extractEmbeddedDomains,
  parseFromMailbox,
  registrableDomainsMatch,
} from "./domains.js";
import { computeRegistrableLabelNaturalness } from "./labelNaturalness.js";
import { getRegistrableDomain as builtinGetRegistrableDomain } from "./psl.js";
import { lookupPublicMailboxProvider } from "./publicMailboxProviders.js";
import type {
  DisplayNameDerivedMetrics,
  DisplayNameMetrics,
  DisplayNameNormalization,
  DisplayNameSignals,
  DomainLabelMetrics,
  DomainParts,
  LexicalHeuristics,
  LexicalStats,
  MetricsDependencies,
  Pronounceability,
  SenderIdentityMetrics,
} from "./types.js";

/**
 * Compute codepoint-based lexical statistics for a token (see LexicalStats). No
 * external word list or dictionary is consulted — only structural counts that an
 * attacker cannot launder away by choosing a benign-looking domain.
 */
export function computeLexicalStats(value: string): LexicalStats {
  let length = 0;
  let digitCount = 0;
  let hyphenCount = 0;
  let hasNonAscii = false;
  for (const char of value) {
    length++;
    if (char >= "0" && char <= "9") digitCount++;
    else if (char === "-") hyphenCount++;
    if ((char.codePointAt(0) ?? 0) > 0x7f) hasNonAscii = true;
  }
  return { length, digitCount, hyphenCount, hasNonAscii };
}

/**
 * Round a floating-point metric to 4 decimal places so heuristics serialize to a
 * stable, cross-language-comparable value (avoiding 0.30000000000000004 drift in
 * fixtures). Integer-valued metrics never pass through here.
 */
function round4(value: number): number {
  return Math.round(value * 1e4) / 1e4;
}

const ASCII_VOWELS = new Set(["a", "e", "i", "o", "u"]);

function isAsciiLetter(char: string): boolean {
  return (char >= "a" && char <= "z") || (char >= "A" && char <= "Z");
}

/** Whether a single character is an ASCII hexadecimal digit (0-9, a-f, A-F). */
function isAsciiHexChar(char: string): boolean {
  return (
    (char >= "0" && char <= "9") ||
    (char >= "a" && char <= "f") ||
    (char >= "A" && char <= "F")
  );
}

/**
 * Minimum length of a digit-bearing ASCII-hex run before it reads as a hash / GUID
 * fragment (LexicalHeuristics.hasLongHexLikeRun). Six matches the add-on metric
 * being migrated: it keeps short ordinary fragments like "abc12" (run length 5)
 * from qualifying while still catching genuine hash/GUID-length hex runs.
 */
const HEX_LIKE_RUN_MIN_LENGTH = 6;

/**
 * Compute the richer, data-free lexical heuristics for a token (see
 * LexicalHeuristics). Like computeLexicalStats it consults no external word list,
 * dictionary, language corpus, or n-gram table — only the token itself. Counts
 * and codepoints are codepoint-based; letter/vowel/consonant classification is
 * ASCII-only (a non-ASCII codepoint still counts toward length, entropy, the
 * unique ratio, and repeated runs, but is not treated as a letter).
 */
export function computeLexicalHeuristics(value: string): LexicalHeuristics {
  const chars = [...value];
  const length = chars.length;
  if (length === 0) {
    return {
      shannonEntropy: 0,
      normalizedEntropy: 0,
      vowelRatio: 0,
      digitRatio: 0,
      hyphenRatio: 0,
      maxHexRun: 0,
      maxConsonantRun: 0,
      maxRepeatedCharRun: 0,
      uniqueCharRatio: 0,
      letterDigitTransitions: 0,
      alphaLength: 0,
      vowelCount: 0,
      vowelRatioAlphaOnly: 0,
      hyphenCount: 0,
      uniqueCharCount: 0,
      letterDigitTransitionCount: 0,
      hasLongHexLikeRun: false,
    };
  }

  const frequencies = new Map<string, number>();
  let letterCount = 0;
  let vowelCount = 0;
  // vowelCountY also counts 'y' as a vowel (see vowelRatioAlphaOnly); vowelCount
  // stays y-exclusive to keep vowelRatio's existing meaning.
  let vowelCountY = 0;
  let digitCount = 0;
  let hyphenCount = 0;
  let consonantRun = 0;
  let maxConsonantRun = 0;
  let hexRun = 0;
  let maxHexRun = 0;
  // Tracks whether the current hex run contains a digit, so a pure-letter run
  // (e.g. "deadbeef") never sets hasLongHexLikeRun.
  let hexRunHasDigit = false;
  let hasLongHexLikeRun = false;
  let repeatedRun = 1;
  let maxRepeatedCharRun = 1;
  let letterDigitTransitions = 0;
  // Symbol-skipping letter/digit alternation: the alphanumeric class last seen,
  // carried across intervening non-alphanumeric characters.
  let letterDigitTransitionCount = 0;
  let lastAlnumClass: "letter" | "digit" | null = null;

  for (let index = 0; index < length; index++) {
    const char = chars[index] as string;
    frequencies.set(char, (frequencies.get(char) ?? 0) + 1);

    const letter = isAsciiLetter(char);
    const digit = char >= "0" && char <= "9";
    if (digit) digitCount++;
    if (char === "-") hyphenCount++;
    if (letter) {
      letterCount++;
      const lower = char.toLowerCase();
      if (ASCII_VOWELS.has(lower)) {
        vowelCount++;
        vowelCountY++;
        consonantRun = 0;
      } else {
        // 'y' counts as a consonant for run length (an unbroken consonant cluster)
        // but as a vowel for the y-inclusive vowelCountY ratio.
        if (lower === "y") vowelCountY++;
        consonantRun++;
        if (consonantRun > maxConsonantRun) maxConsonantRun = consonantRun;
      }
    } else {
      consonantRun = 0;
    }

    if (isAsciiHexChar(char)) {
      hexRun++;
      if (hexRun > maxHexRun) maxHexRun = hexRun;
      if (digit) hexRunHasDigit = true;
      if (hexRun >= HEX_LIKE_RUN_MIN_LENGTH && hexRunHasDigit) hasLongHexLikeRun = true;
    } else {
      hexRun = 0;
      hexRunHasDigit = false;
    }

    // Symbol-skipping letter/digit alternation: a non-alphanumeric character is
    // skipped (it does not reset lastAlnumClass), so "ab-12" still records the
    // letter->digit change the adjacency-based letterDigitTransitions misses.
    if (letter || digit) {
      const alnumClass = letter ? "letter" : "digit";
      if (lastAlnumClass !== null && lastAlnumClass !== alnumClass) {
        letterDigitTransitionCount++;
      }
      lastAlnumClass = alnumClass;
    }

    if (index > 0) {
      const prev = chars[index - 1] as string;
      if (char === prev) {
        repeatedRun++;
        if (repeatedRun > maxRepeatedCharRun) maxRepeatedCharRun = repeatedRun;
      } else {
        repeatedRun = 1;
      }
      const prevLetter = isAsciiLetter(prev);
      const prevDigit = prev >= "0" && prev <= "9";
      if ((prevLetter && digit) || (prevDigit && letter)) letterDigitTransitions++;
    }
  }

  let shannonEntropy = 0;
  for (const count of frequencies.values()) {
    const probability = count / length;
    shannonEntropy -= probability * Math.log2(probability);
  }

  // Max possible entropy for a token of this length is log2(length), reached when
  // every codepoint is distinct; dividing by it yields a length-independent [0, 1]
  // value. Length 1 has zero spread (log2(1) === 0), so report 0 rather than 0/0.
  const normalizedEntropy = length > 1 ? shannonEntropy / Math.log2(length) : 0;

  return {
    shannonEntropy: round4(shannonEntropy),
    normalizedEntropy: round4(normalizedEntropy),
    vowelRatio: letterCount > 0 ? round4(vowelCount / letterCount) : 0,
    digitRatio: round4(digitCount / length),
    hyphenRatio: round4(hyphenCount / length),
    maxHexRun,
    maxConsonantRun,
    maxRepeatedCharRun,
    uniqueCharRatio: round4(frequencies.size / length),
    letterDigitTransitions,
    alphaLength: letterCount,
    vowelCount: vowelCountY,
    vowelRatioAlphaOnly: letterCount > 0 ? round4(vowelCountY / letterCount) : 0,
    hyphenCount,
    uniqueCharCount: frequencies.size,
    letterDigitTransitionCount,
    hasLongHexLikeRun,
  };
}

/**
 * Structural gates for computePronounceability, tuned against the readable
 * brand-like labels that made naive vowel/consonant-run rules misfire.
 *
 *   - maxConsonantCluster <= 4: a natural word breaks its consonants with vowels,
 *     so its longest cluster stays short. `anthropic` ("nthr" = 4) and `switchbot`
 *     ("tchb" = 4) sit right at the ceiling; `crowdworks` ("wdw" = 3) is under it,
 *     while `mpqxyt` (6) and `qwrtplkjhg` (10) blow past it.
 *   - vowelRatio >= 0.2: even a consonant-heavy word keeps roughly one vowel per
 *     five letters. `crowdworks` is exactly at the floor (2 / 10); vowel-starved
 *     runs such as `mpqxyt` (0) and alphabet-style strings such as `bcdefgh`
 *     (1 / 7 ≈ 0.14) fall below it. Set equal to RANDOM_LOOKING_MAX_VOWEL_RATIO so
 *     the "pronounceable" and "low-vowel random" bands meet without a gap.
 *
 * A token must also carry at least one vowel; a vowel-free run can never be
 * pronounceable regardless of its cluster length.
 */
const PRONOUNCEABLE_MAX_CONSONANT_CLUSTER = 4;
const PRONOUNCEABLE_MIN_VOWEL_RATIO = 0.2;

/**
 * Compute the data-free structural pronounceability of a token (see
 * Pronounceability), the false-positive guard for the random-looking heuristics.
 *
 * Like every helper in this module it consults **no** bundled word list, brand
 * dictionary, language corpus, or n-gram table — only the token's own shape. It
 * measures the syllable structure a naive vowel/consonant-run rule ignores: a
 * pronounceable word interleaves vowels and consonants so its consonant clusters
 * stay short and its vowels recur, whereas a generated label piles consonants into
 * long, vowel-starved runs. Classification is ASCII-only and `y` counts as a
 * consonant (treating it as a vowel would let more gibberish read as pronounceable).
 *
 * This is deliberately one-sided: it recognizes a pronounceable *shape* to
 * *suppress* a false random-looking verdict, and it never asserts a token is
 * gibberish. A structurally word-like token it cannot separate from a real word
 * (e.g. `wlikqkgi`, indistinguishable by shape from `switchbot`) still reads
 * pronounceable here — the guard errs toward not flagging, leaving that residual
 * class to a caller's own corpus (see computeRandomLookingCandidate / isNatural).
 */
export function computePronounceability(value: string): Pronounceability {
  let alphaLength = 0;
  let vowelCount = 0;
  let syllableEstimate = 0;
  let inVowelGroup = false;
  let consonantCluster = 0;
  let maxConsonantCluster = 0;

  for (const char of value) {
    if (!isAsciiLetter(char)) {
      // A non-letter (digit, hyphen, non-ASCII codepoint) breaks a consonant
      // cluster and ends any vowel group, exactly like maxConsonantRun.
      consonantCluster = 0;
      inVowelGroup = false;
      continue;
    }
    alphaLength++;
    if (ASCII_VOWELS.has(char.toLowerCase())) {
      vowelCount++;
      consonantCluster = 0;
      // Count one syllable per maximal run of adjacent vowels.
      if (!inVowelGroup) {
        syllableEstimate++;
        inVowelGroup = true;
      }
    } else {
      // `y` is classified as a consonant here (conservative — see the doc comment).
      inVowelGroup = false;
      consonantCluster++;
      if (consonantCluster > maxConsonantCluster) maxConsonantCluster = consonantCluster;
    }
  }

  const vowelRatio = alphaLength > 0 ? round4(vowelCount / alphaLength) : 0;
  const looksPronounceable =
    alphaLength > 0 &&
    vowelCount > 0 &&
    maxConsonantCluster <= PRONOUNCEABLE_MAX_CONSONANT_CLUSTER &&
    vowelRatio >= PRONOUNCEABLE_MIN_VOWEL_RATIO;

  return {
    alphaLength,
    vowelCount,
    vowelRatio,
    syllableEstimate,
    maxConsonantCluster,
    looksPronounceable,
  };
}

/**
 * A conservative, data-free naturalness predicate suitable for passing directly as
 * RandomLookingOptions.isNatural. Backed by computePronounceability, it treats a
 * token as "natural" when it has the syllable shape of a pronounceable word.
 *
 * It exists so a caller can close the corpus-dependent gap in
 * computeRandomLookingCandidate *without* maintaining a word list or bigram model
 * that would mis-reject readable brand-like labels — the exact false positive
 * (`anthropic`, `crowdworks`) this guard targets. A crude model that has never
 * seen "anthropic" rejects it and turns it into a random-looking candidate;
 * isLikelyNaturalToken accepts any pronounceable token, so those labels stay
 * unflagged while genuinely unpronounceable generated labels still read random.
 *
 * The tradeoff is intended: because pronounceability is judged by shape alone, a
 * word-like gibberish label such as `wlikqkgi` also reads natural here, so a
 * caller that must catch that residual class should supply its own corpus-backed
 * predicate instead. This one favors *not* flagging readable labels.
 *
 * It applies the same y-as-vowel guard as computeRandomLookingCandidate's low-vowel
 * branch. computePronounceability counts `y` as a consonant, so a readable label
 * where `y` does a vowel's work (`crypto`, `python`, `system`, `strychnine`) exceeds
 * its consonant-cluster ceiling and reads unpronounceable. Left uncorrected, a caller
 * that followed the docs and passed this helper as isNatural would see those labels
 * re-flagged on the corpus branch — the very class the structural y-guard exempts by
 * default. So a token the plain pronounceability check rejects is still accepted when,
 * exactly as in that guard, it carries a real A/E/I/O/U vowel and reading `y` as a
 * vowel leaves its remaining consonant run short (<= RANDOM_LOOKING_Y_VOWEL_MAX_RUN).
 * A vowel-free label (`yyyyyy`, `mpqxyt`) reads `y` as a vowel only by absence of any
 * other and is not rescued.
 */
export function isLikelyNaturalToken(token: string): boolean {
  const pronounceability = computePronounceability(token);
  if (pronounceability.looksPronounceable) return true;
  // Mirror the detector's y-as-vowel guard so the two agree on this word class.
  return (
    pronounceability.vowelCount > 0 &&
    maxConsonantRunTreatingYAsVowel(token) <= RANDOM_LOOKING_Y_VOWEL_MAX_RUN
  );
}

/** Matches a single Latin-script codepoint (excludes ASCII — checked separately). */
const LATIN_SCRIPT_RE = /\p{Script=Latin}/u;

/** Matches any Unicode combining mark (Category M), used to strip diacritics after NFD. */
const COMBINING_MARK_RE = /\p{M}/gu;

/** Single-codepoint test for combining marks (no `g` flag to avoid stateful lastIndex). */
const COMBINING_MARK_TEST_RE = /\p{M}/u;

/** Single-codepoint test for Script=Common (script-neutral: punctuation, symbols, spaces). */
const SCRIPT_COMMON_TEST_RE = /\p{Script=Common}/u;

/**
 * Classify the script composition of a display-name text and compute the
 * Latin-folded form (NFD + strip combining marks) when it is safe to do so.
 *
 * Folding is safe only when every non-ASCII codepoint in the text belongs to the
 * Latin script. If any non-ASCII codepoint is Cyrillic, Greek, CJK, etc., folding
 * is suppressed (latinFolded = null) to prevent homoglyph text from silently
 * comparing equal to a Latin brand name.
 *
 * hasMixedScript flags the lookalike-attack pattern: a display name that mixes
 * Latin characters with non-Latin-script non-ASCII codepoints (e.g. Cyrillic `Н`
 * alongside Latin `ERMES`). This is the case an attacker exploits to make a
 * Cyrillic name look like a Latin brand without triggering the non-ASCII flag.
 */
function computeLatinFolding(text: string): {
  latinFolded: string | null;
  latinFoldedChanged: boolean;
  hasNonLatinScript: boolean;
  hasMixedScript: boolean;
} {
  let hasLatinChar = false;
  let hasNonLatinNonAscii = false;

  for (const char of text) {
    const cp = char.codePointAt(0) ?? 0;
    if (cp > 0x7f) {
      if (COMBINING_MARK_TEST_RE.test(char)) {
        // Combining marks have Script=Inherited — skip; they attach to the
        // preceding base character and must not vote as non-Latin.
      } else if (SCRIPT_COMMON_TEST_RE.test(char)) {
        // Script=Common characters (punctuation, symbols, spaces such as ™, ©,
        // non-breaking space) are script-neutral and must not vote as non-Latin.
      } else if (LATIN_SCRIPT_RE.test(char)) {
        hasLatinChar = true;
      } else {
        hasNonLatinNonAscii = true;
      }
    } else if (isAsciiLetter(char)) {
      hasLatinChar = true;
    }
  }

  const hasNonLatinScript = hasNonLatinNonAscii;
  const hasMixedScript = hasNonLatinNonAscii && hasLatinChar;

  if (hasNonLatinNonAscii) {
    return { latinFolded: null, latinFoldedChanged: false, hasNonLatinScript, hasMixedScript };
  }

  const folded = text.normalize("NFD").replace(COMBINING_MARK_RE, "");
  return {
    latinFolded: folded,
    latinFoldedChanged: folded !== text,
    hasNonLatinScript,
    hasMixedScript,
  };
}

/**
 * Thresholds for computeRandomLookingCandidate. Each branch captures a distinct
 * shape of machine-generated / obfuscated token; a caller still owns the final
 * verdict (this returns a candidate flag, never a score).
 *
 * The length floor is 6 to match the add-on's domain-label check, which flags
 * short all-consonant labels such as `mpqxyt` (length 6, vowel ratio 0, consonant
 * run 6). Tuned so that known false-positive brand/word labels from the add-on's
 * history (`switchbot`, `crowdworks`, and similar low-vowel but pronounceable
 * words) still read false: those keep a vowel ratio at or above the floor and a
 * consonant run no longer than a pronounceable word's, no digits, no hex run, and
 * no letter/digit alternation, so none of the structural branches fire.
 *
 * RANDOM_LOOKING_MIN_CONSONANT_RUN is 5 — one past the longest consonant cluster a
 * pronounceable word is allowed (PRONOUNCEABLE_MAX_CONSONANT_CLUSTER, 4). A run of
 * exactly 4 is not a reliable random-looking marker on its own: readable words
 * carry run-4 clusters with a low A/E/I/O/U ratio (`strength`: `ngth`, vowel ratio
 * 1/8; `blindspots`: `ndsp`, vowel ratio 0.2), and no purely structural test
 * separates them from a generated run-4 label — computePronounceability cannot
 * rescue `strength` either, since its 0.2 vowel floor rejects the word as well.
 * Requiring run >= 5 keeps those readable labels out of the low-vowel branch
 * entirely (matching the add-on's own >= 5 threshold), while `mpqxyt` (run 6) and
 * `qwrtplkjhg` (run 10) still trip it. Word-shaped run-4 gibberish is instead left
 * to the caller's corpus branch (see RandomLookingOptions.isNatural).
 */
const RANDOM_LOOKING_MIN_LENGTH = 6;
const RANDOM_LOOKING_MIN_DIGIT_RATIO = 0.4;
const RANDOM_LOOKING_MIN_LETTER_DIGIT_TRANSITIONS = 4;
const RANDOM_LOOKING_MIN_HEX_RUN = 8;
const RANDOM_LOOKING_MAX_VOWEL_RATIO = 0.2;
const RANDOM_LOOKING_MIN_CONSONANT_RUN = 5;

/**
 * Ceiling on the non-`y` consonant run that still lets the low-vowel branch's
 * y-guard read `y` as the label's vowel. A genuine y-as-vowel word keeps its other
 * consonant clusters short — `crypto` (`cr`/`pt` = 2) and `strychnine` (`str`/`chn`
 * = 3) sit at or below 3 — so the run only reached RANDOM_LOOKING_MIN_CONSONANT_RUN
 * because `y` was counted inside it. A label whose non-`y` consonants still cluster
 * to 4 or more (`mpqxyta`: `mpqx`) is not pronounceable no matter how `y` is read, so
 * a single `y` must not rescue it. Set at RANDOM_LOOKING_MIN_CONSONANT_RUN - 2.
 */
const RANDOM_LOOKING_Y_VOWEL_MAX_RUN = RANDOM_LOOKING_MIN_CONSONANT_RUN - 2;

/**
 * Longest run of consecutive consonants when `y` is read as a vowel (so it breaks a
 * run rather than extending it), mirroring maxConsonantRun's treatment of vowels
 * and non-letters. Used only by the random-looking y-guard to tell a label whose
 * consonant run only reaches the floor because `y` sits inside it (`crypto`,
 * `strychnine`) from one with a genuinely long non-`y` cluster (`mpqxyta`: `mpqx` = 4).
 */
function maxConsonantRunTreatingYAsVowel(value: string): number {
  let run = 0;
  let max = 0;
  for (const char of value) {
    if (!isAsciiLetter(char)) {
      run = 0;
      continue;
    }
    const lower = char.toLowerCase();
    if (ASCII_VOWELS.has(lower) || lower === "y") {
      run = 0;
    } else {
      run++;
      if (run > max) max = run;
    }
  }
  return max;
}

/** Whether every character is an ASCII uppercase letter (A-Z). False for "". */
function isAllAsciiUppercaseLetters(value: string): boolean {
  let any = false;
  for (const char of value) {
    if (!(char >= "A" && char <= "Z")) return false;
    any = true;
  }
  return any;
}

/**
 * Optional inputs to computeRandomLookingCandidate.
 *
 * - isNatural: a caller-supplied naturalness predicate (typically backed by the
 *   caller's own bigram/trigram language model) returning true when a token reads
 *   as a natural, pronounceable word. It exists to close the one parity gap the
 *   structural branches cannot: a structurally word-like token such as `wlikqkgi`
 *   (vowel ratio 0.25, longest consonant run 4) is indistinguishable *by shape
 *   alone* from a real word such as `switchbot` (vowel ratio 0.22, longest
 *   consonant run 4), so no codepoint-only threshold can flag one without the
 *   other. Separating them needs a language-frequency corpus, which this package
 *   deliberately does not bundle (the data/license boundary in AGENTS.md / NOTICE).
 *   When supplied, an all-ASCII-letter token the model rejects is also flagged, so
 *   a caller holding its own corpus reaches full add-on parity; when omitted, the
 *   helper stays purely structural and such tokens read false.
 *
 *   A caller that does *not* want to maintain a corpus can pass the data-free
 *   isLikelyNaturalToken here: it accepts any pronounceable token, which keeps
 *   readable brand-like labels (`anthropic`, `crowdworks`) from being flagged by a
 *   crude word list that has never seen them — the false positive this guard
 *   targets — at the cost of also accepting word-shaped gibberish (see
 *   isLikelyNaturalToken).
 */
export type RandomLookingOptions = {
  isNatural?: (token: string) => boolean;
};

/**
 * Decide whether a single token *looks* randomly generated, ported from the add-on's
 * random-looking local-part / domain-label checks so callers can retire their local
 * copies. The structural branches consult **no** bundled word list, brand
 * dictionary, language corpus, or n-gram table — only the token's own shape.
 *
 * The token must be reasonably long (>= 6 codepoints) and then match any one of
 * these machine-generated shapes:
 *
 *   - a high digit ratio (a numeric-heavy identifier),
 *   - frequent letter/digit alternation (e.g. `x9z8q2w1`),
 *   - a long run of hex characters (a hash / GUID fragment),
 *   - a low vowel ratio paired with a consonant run of at least 5 — one past the
 *     pronounceable ceiling (e.g. `mpqxyt`) — unless `y` genuinely acts as the
 *     label's vowel, i.e. reading `y` as a vowel leaves the remaining consonant run
 *     short (`crypto`, `strychnine`); a label whose non-`y` consonants still cluster
 *     long (`mpqxyta`: `mpqx` = 4) is not rescued by a lone `y`. Readable run-4
 *     words such as `strength` and `blindspots` stay below the run floor and never
 *     reach this branch, or
 *   - the add-on's letters-only uppercase rule: an all-uppercase ASCII-letter
 *     token (e.g. `CAQLEV`) reads as a shouty machine label.
 *
 * One add-on-positive class — structurally word-like gibberish such as `wlikqkgi`
 * — cannot be told apart from real words (`switchbot`) by shape alone and is only
 * flagged when the caller passes a naturalness model (see RandomLookingOptions);
 * this keeps the structural default free of the data/license boundary while still
 * letting a caller reach full parity.
 *
 * This is a policy-neutral candidate flag, not a verdict: legitimate DKIM
 * selectors, hashes, and ESP labels also look random, so a caller decides whether
 * a random-looking token matters in its context. Returns false for an empty token.
 */
export function computeRandomLookingCandidate(
  value: string,
  options?: RandomLookingOptions,
): boolean {
  const chars = [...value];
  // length is codepoint-based, matching the heuristics above.
  if (chars.length < RANDOM_LOOKING_MIN_LENGTH) return false;
  const h = computeLexicalHeuristics(value);
  // False-positive guard for readable brand-like labels. The low-vowel /
  // consonant-run branch below is the only structural branch that keys on word
  // *shape* rather than on machine-generated markers (digits, hex, alternation,
  // shouting caps), so it is the one that can misfire on a readable but vowel-poor
  // word. Two properties keep it narrow:
  //
  //   - The consonant-run floor (RANDOM_LOOKING_MIN_CONSONANT_RUN) is 5, one past
  //     the longest cluster a pronounceable word carries. A run of exactly 4 is
  //     shared by readable words (`strength`, `blindspots`) and generated labels
  //     alike, and no structural test separates them — computePronounceability
  //     included, since its 0.2 vowel floor also rejects `strength` — so run-4
  //     tokens are left to the caller's corpus branch (see isNatural) instead of
  //     being flagged here.
  //   - `y` is counted as a consonant for maxConsonantRun, so an ordinary label
  //     where `y` acts as a vowel (`crypto`: run `crypt` = 5, A/E/I/O/U vowel ratio
  //     1/6) can reach this branch on an inflated run. Rescue such a label only when
  //     `y` genuinely does a vowel's work: read `y` as a vowel and require the
  //     resulting non-`y` consonant run to stay short (<= RANDOM_LOOKING_Y_VOWEL_MAX_RUN,
  //     as in `crypto`: `cr`/`pt` = 2, or `strychnine`: `str`/`chn` = 3). This does *not* rescue
  //     a label whose non-`y` consonants still cluster long — `mpqxyta` (vowelRatio
  //     1/7, maxConsonantRun 6) keeps a `mpqx` = 4 run once `y` is a vowel, so a
  //     single `y` cannot lift it out of the detector (an earlier vowelRatioAlphaOnly
  //     ratio guard wrongly did, suppressing downstream composite signals). The
  //     rescue also requires a real A/E/I/O/U vowel (vowelRatio > 0): a vowel-free
  //     label reads `y` as a vowel purely by absence of any other, so a y-heavy
  //     all-consonant run (`bcyydf`, `yyyyyy`: maxConsonantRun 6) stays flagged.
  //
  // The digit/hex/alternation/uppercase branches are intentionally *not* guarded:
  // those shapes read as generated regardless of pronounceability (e.g. the
  // pronounceable-looking but shouting `CAQLEV`).
  if (
    h.digitRatio >= RANDOM_LOOKING_MIN_DIGIT_RATIO ||
    h.letterDigitTransitionCount >= RANDOM_LOOKING_MIN_LETTER_DIGIT_TRANSITIONS ||
    h.maxHexRun >= RANDOM_LOOKING_MIN_HEX_RUN ||
    (h.vowelRatio <= RANDOM_LOOKING_MAX_VOWEL_RATIO &&
      h.maxConsonantRun >= RANDOM_LOOKING_MIN_CONSONANT_RUN &&
      !(h.vowelRatio > 0 &&
        maxConsonantRunTreatingYAsVowel(value) <= RANDOM_LOOKING_Y_VOWEL_MAX_RUN)) ||
    isAllAsciiUppercaseLetters(value)
  ) {
    return true;
  }
  // Corpus-dependent branch: only consult the model for an all-ASCII-letter,
  // word-shaped token, and only when the caller supplied one.
  if (options?.isNatural && h.alphaLength === chars.length && !options.isNatural(value)) {
    return true;
  }
  return false;
}

/**
 * Minimum whitespace-separated tokens, minimum single-letter tokens, and the
 * single-letter share required before a display name reads as letter-spacing
 * camouflage. Tuned (see DisplayNameSignals) so a fully or mostly spaced brand
 * name fires while normal multi-word names and one- or two-initial names do not.
 */
const SPACED_CAMOUFLAGE_MIN_TOKENS = 3;
const SPACED_CAMOUFLAGE_MIN_SINGLE_LETTER_TOKENS = 3;
const SPACED_CAMOUFLAGE_MIN_SINGLE_LETTER_RATIO = 0.6;

/** A token that is exactly one Unicode letter — the unit a letter-spaced name emits. */
function isSingleLetterToken(token: string): boolean {
  return /^\p{L}$/u.test(token);
}

/**
 * Derive the whitespace-normalization view of a display name (see
 * DisplayNameNormalization, DisplayNameDerivedMetrics, DisplayNameSignals).
 *
 * Compaction removes every run of intra-name whitespace, collapsing a
 * letter-spaced brand name into a single matchable token without consulting any
 * bundled brand list or word list. The camouflage signal is a pure structural
 * judgement on the whitespace-separated tokens; it never inspects the meaning of
 * the token, so it cannot be laundered by choosing a benign-looking brand.
 */
export function computeDisplayNameWhitespace(text: string | null): {
  normalized: DisplayNameNormalization;
  metrics: DisplayNameDerivedMetrics;
  signals: DisplayNameSignals;
} {
  if (text === null) {
    return {
      normalized: { compactedWhitespace: null, latinFolded: null },
      metrics: { whitespaceCompactedChanged: false, latinFoldedChanged: false },
      signals: {
        spacedDisplayNameCamouflageCandidate: false,
        hasNonLatinScript: false,
        hasMixedScript: false,
      },
    };
  }

  const compactedWhitespace = text.replace(/\s+/gu, "");
  const tokens = text.split(/\s+/u).filter((token) => token.length > 0);
  const singleLetterTokens = tokens.filter(isSingleLetterToken).length;

  const spacedDisplayNameCamouflageCandidate =
    tokens.length >= SPACED_CAMOUFLAGE_MIN_TOKENS &&
    singleLetterTokens >= SPACED_CAMOUFLAGE_MIN_SINGLE_LETTER_TOKENS &&
    singleLetterTokens / tokens.length >= SPACED_CAMOUFLAGE_MIN_SINGLE_LETTER_RATIO;

  const { latinFolded, latinFoldedChanged, hasNonLatinScript, hasMixedScript } =
    computeLatinFolding(text);

  return {
    normalized: { compactedWhitespace, latinFolded },
    // Compaction "changed" the token whenever any whitespace was removed.
    metrics: { whitespaceCompactedChanged: compactedWhitespace !== text, latinFoldedChanged },
    signals: { spacedDisplayNameCamouflageCandidate, hasNonLatinScript, hasMixedScript },
  };
}

/**
 * Decompose a normalized domain into its dot-separated labels (see DomainParts).
 * The label fields need no external data; the registrable-domain fields are
 * populated only when a resolver is supplied (the core bundles no PSL data).
 * Per-label consecutive-hyphen and punycode metrics are always computed.
 */
export function computeDomainParts(
  domain: string,
  getRegistrableDomain?: (domain: string) => string | null,
): DomainParts {
  const labels = domain.split(".");
  let registrableDomain: string | null = null;
  let subdomainDepth: number | null = null;
  if (getRegistrableDomain) {
    const resolved = getRegistrableDomain(domain);
    if (resolved) {
      registrableDomain = resolved;
      // Labels above the registrable boundary. Clamp at 0 so a resolver returning
      // a value with more labels than `domain` (an inconsistent resolver) can
      // never produce a negative depth.
      subdomainDepth = Math.max(0, labels.length - resolved.split(".").length);
    }
  }

  // Per-label metrics: punycode detection uses the ACE prefix `xn--`; consecutive
  // hyphens are any `--` occurrence anywhere in the label. Both are computed from
  // normalized (lower-cased) labels so casing variants never escape detection.
  const labelMetrics: DomainLabelMetrics[] = labels.map((label) => ({
    label,
    isPunycode: label.toLowerCase().startsWith("xn--"),
    hasConsecutiveHyphen: label.includes("--"),
  }));

  const hasConsecutiveHyphen = labelMetrics.some((lm) => lm.hasConsecutiveHyphen);
  const hasPunycodeLabel = labelMetrics.some((lm) => lm.isPunycode);
  // A `--` inside an `xn--` label is the ACE encoding marker, not a suspicious
  // pattern; only non-punycode labels with `--` set this flag.
  const hasConsecutiveHyphenOutsidePunycode = labelMetrics.some(
    (lm) => lm.hasConsecutiveHyphen && !lm.isPunycode,
  );

  return {
    domain,
    labels,
    labelCount: labels.length,
    topLabel: labels[labels.length - 1] ?? domain,
    registrableDomain,
    subdomainDepth,
    labelMetrics,
    hasConsecutiveHyphen,
    hasPunycodeLabel,
    hasConsecutiveHyphenOutsidePunycode,
  };
}

/**
 * Build the sender-identity metrics (see SenderIdentityMetrics) from the raw From
 * header value, the already-extracted canonical From domain, the Message-ID
 * domain, and optional runtime dependencies.
 *
 * Pure and serializable: no scoring, no policy. The From domain is taken as an
 * argument (rather than re-parsed) so the local part and the domain decomposition
 * stay consistent with MessageMetrics.fromDomain.
 */
export function computeSenderIdentity(
  fromValue: string | null,
  fromDomain: string | null,
  messageIdDomain: string | null,
  deps?: MetricsDependencies,
): SenderIdentityMetrics {
  const getRegistrableDomain = deps?.getRegistrableDomain;
  // All PSL-backed lookups use the built-in resolver by default; a caller-supplied
  // resolver takes precedence everywhere.
  const structuralResolver = getRegistrableDomain ?? builtinGetRegistrableDomain;
  const publicMailboxProviders = deps?.publicMailboxProviders;
  const parsed = parseFromMailbox(fromValue);

  const displayText = parsed.displayName;
  const embeddedDomains = extractEmbeddedDomains(displayText);
  const whitespace = computeDisplayNameWhitespace(displayText);
  const displayName: DisplayNameMetrics = {
    present: displayText !== null,
    text: displayText,
    length: displayText ? [...displayText].length : 0,
    hasNonAscii: displayText ? computeLexicalStats(displayText).hasNonAscii : false,
    containsEmail: embeddedDomains.length > 0,
    embeddedDomains,
    embeddedDomainMatchesFromDomain: allDomainsMatch(fromDomain, embeddedDomains),
    normalized: whitespace.normalized,
    metrics: whitespace.metrics,
    signals: whitespace.signals,
  };

  // Pair the local part with the canonical From domain. parseFromMailbox mirrors
  // the fromDomain extractor, so when a From domain is present its local part
  // belongs to the same address; when From has no parseable domain there is no
  // address to read a local part from.
  const localPart = fromDomain !== null ? parsed.localPart : null;

  const messageIdRegistrableDomainMatchesFromDomain = registrableDomainsMatch(
    fromDomain,
    messageIdDomain,
    structuralResolver,
  );

  // Public mailbox provider membership of the visible From. Catalog entries are
  // registrable domains, so prefer matching the From *registrable* domain when a
  // PSL resolver is supplied (so `mail.gmail.com` still resolves to "google"),
  // then fall back to the bare From domain (the common case: From is already the
  // registrable domain). Null From belongs to no provider.
  const publicMailboxProviderId = ((): string | null => {
    if (fromDomain === null) return null;
    const fromRegistrable = structuralResolver(fromDomain);
    return (
      lookupPublicMailboxProvider(fromRegistrable, publicMailboxProviders) ??
      lookupPublicMailboxProvider(fromDomain, publicMailboxProviders)
    );
  })();

  // Display-name brand inference is computed only when the caller opts in by
  // supplying a brand catalog (the core bundles none). When omitted, the
  // brandInference field stays absent so consumers that never opt in see no brand
  // surface at all (and existing serialized snapshots are unaffected).
  const brandCatalog = deps?.brandCatalog;
  const brandInference =
    brandCatalog === undefined
      ? undefined
      : computeDisplayNameBrandInference(displayText, fromDomain, brandCatalog, structuralResolver);

  // Registrable-label naturalness is likewise opt-in: the core bundles no
  // frequency table, so the field exists only when the caller supplies a model.
  const fromRegistrableLabelNaturalness =
    deps?.scoreLabelNaturalness === undefined
      ? undefined
      : computeRegistrableLabelNaturalness(fromDomain, {
          getRegistrableDomain: structuralResolver,
          scoreLabelNaturalness: deps.scoreLabelNaturalness,
        });

  return {
    displayName,
    localPart,
    localPartLexical: localPart !== null ? computeLexicalStats(localPart) : null,
    fromDomainLexical: fromDomain !== null ? computeLexicalStats(fromDomain) : null,
    fromDomainParts:
      fromDomain !== null ? computeDomainParts(fromDomain, structuralResolver) : null,
    messageIdDomainParts:
      messageIdDomain !== null ? computeDomainParts(messageIdDomain, structuralResolver) : null,
    messageIdRegistrableDomainMatchesFromDomain,
    fromDomainIsPublicMailboxProvider: publicMailboxProviderId !== null,
    publicMailboxProviderId,
    ...(brandInference !== undefined ? { brandInference } : {}),
    ...(fromRegistrableLabelNaturalness !== undefined ? { fromRegistrableLabelNaturalness } : {}),
  };
}
