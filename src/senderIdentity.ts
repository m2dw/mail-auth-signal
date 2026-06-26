import { computeDisplayNameBrandInference } from "./brandInference.js";
import {
  allDomainsMatch,
  extractEmbeddedDomains,
  parseFromMailbox,
  registrableDomainsMatch,
} from "./domains.js";
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
 * words) still read false: those have a short-to-moderate consonant run, a vowel
 * ratio above the floor, no digits, no hex run, and no letter/digit alternation,
 * so none of the structural branches fire.
 */
const RANDOM_LOOKING_MIN_LENGTH = 6;
const RANDOM_LOOKING_MIN_DIGIT_RATIO = 0.4;
const RANDOM_LOOKING_MIN_LETTER_DIGIT_TRANSITIONS = 4;
const RANDOM_LOOKING_MIN_HEX_RUN = 8;
const RANDOM_LOOKING_MAX_VOWEL_RATIO = 0.2;
const RANDOM_LOOKING_MIN_CONSONANT_RUN = 5;

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
 *   - a low vowel ratio paired with a long consonant run (an unpronounceable
 *     consonant cluster, e.g. `mpqxyt`), or
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
  if (
    h.digitRatio >= RANDOM_LOOKING_MIN_DIGIT_RATIO ||
    h.letterDigitTransitionCount >= RANDOM_LOOKING_MIN_LETTER_DIGIT_TRANSITIONS ||
    h.maxHexRun >= RANDOM_LOOKING_MIN_HEX_RUN ||
    (h.vowelRatio <= RANDOM_LOOKING_MAX_VOWEL_RATIO &&
      h.maxConsonantRun >= RANDOM_LOOKING_MIN_CONSONANT_RUN) ||
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
  };
}
