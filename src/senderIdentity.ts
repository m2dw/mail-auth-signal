import { allDomainsMatch, extractEmbeddedDomains, parseFromMailbox } from "./domains.js";
import type {
  DisplayNameMetrics,
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
      maxConsonantRun: 0,
      maxRepeatedCharRun: 0,
      uniqueCharRatio: 0,
      letterDigitTransitions: 0,
    };
  }

  const frequencies = new Map<string, number>();
  let letterCount = 0;
  let vowelCount = 0;
  let consonantRun = 0;
  let maxConsonantRun = 0;
  let repeatedRun = 1;
  let maxRepeatedCharRun = 1;
  let letterDigitTransitions = 0;

  for (let index = 0; index < length; index++) {
    const char = chars[index] as string;
    frequencies.set(char, (frequencies.get(char) ?? 0) + 1);

    const letter = isAsciiLetter(char);
    const digit = char >= "0" && char <= "9";
    if (letter) {
      letterCount++;
      if (ASCII_VOWELS.has(char.toLowerCase())) {
        vowelCount++;
        consonantRun = 0;
      } else {
        consonantRun++;
        if (consonantRun > maxConsonantRun) maxConsonantRun = consonantRun;
      }
    } else {
      consonantRun = 0;
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
    maxConsonantRun,
    maxRepeatedCharRun,
    uniqueCharRatio: round4(frequencies.size / length),
    letterDigitTransitions,
  };
}

/**
 * Decompose a normalized domain into its dot-separated labels (see DomainParts).
 * The label fields need no external data; the registrable-domain fields are
 * populated only when a resolver is supplied (the core bundles no PSL data).
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
  return {
    domain,
    labels,
    labelCount: labels.length,
    topLabel: labels[labels.length - 1] ?? domain,
    registrableDomain,
    subdomainDepth,
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
  const parsed = parseFromMailbox(fromValue);

  const displayText = parsed.displayName;
  const embeddedDomains = extractEmbeddedDomains(displayText);
  const displayName: DisplayNameMetrics = {
    present: displayText !== null,
    text: displayText,
    length: displayText ? [...displayText].length : 0,
    hasNonAscii: displayText ? computeLexicalStats(displayText).hasNonAscii : false,
    containsEmail: embeddedDomains.length > 0,
    embeddedDomains,
    embeddedDomainMatchesFromDomain: allDomainsMatch(fromDomain, embeddedDomains),
  };

  // Pair the local part with the canonical From domain. parseFromMailbox mirrors
  // the fromDomain extractor, so when a From domain is present its local part
  // belongs to the same address; when From has no parseable domain there is no
  // address to read a local part from.
  const localPart = fromDomain !== null ? parsed.localPart : null;

  const messageIdRegistrableDomainMatchesFromDomain = ((): boolean | null => {
    if (!getRegistrableDomain || fromDomain === null || messageIdDomain === null) return null;
    const fromRegistrable = getRegistrableDomain(fromDomain);
    const messageIdRegistrable = getRegistrableDomain(messageIdDomain);
    if (!fromRegistrable || !messageIdRegistrable) return null;
    return fromRegistrable === messageIdRegistrable;
  })();

  return {
    displayName,
    localPart,
    localPartLexical: localPart !== null ? computeLexicalStats(localPart) : null,
    fromDomainLexical: fromDomain !== null ? computeLexicalStats(fromDomain) : null,
    fromDomainParts:
      fromDomain !== null ? computeDomainParts(fromDomain, getRegistrableDomain) : null,
    messageIdDomainParts:
      messageIdDomain !== null ? computeDomainParts(messageIdDomain, getRegistrableDomain) : null,
    messageIdRegistrableDomainMatchesFromDomain,
  };
}
