/**
 * Round a floating-point similarity value to 4 decimal places for stable,
 * cross-language-comparable fixture values (same convention as LexicalHeuristics).
 */
function round4(value: number): number {
  return Math.round(value * 1e4) / 1e4;
}

/**
 * Compute the raw (unrounded) Jaro similarity over pre-split codepoint arrays.
 * Callers that need the unrounded value for further arithmetic (e.g.
 * computeJaroWinkler) call this directly to avoid double-rounding.
 */
function jaroScore(aChars: string[], bChars: string[]): number {
  const aLen = aChars.length;
  const bLen = bChars.length;
  if (aLen === 0 || bLen === 0) return 0;

  const matchWindow = Math.max(Math.floor(Math.max(aLen, bLen) / 2) - 1, 0);
  const aMatched = new Array<boolean>(aLen).fill(false);
  const bMatched = new Array<boolean>(bLen).fill(false);
  let matches = 0;

  for (let i = 0; i < aLen; i++) {
    const start = Math.max(0, i - matchWindow);
    const end = Math.min(bLen - 1, i + matchWindow);
    const ac = aChars[i] as string;
    for (let j = start; j <= end; j++) {
      if ((bMatched[j] as boolean) || ac !== (bChars[j] as string)) continue;
      aMatched[i] = true;
      bMatched[j] = true;
      matches++;
      break;
    }
  }

  if (matches === 0) return 0;

  // Count transpositions: walk the matched characters in their original order in
  // each string and compare pairwise. A pair that differs counts as one
  // half-transposition; dividing by 2 gives the transposition count t.
  let transpositions = 0;
  let k = 0;
  for (let i = 0; i < aLen; i++) {
    if (!(aMatched[i] as boolean)) continue;
    while (k < bLen && !(bMatched[k] as boolean)) k++;
    if (k < bLen && (aChars[i] as string) !== (bChars[k] as string)) transpositions++;
    k++;
  }

  return (matches / aLen + matches / bLen + (matches - transpositions / 2) / matches) / 3;
}

/**
 * Compute Jaro similarity between two strings. Returns a value in [0, 1]:
 * 1 for identical strings (including two empty strings), 0 when no characters
 * match. The result is rounded to 4 decimal places for stable fixture comparison.
 *
 * Matching is codepoint-based so a multi-byte Unicode character is measured as
 * one unit, not split across code units. "Matching" means the same codepoint
 * appears within a window of floor(max(|a|, |b|) / 2) − 1 positions on either
 * side (clamped to 0), and each codepoint is matched at most once.
 *
 * This is a policy-neutral primitive. Callers decide which strings to compare
 * and what the similarity value means in their context — the core forms no opinion
 * on what constitutes a "suspicious" similarity threshold.
 */
export function computeJaro(a: string, b: string): number {
  if (a === b) return 1;
  return round4(jaroScore([...a], [...b]));
}

/**
 * Compute Jaro-Winkler similarity between two strings. Extends computeJaro with
 * a prefix bonus: up to 4 leading codepoints that both strings share increase
 * the score by prefixScalingFactor × prefixLength × (1 − jaro). Returns a value
 * in [0, 1], rounded to 4 decimal places.
 *
 * The conventional Winkler scaling factor is 0.1 (the default). Values above 0.25
 * can push the result above 1; callers should keep prefixScalingFactor in [0, 0.25]
 * or clamp the result themselves.
 *
 * Like computeJaro, this is a policy-neutral primitive: callers decide which
 * strings to compare and what the returned similarity means in their context.
 */
export function computeJaroWinkler(a: string, b: string, prefixScalingFactor = 0.1): number {
  if (a === b) return 1;
  const aChars = [...a];
  const bChars = [...b];
  const jaro = jaroScore(aChars, bChars);
  const maxPrefix = Math.min(4, aChars.length, bChars.length);
  let prefixLen = 0;
  for (let i = 0; i < maxPrefix; i++) {
    if ((aChars[i] as string) !== (bChars[i] as string)) break;
    prefixLen++;
  }
  return round4(jaro + prefixLen * prefixScalingFactor * (1 - jaro));
}
