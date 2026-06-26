/**
 * Round a floating-point similarity value to 4 decimal places for stable,
 * cross-language-comparable fixture values (same convention as computeJaro /
 * LexicalHeuristics).
 */
function round4(value: number): number {
  return Math.round(value * 1e4) / 1e4;
}

/**
 * Decompose a string into the set of its adjacent codepoint bigrams. A token of
 * one codepoint has no adjacent pair, so it contributes that single codepoint as
 * its only feature (otherwise two distinct single characters would score 0 even
 * when a caller considers them comparable). Bigrams are codepoint-based so a
 * multi-byte Unicode character is one unit, matching computeJaro / computeJaccard.
 */
function bigramSet(value: string): Set<string> {
  const chars = [...value];
  if (chars.length === 0) return new Set();
  if (chars.length === 1) return new Set(chars);
  const set = new Set<string>();
  for (let i = 0; i < chars.length - 1; i++) {
    set.add((chars[i] as string) + (chars[i + 1] as string));
  }
  return set;
}

/**
 * Compute the Jaccard similarity of two strings over their adjacent-codepoint
 * bigram sets: |A ∩ B| / |A ∪ B|. Returns a value in [0, 1] — 1 for identical
 * strings (including two empty strings), 0 when the bigram sets are disjoint or
 * either string is empty. The result is rounded to 4 decimal places for stable
 * fixture comparison.
 *
 * Bigrams (rather than single characters) capture local letter order, so
 * "abc" and "cba" — identical as character sets — score below 1, which is the
 * property brand-token matching wants. Like computeJaro / computeJaroWinkler this
 * is a policy-neutral primitive: callers decide which strings to compare and what
 * the returned similarity means in their context. It complements Jaro-Winkler —
 * Jaccard rewards shared substrings irrespective of position while Jaro-Winkler
 * rewards a shared prefix — so a caller can corroborate one with the other.
 */
export function computeJaccard(a: string, b: string): number {
  if (a === b) return 1;
  const setA = bigramSet(a);
  const setB = bigramSet(b);
  if (setA.size === 0 || setB.size === 0) return 0;
  let intersection = 0;
  for (const gram of setA) {
    if (setB.has(gram)) intersection++;
  }
  const union = setA.size + setB.size - intersection;
  return union === 0 ? 0 : round4(intersection / union);
}
