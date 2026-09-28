import type { AuthenticationMethodResult, AuthenticationResultsHeader } from "./types.js";

// Every match starts at the header start or a ';' and ends at the next ';', and
// no quantifier crosses a ';', so the scan is linear in the header length.
const METHOD_PATTERN = /(?:^|;)\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*([A-Za-z][A-Za-z0-9_.-]*)\b([^;]*)/g;

export function parseAuthenticationResults(raw: string, trustedAuthservIds: readonly string[] = []): AuthenticationResultsHeader {
  // Strip RFC 5322 comments before parsing so a crafted comment cannot inject a
  // property-shaped token (e.g. `header.d=...`) that overwrites the real value.
  const decommented = stripComments(raw);
  const authservId = decommented.split(";", 1)[0]?.trim().toLowerCase() ?? "";
  const methods: AuthenticationMethodResult[] = [];
  let match: RegExpExecArray | null;

  METHOD_PATTERN.lastIndex = 0;
  while ((match = METHOD_PATTERN.exec(decommented)) !== null) {
    const method = match[1]?.toLowerCase() ?? "";
    const result = match[2]?.toLowerCase() ?? "";
    const properties = parseProperties(match[3] ?? "");
    if (method && result) {
      methods.push({ method, result, properties });
    }
  }

  return {
    raw,
    authservId,
    trusted: isTrustedAuthservId(authservId, trustedAuthservIds),
    methods,
  };
}

export function isTrustedAuthservId(authservId: string, trustedAuthservIds: readonly string[]): boolean {
  const normalized = authservId.toLowerCase();
  return trustedAuthservIds.some((trusted) => normalized === trusted.trim().toLowerCase());
}

/**
 * Extract `key=value` properties from one method's result segment.
 *
 * This is the linear-time equivalent of the former unanchored search
 * `/([A-Za-z][A-Za-z0-9_.-]*)\s*=\s*("[^"]*"|[^\s;]+)/g`. That regex restarted
 * at every letter of a long property-like run with no '=' (e.g. `aaaa…`) and
 * rescanned the run to its end each time, which is quadratic in
 * attacker-controlled header text. Here each maximal run of name characters is
 * scanned once; the key is that run from its first ASCII letter, exactly the
 * regex's leftmost start. The run is kept only when optional whitespace, '=',
 * optional whitespace, and a non-empty value follow — the same success
 * conditions as the regex, whose name and whitespace quantifiers never have a
 * shorter alternative that could succeed. A value is a closed quoted string
 * when one is present, otherwise a run of non-whitespace, non-';' characters.
 */
function parseProperties(input: string): Record<string, string> {
  const properties: Record<string, string> = {};
  let i = 0;

  while (i < input.length) {
    if (!PROPERTY_NAME_CHAR.test(input[i] as string)) {
      i++;
      continue;
    }

    const runStart = i;
    while (i < input.length && PROPERTY_NAME_CHAR.test(input[i] as string)) i++;
    let keyStart = runStart;
    while (keyStart < i && !ASCII_LETTER.test(input[keyStart] as string)) keyStart++;
    if (keyStart === i) continue;

    let cursor = skipWhitespace(input, i);
    if (input[cursor] !== "=") continue;
    cursor = skipWhitespace(input, cursor + 1);
    const rawValue = readPropertyValue(input, cursor);
    if (rawValue === null) continue;

    properties[input.slice(keyStart, i).toLowerCase()] = stripQuotes(rawValue);
    i = cursor + rawValue.length;
  }

  return properties;
}

const PROPERTY_NAME_CHAR = /[A-Za-z0-9_.-]/;
const ASCII_LETTER = /[A-Za-z]/;
// Sticky single-class runs match maximally on the first try and never backtrack.
const WHITESPACE_RUN = /\s*/y;
const UNQUOTED_VALUE_RUN = /[^\s;]+/y;

function skipWhitespace(input: string, index: number): number {
  WHITESPACE_RUN.lastIndex = index;
  WHITESPACE_RUN.exec(input);
  return WHITESPACE_RUN.lastIndex;
}

function readPropertyValue(input: string, index: number): string | null {
  if (input[index] === '"') {
    const close = input.indexOf('"', index + 1);
    if (close !== -1) return input.slice(index, close + 1);
  }
  UNQUOTED_VALUE_RUN.lastIndex = index;
  return UNQUOTED_VALUE_RUN.exec(input)?.[0] ?? null;
}

function stripQuotes(value: string): string {
  return value.startsWith('"') && value.endsWith('"') ? value.slice(1, -1) : value;
}

/**
 * Remove RFC 5322 comments (parenthesized CFWS) from an Authentication-Results
 * header. Comments are free text that may themselves contain `key=value`-shaped
 * tokens; left in place, a crafted comment such as `(header.d=example.com )`
 * after a real `header.d=evil.test` lets the property parser overwrite the
 * genuine signing domain and mask a mismatch. Quoted strings are preserved
 * verbatim (parentheses inside them are literal data), comments may nest, and
 * each comment collapses to a single space so it still separates the tokens
 * that surround it.
 */
function stripComments(input: string): string {
  let output = "";
  let depth = 0;
  let inQuote = false;

  for (let i = 0; i < input.length; i++) {
    const char = input[i];

    // A quoted-pair escapes the next character; keep it only outside comments.
    if (char === "\\" && i + 1 < input.length) {
      if (depth === 0) output += char + input[i + 1];
      i++;
      continue;
    }

    if (inQuote) {
      output += char;
      if (char === '"') inQuote = false;
      continue;
    }

    if (char === '"' && depth === 0) {
      inQuote = true;
      output += char;
      continue;
    }

    if (char === "(") {
      if (depth === 0) output += " ";
      depth++;
      continue;
    }

    if (char === ")" && depth > 0) {
      depth--;
      continue;
    }

    if (depth === 0) output += char;
  }

  return output;
}

