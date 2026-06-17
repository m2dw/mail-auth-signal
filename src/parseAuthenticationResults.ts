import type { AuthenticationMethodResult, AuthenticationResultsHeader } from "./types.js";

const METHOD_PATTERN = /(?:^|;)\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*([A-Za-z][A-Za-z0-9_.-]*)\b([^;]*)/g;
const PROPERTY_PATTERN = /([A-Za-z][A-Za-z0-9_.-]*)\s*=\s*("[^"]*"|[^\s;]+)/g;

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

function parseProperties(input: string): Record<string, string> {
  const properties: Record<string, string> = {};
  let match: RegExpExecArray | null;

  PROPERTY_PATTERN.lastIndex = 0;
  while ((match = PROPERTY_PATTERN.exec(input)) !== null) {
    const key = match[1]?.toLowerCase();
    const value = stripQuotes(match[2] ?? "");
    if (key) properties[key] = value;
  }

  return properties;
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

