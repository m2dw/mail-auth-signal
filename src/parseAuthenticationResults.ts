import type { AuthenticationMethodResult, AuthenticationResultsHeader } from "./types.js";

const METHOD_PATTERN = /(?:^|;)\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*([A-Za-z][A-Za-z0-9_.-]*)\b([^;]*)/g;
const PROPERTY_PATTERN = /([A-Za-z][A-Za-z0-9_.-]*)\s*=\s*("[^"]*"|[^\s;]+)/g;

export function parseAuthenticationResults(raw: string, trustedAuthservIds: readonly string[] = []): AuthenticationResultsHeader {
  const authservId = raw.split(";", 1)[0]?.trim().toLowerCase() ?? "";
  const methods: AuthenticationMethodResult[] = [];
  let match: RegExpExecArray | null;

  METHOD_PATTERN.lastIndex = 0;
  while ((match = METHOD_PATTERN.exec(raw)) !== null) {
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

