import type { HeaderInput, HeaderLine } from "./types.js";

export function normalizeHeaders(headers: HeaderInput): Map<string, string[]> {
  const normalized = new Map<string, string[]>();

  const add = (name: string, value: string): void => {
    const key = name.trim().toLowerCase();
    if (!key) return;
    const values = normalized.get(key) ?? [];
    values.push(unfoldHeaderValue(value));
    normalized.set(key, values);
  };

  if (Array.isArray(headers)) {
    for (const header of headers) {
      add(header.name, header.value);
    }
    return normalized;
  }

  for (const [name, value] of Object.entries(headers)) {
    if (typeof value === "string") {
      add(name, value);
    } else if (Array.isArray(value)) {
      for (const item of value) add(name, item);
    }
  }

  return normalized;
}

function unfoldHeaderValue(value: string): string {
  return value.replace(/\r?\n[\t ]+/g, " ").trim();
}

export function getHeaderValues(headers: Map<string, string[]>, name: string): string[] {
  return headers.get(name.toLowerCase()) ?? [];
}

export function getFirstHeaderValue(headers: Map<string, string[]>, name: string): string | null {
  return getHeaderValues(headers, name)[0] ?? null;
}

