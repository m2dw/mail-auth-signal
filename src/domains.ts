export function extractDomainFromMailbox(value: string | null): string | null {
  if (!value) return null;

  const angleMatch = /<[^<>@\s]+@([^<>\s]+)>/.exec(value);
  const domain = angleMatch?.[1] ?? /[^<>@\s]+@([^<>\s,;]+)/.exec(value)?.[1];
  return normalizeDomain(domain ?? null);
}

export function extractDomainFromMessageId(value: string | null): string | null {
  if (!value) return null;

  const domain = /@([^>\s]+)>?\s*$/.exec(value.trim())?.[1];
  return normalizeDomain(domain ?? null);
}

export function domainsExactlyMatch(left: string | null, right: string | null): boolean | null {
  if (!left || !right) return null;
  return left === right;
}

function normalizeDomain(value: string | null): string | null {
  if (!value) return null;
  const trimmed = value.trim().replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  if (!trimmed || !trimmed.includes(".")) return null;
  return trimmed;
}

