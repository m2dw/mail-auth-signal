export function extractDomainFromMailbox(value: string | null): string | null {
  if (!value) return null;

  // The captured domain excludes '@' so a malformed multi-'@' address does not
  // yield a bogus domain that could trigger a spurious consistency signal.
  const angleMatch = /<[^<>@\s]+@([^<>@\s]+)>/.exec(value);
  const domain = angleMatch?.[1] ?? /[^<>@\s]+@([^<>@\s,;]+)/.exec(value)?.[1];
  return normalizeDomain(domain ?? null);
}

export function extractDomainFromMessageId(value: string | null): string | null {
  if (!value) return null;

  // Anchor on the final '@' and exclude '@' from the domain so a malformed
  // multi-'@' Message-ID resolves to its real trailing domain rather than a
  // bogus value spanning the extra '@'.
  const domain = /@([^>@\s]+)>?\s*$/.exec(value.trim())?.[1];
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

