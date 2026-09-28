import { describe, expect, it } from "vitest";
import {
  analyzeMessage,
  extractDomainFromMailbox,
  extractDomainsFromMailboxList,
  extractEmbeddedDomains,
  parseAuthenticationResults,
  parseFromMailbox,
} from "../src/index.js";

// Issue #99: the bare-mailbox, embedded-address, and Authentication-Results
// property searches used unanchored regexes that restart at every position of a
// long delimiter-free run and rescan it, which is quadratic in caller-supplied
// header text. They were replaced by linear scanners. These tests pin the
// structured results (including a seeded differential check against the former
// regexes) and guard against superlinear growth on adversarial input.

describe("bare mailbox parsing", () => {
  it("parses a bare addr-spec with no display name", () => {
    expect(parseFromMailbox("alice@example.com")).toEqual({
      displayName: null,
      localPart: "alice",
      domain: "example.com",
    });
  });

  it("skips earlier '@'s with an empty local or domain run", () => {
    expect(extractDomainFromMailbox("junk @ bad@@x alice@Example.COM")).toBe("example.com");
  });

  it("does not fabricate a domain from a multi-'@' bare address", () => {
    expect(parseFromMailbox("a@b@example.com")).toEqual({ displayName: null, localPart: null, domain: null });
    expect(extractDomainFromMailbox("a@b@example.com")).toBeNull();
  });

  it("stops the domain at ',' or ';'", () => {
    expect(extractDomainFromMailbox("alice@example.com;bob@evil.test")).toBe("example.com");
  });

  it("treats Unicode whitespace as a local-part delimiter", () => {
    expect(parseFromMailbox("alice bob@example.com").localPart).toBe("bob");
  });

  it("still ignores addresses inside comments", () => {
    expect(extractDomainFromMailbox("(billing@evil.test, Alice) alice@example.com")).toBe("example.com");
  });

  it("still skips angle-addrs inside quoted display names", () => {
    const value = `"a <x@one.test>" "b \\" <y@two.test>" <real@example.com>`;
    expect(parseFromMailbox(value)).toEqual({
      displayName: 'a <x@one.test>" "b " <y@two.test>',
      localPart: "real",
      domain: "example.com",
    });
  });
});

describe("embedded address extraction", () => {
  it("collects distinct domains in encounter order, including Unicode domains", () => {
    expect(extractEmbeddedDomains("service@paypal.com / support@раураl.com, service@paypal.com")).toEqual([
      "paypal.com",
      "раураl.com",
    ]);
  });

  it("resumes after the previous match's domain", () => {
    // The first token consumes `b.com`; the trailing `@c.org` has no local part left.
    expect(extractEmbeddedDomains("a@b.com@c.org")).toEqual(["b.com"]);
    // `_` ends the first domain but is a valid local character for the next token.
    expect(extractEmbeddedDomains("x@first.example_y@second.example")).toEqual([
      "first.example",
      "second.example",
    ]);
  });

  it("requires the local part to touch the '@'", () => {
    expect(extractEmbeddedDomains("'billing'@evil.test")).toEqual([]);
  });

  it("accepts astral characters in the local part", () => {
    expect(extractEmbeddedDomains("\u{1F600}@example.com")).toEqual(["example.com"]);
  });
});

describe("Authentication-Results property parsing", () => {
  it("parses whitespace around '=' and quoted values", () => {
    const parsed = parseAuthenticationResults('mx; dkim=pass Header.D = Example.com header.s="sel 1"');
    expect(parsed.methods[0]?.properties).toEqual({ "header.d": "Example.com", "header.s": "sel 1" });
  });

  it("starts a key at the first letter of a property-name run", () => {
    const parsed = parseAuthenticationResults("mx; spf=pass 1smtp.mailfrom=example.com");
    expect(parsed.methods[0]?.properties).toEqual({ "smtp.mailfrom": "example.com" });
  });

  it("keeps an unclosed quote as an unquoted value", () => {
    const parsed = parseAuthenticationResults('mx; dkim=pass header.b="abc def');
    expect(parsed.methods[0]?.properties).toEqual({ "header.b": '"abc' });
  });

  it("drops a property with an empty value", () => {
    const parsed = parseAuthenticationResults("mx; spf=pass smtp.mailfrom=; dkim=pass header.d=example.com");
    expect(parsed.methods).toEqual([
      { method: "spf", result: "pass", properties: {} },
      { method: "dkim", result: "pass", properties: { "header.d": "example.com" } },
    ]);
  });
});

// Reference implementations: the pre-#99 regex-based parsers, used only as
// oracles on short random inputs where their quadratic cost is irrelevant.
function referenceNormalizeDomain(value: string | null): string | null {
  if (!value) return null;
  const trimmed = value.trim().replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  return !trimmed || !trimmed.includes(".") ? null : trimmed;
}

function referenceInsideQuotes(value: string, index: number): boolean {
  let inQuotes = false;
  for (let i = 0; i < index; i++) {
    const ch = value[i];
    if (inQuotes && ch === "\\") {
      i += 1;
      continue;
    }
    if (ch === '"') inQuotes = !inQuotes;
  }
  return inQuotes;
}

function referenceUnquote(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1).replace(/\\(.)/g, "$1").trim();
  }
  return trimmed;
}

/** Former parseFromMailbox for comment-free input (stripComments is then the identity). */
function referenceParseFromMailbox(value: string): ReturnType<typeof parseFromMailbox> {
  const re = /<([^<>@\s]+)@([^<>@\s]+)>/g;
  let angle: RegExpExecArray | null = null;
  let match: RegExpExecArray | null;
  while ((match = re.exec(value)) !== null) {
    if (!referenceInsideQuotes(value, match.index)) {
      angle = match;
      break;
    }
  }
  let localPartRaw: string | null = null;
  let domainRaw: string | null = null;
  let displayName: string | null = null;
  if (angle) {
    localPartRaw = angle[1] ?? null;
    domainRaw = angle[2] ?? null;
    displayName = angle.index > 0 ? referenceUnquote(value.slice(0, angle.index)) : null;
  } else {
    const bare = /([^<>@\s]+)@([^<>@\s,;]+)/.exec(value);
    localPartRaw = bare?.[1] ?? null;
    domainRaw = bare?.[2] ?? null;
  }
  const domain = referenceNormalizeDomain(domainRaw);
  return {
    displayName: displayName && displayName.length ? displayName : null,
    localPart: domain && localPartRaw ? localPartRaw : null,
    domain,
  };
}

function referenceEmbeddedDomains(text: string): string[] {
  const domains: string[] = [];
  const pattern = /[^\s<>@,;"']+@([\p{L}\p{N}.-]+)/gu;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text)) !== null) {
    const domain = referenceNormalizeDomain(match[1] ?? null);
    if (domain) domains.push(domain);
  }
  return [...new Set(domains)];
}

function referenceProperties(input: string): Record<string, string> {
  const properties: Record<string, string> = {};
  const pattern = /([A-Za-z][A-Za-z0-9_.-]*)\s*=\s*("[^"]*"|[^\s;]+)/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(input)) !== null) {
    const raw = match[2] ?? "";
    properties[(match[1] ?? "").toLowerCase()] =
      raw.startsWith('"') && raw.endsWith('"') ? raw.slice(1, -1) : raw;
  }
  return properties;
}

/** Deterministic PRNG (mulberry32) so a failing case is reproducible. */
function seededRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function randomText(random: () => number, alphabet: readonly string[], maxLength: number): string {
  const length = Math.floor(random() * (maxLength + 1));
  let text = "";
  for (let i = 0; i < length; i++) text += alphabet[Math.floor(random() * alphabet.length)] ?? "";
  return text;
}

describe("seeded differential check against the former regexes", () => {
  // Parentheses are omitted from the mailbox alphabet so comment stripping is the
  // identity and the reference can skip it; ';' and parentheses are omitted from
  // the property alphabet so the input stays inside one method segment.
  const MAILBOX_ALPHABET = [
    "a", "b", "x", "1", "_", "-", ".", ".", "@", "@", "<", ">", '"', "'", "\\",
    " ", "\t", " ", ",", ";", "é", "р", "\u{1F600}",
  ];
  const PROPERTY_ALPHABET = [
    "a", "B", "z", "1", "_", ".", "-", "=", "=", '"', " ", "\t", " ", "\\", "é", ",", "@",
  ];

  it("parseFromMailbox and extractDomainFromMailbox", () => {
    const random = seededRandom(99);
    for (let i = 0; i < 3000; i++) {
      const value = randomText(random, MAILBOX_ALPHABET, 32);
      if (!value) continue;
      const expected = referenceParseFromMailbox(value);
      expect(parseFromMailbox(value), JSON.stringify(value)).toEqual(expected);
      expect(extractDomainFromMailbox(value), JSON.stringify(value)).toBe(expected.domain);
    }
  });

  it("extractEmbeddedDomains", () => {
    const random = seededRandom(9901);
    for (let i = 0; i < 3000; i++) {
      const text = randomText(random, MAILBOX_ALPHABET, 32);
      expect(extractEmbeddedDomains(text), JSON.stringify(text)).toEqual(referenceEmbeddedDomains(text));
    }
  });

  it("Authentication-Results properties", () => {
    const random = seededRandom(9902);
    for (let i = 0; i < 3000; i++) {
      const segment = ` ${randomText(random, PROPERTY_ALPHABET, 32)}`;
      const parsed = parseAuthenticationResults(`mx; spf=pass${segment}`);
      expect(parsed.methods[0]?.properties, JSON.stringify(segment)).toEqual(referenceProperties(segment));
    }
  });
});

/**
 * Growth-oriented performance guard (not a millisecond budget). Each input is
 * timed at SMALL and at 8x SMALL characters, keeping the best of a few runs.
 * Linear work grows ~8x and the former quadratic searches ~64x (≈5 s per call at
 * LARGE on V8), so requiring less than 24x growth separates the two with wide
 * margin; the absolute floor absorbs timer noise when both runs are tiny.
 *
 * Repeatable benchmark: raise SMALL (e.g. to 100_000) and log `small`/`large`
 * from expectLinearGrowth to see the ratio stay near 8.
 */
const SMALL = 10_000;
const LARGE = SMALL * 8;
const NOISE_FLOOR_MS = 100;

function bestDurationMs(run: () => void): number {
  let best = Number.POSITIVE_INFINITY;
  for (let i = 0; i < 3; i++) {
    const start = performance.now();
    run();
    best = Math.min(best, performance.now() - start);
  }
  return best;
}

function expectLinearGrowth(build: (size: number) => () => void): void {
  const small = bestDurationMs(build(SMALL));
  const large = bestDurationMs(build(LARGE));
  expect(large).toBeLessThan(Math.max(small * 24, NOISE_FLOOR_MS));
}

describe("adversarial delimiter-free header text", () => {
  const TIMEOUT_MS = 30_000;

  it("mailbox helpers on local-part-like text without '@'", () => {
    expectLinearGrowth((size) => {
      const value = "a".repeat(size);
      return () => {
        expect(extractDomainFromMailbox(value)).toBeNull();
        expect(parseFromMailbox(value)).toEqual({ displayName: null, localPart: null, domain: null });
        expect(extractDomainsFromMailboxList(value)).toEqual([]);
      };
    });
  }, TIMEOUT_MS);

  it("embedded extraction on local-part-like text without '@'", () => {
    expectLinearGrowth((size) => {
      const value = "a".repeat(size);
      return () => expect(extractEmbeddedDomains(value)).toEqual([]);
    });
  }, TIMEOUT_MS);

  it("angle-addr search past many quoted address-shaped fragments", () => {
    expectLinearGrowth((size) => {
      const value = `"${"<a@b.c>".repeat(size / 7)}" <real@example.com>`;
      return () => expect(extractDomainFromMailbox(value)).toBe("example.com");
    });
  }, TIMEOUT_MS);

  it("Authentication-Results properties on property-like text without '='", () => {
    expectLinearGrowth((size) => {
      const header = `mx; spf=pass ${"a.".repeat(size / 2)}`;
      return () => expect(parseAuthenticationResults(header).methods[0]?.properties).toEqual({});
    });
  }, TIMEOUT_MS);

  it("analyzeMessage on long From, Reply-To, and Authentication-Results values", () => {
    expectLinearGrowth((size) => {
      const localLike = "a".repeat(size);
      // Digits keep the long display name out of brand matching so the check
      // stays focused on the address scanners.
      const displayName = "0".repeat(size);
      const headers = {
        from: `"${displayName}" <alice@example.com>`,
        "reply-to": localLike,
        "return-path": localLike,
        "authentication-results": [`mx.example.net; spf=pass ${"a.".repeat(size / 2)}`],
      };
      return () => {
        const result = analyzeMessage({ headers, options: { trustedAuthservIds: ["mx.example.net"] } });
        expect(result.metrics.fromDomain).toBe("example.com");
      };
    });
    expect(analyzeMessage({ headers: { from: "a".repeat(SMALL) } }).metrics.fromDomain).toBeNull();
  }, TIMEOUT_MS);
});
