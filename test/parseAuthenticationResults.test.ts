import { describe, expect, it } from "vitest";
import { parseAuthenticationResults } from "../src/index.js";

/** Find the first method of the given name in a parsed header. */
function method(raw: string, name: string) {
  return parseAuthenticationResults(raw).methods.find((m) => m.method === name);
}

describe("parseAuthenticationResults — RFC 5322 comment stripping", () => {
  it("ignores a property-shaped token inside a comment after the real property", () => {
    // The comment carries its own `header.d=`; the genuine signer must win.
    const dkim = method("mx.test; dkim=pass header.d=evil.test (header.d=example.com )", "dkim");
    expect(dkim?.properties["header.d"]).toBe("evil.test");
  });

  it("ignores a property-shaped token inside a comment before the real property", () => {
    const dkim = method("mx.test; dkim=pass (header.d=evil.test) header.d=example.com", "dkim");
    expect(dkim?.properties["header.d"]).toBe("example.com");
  });

  it("strips comments from the smtp.mailfrom property too", () => {
    const spf = method("mx.test; spf=pass smtp.mailfrom=example.com (helo=evil.test)", "spf");
    expect(spf?.properties["smtp.mailfrom"]).toBe("example.com");
  });

  it("keeps parentheses that live inside a quoted string", () => {
    const dkim = method('mx.test; dkim=pass header.i="@a(b)c.example"', "dkim");
    expect(dkim?.properties["header.i"]).toBe("@a(b)c.example");
  });

  it("handles nested comments", () => {
    const dkim = method("mx.test; dkim=pass header.d=example.com (a (b header.d=evil.test) c)", "dkim");
    expect(dkim?.properties["header.d"]).toBe("example.com");
  });

  it("does not let a comment in the authserv-id position leak into it", () => {
    const header = parseAuthenticationResults("mx.test (primary); dkim=pass header.d=example.com");
    expect(header.authservId).toBe("mx.test");
  });
});
