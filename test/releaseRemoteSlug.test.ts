import { describe, expect, it } from "vitest";
// release-common.mjs is a plain-JS maintainer script outside the typed `src`
// tree, so it ships no declarations; ignore the missing-types error here.
// @ts-ignore
import { parseRepoSlug } from "../scripts/lib/release-common.mjs";

describe("parseRepoSlug — host validation", () => {
  it("accepts canonical GitHub remote URL forms", () => {
    const expected = "m2dw/mail-auth-signal";
    expect(parseRepoSlug("git@github.com:m2dw/mail-auth-signal.git")).toBe(expected);
    expect(parseRepoSlug("ssh://git@github.com/m2dw/mail-auth-signal.git")).toBe(expected);
    expect(parseRepoSlug("ssh://git@github.com:22/m2dw/mail-auth-signal.git")).toBe(expected);
    expect(parseRepoSlug("https://github.com/m2dw/mail-auth-signal.git")).toBe(expected);
    expect(parseRepoSlug("git://github.com/m2dw/mail-auth-signal")).toBe(expected);
    expect(parseRepoSlug("github.com:m2dw/mail-auth-signal")).toBe(expected);
  });

  it("rejects non-GitHub hosts that merely contain github.com in the path", () => {
    expect(
      parseRepoSlug("ssh://git@example.com/github.com/m2dw/mail-auth-signal.git"),
    ).toBeNull();
    expect(
      parseRepoSlug("https://example.com/github.com/m2dw/mail-auth-signal"),
    ).toBeNull();
    expect(
      parseRepoSlug("git@example.com:github.com/m2dw/mail-auth-signal.git"),
    ).toBeNull();
  });

  it("rejects look-alike hosts", () => {
    expect(parseRepoSlug("https://github.com.evil.com/m2dw/mail-auth-signal")).toBeNull();
    expect(parseRepoSlug("git@notgithub.com:m2dw/mail-auth-signal.git")).toBeNull();
  });

  it("returns null for unparseable or incomplete URLs", () => {
    expect(parseRepoSlug("not a url")).toBeNull();
    expect(parseRepoSlug("https://github.com/onlyowner")).toBeNull();
  });
});
