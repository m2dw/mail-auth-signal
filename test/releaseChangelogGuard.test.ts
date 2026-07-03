import { describe, expect, it } from "vitest";
// @ts-ignore — plain-JS maintainer script, no declarations
import { checkChangelogBody } from "../scripts/lib/release-common.mjs";

const VERSION = "1.2.3";

const CLEAN = `# Changelog

## Unreleased

## v1.2.3 — 2026-06-27

- released item
`;

const COMMENT_ONLY_UNRELEASED = `# Changelog

## Unreleased

<!-- placeholder -->

## v1.2.3 — 2026-06-27

- released item
`;

const POPULATED_UNRELEASED = `# Changelog

## Unreleased

- a new feature not yet moved to the version section

## v1.2.3 — 2026-06-27

- released item
`;

const MISSING_VERSION_HEADING = `# Changelog

## Unreleased

## v1.0.0 — 2026-01-01

- old item
`;

// Has a pre-release heading for the same base version but not the exact target.
const PRERELEASE_HEADING_ONLY = `# Changelog

## Unreleased

## v1.2.3-alpha.1 — 2026-06-01

- alpha item
`;

// Has a heading that extends the target version with an extra segment.
const EXTENDED_VERSION_HEADING = `# Changelog

## Unreleased

## v1.2.3.4 — 2026-06-01

- patch item
`;

const NO_UNRELEASED_SECTION = `# Changelog

## v1.2.3 — 2026-06-27

- released item
`;

const UNRELEASED_AFTER_VERSION = `# Changelog

## v1.2.3 — 2026-06-27

- released item

## Unreleased

`;

describe("checkChangelogBody", () => {
  it("passes for a clean empty Unreleased section with version heading", () => {
    expect(() => checkChangelogBody(CLEAN, VERSION)).not.toThrow();
  });

  it("passes when Unreleased contains only HTML comments", () => {
    expect(() => checkChangelogBody(COMMENT_ONLY_UNRELEASED, VERSION)).not.toThrow();
  });

  it("fails when Unreleased has real bullet content", () => {
    expect(() => checkChangelogBody(POPULATED_UNRELEASED, VERSION)).toThrowError(
      /Unreleased.*section still has content/i,
    );
  });

  it("failure message for populated Unreleased names the target version", () => {
    expect(() => checkChangelogBody(POPULATED_UNRELEASED, VERSION)).toThrowError(/v1\.2\.3/);
  });

  it("fails when the target version heading is missing", () => {
    expect(() => checkChangelogBody(MISSING_VERSION_HEADING, VERSION)).toThrowError(
      /missing a heading for v1\.2\.3/i,
    );
  });

  it("fails when there is no Unreleased section", () => {
    expect(() => checkChangelogBody(NO_UNRELEASED_SECTION, VERSION)).toThrowError(
      /missing an.*Unreleased.*section/i,
    );
  });

  it("fails when Unreleased section appears after the version heading", () => {
    expect(() => checkChangelogBody(UNRELEASED_AFTER_VERSION, VERSION)).toThrowError(
      /Unreleased.*must appear before.*v1\.2\.3/i,
    );
  });

  it("fails when only a pre-release heading exists for the target version", () => {
    expect(() => checkChangelogBody(PRERELEASE_HEADING_ONLY, VERSION)).toThrowError(
      /missing a heading for v1\.2\.3/i,
    );
  });

  it("fails when only an extended-version heading exists for the target version", () => {
    expect(() => checkChangelogBody(EXTENDED_VERSION_HEADING, VERSION)).toThrowError(
      /missing a heading for v1\.2\.3/i,
    );
  });
});
