# Changelog

## Unreleased

- Added a versioned release and npm publishing process (issue #26):
  - Documented the full release flow in `RELEASING.md`: SemVer policy, changelog
    update, version bump, `npm test`, `npm run build`, `npm pack --dry-run`
    inspection, git tagging (`vX.Y.Z`), publishing, and first-release/trusted-
    publishing bootstrap steps.
  - Added the `.github/workflows/release.yml` GitHub Actions workflow. It runs
    only on maintainer-pushed `v*.*.*` tags, gates publishing behind the
    `release` environment, verifies the tag matches `package.json` `version`,
    re-runs tests/build/`npm pack --dry-run`, and publishes with provenance via
    npm trusted publishing (OIDC) or a maintainer-controlled `NPM_TOKEN`
    fallback. It does not publish on branch pushes or pull requests.
  - Added `release:check`, `prepack` (builds `dist/` before packing/publishing),
    and `prepublishOnly` (typecheck + tests) npm scripts.
  - Documented the published package contents (`dist`, `README.md`, `LICENSE`,
    `NOTICE`, `package.json`) and the post-publish `npm install mail-auth-signal`
    flow in the README. No release is published by this change.

- Prepared package for add-on consumption (issue #24):
  - Fixed `package.json` `main`, `module`, `types`, and `exports` fields to match
    the actual flat `dist/` output produced by tsup (`dist/index.js`,
    `dist/index.cjs`, `dist/index.d.ts`). The prior paths referenced non-existent
    subdirectories (`dist/esm/`, `dist/cjs/`, `dist/types/`).
  - Verified that all README import examples (`analyzeMessage`, `extractMetrics`,
    `runRules`, `defaultRules`, `Rule`) are present in the public `src/index.ts`
    export surface.
  - Confirmed `files` in `package.json` includes only `dist`, `README.md`,
    `LICENSE`, and `NOTICE`; `.n8n-artifacts/` and other local automation state
    are excluded by `.gitignore` and are not listed in `files`.
  - Confirmed no runtime network access, Thunderbird/WebExtension APIs, mailbox
    operations, storage, notifications, DNS, or n8n dependencies exist in
    `src/`.
  - All 258 tests pass; build output is current.

- Initial TypeScript library scaffold.
- Added basic header normalization, `Authentication-Results` parsing, sender domain extraction, and signal output.
- Established the public analysis API boundary for incremental rule migration:
  - Separated the pipeline into `extractMetrics` (parsing/facts) and rule evaluation.
  - Added the stable `Rule` and `RuleContext` types, exported `defaultRules`, the
    `runRules` helper, and individual rule modules.
  - `analyzeMessage` now accepts an optional rule set as its second argument so
    callers can target a narrowed or extended set of rules.
  - Added a JSON fixture (`test/fixtures/dmarc-fail.json`) pinning the serializable
    `AnalyzeResult` shape, plus tests covering the new API surface.
- Migrated the Authentication-Results failure-signal family from the Thunderbird
  add-on (issue #5):
  - `authMethodFailureRule` is now trust-aware: failures stamped by an untrusted
    authserv-id are non-authoritative (could be forged) and capped at low, while
    trusted DMARC `fail` (unaligned with the From domain) is reported high, other
    trusted hard `fail`s medium, and softfail/temperror/permerror low. Each
    failure signal now carries a `trusted` flag in its `data`.
  - Added `resolveHeaderTrust`, a shared helper so every Authentication-Results
    rule resolves trust identically (honoring `runRules` option overrides), and
    refactored `untrustedAuthservIdRule` to use it.
  - Added fixtures `dmarc-fail-trusted.json`, `spf-softfail.json`, and
    `dkim-fail.json`, updated `dmarc-fail.json` for the trust-aware severity, and
    added `test/authMethodFailure.test.ts` covering the SPF/DKIM/DMARC
    fail/softfail/temperror/permerror matrix across trusted and untrusted sources.
- Migrated DMARC `header.from` consistency from the Thunderbird add-on (issue #16):
  - Added `extractDmarcHeaderFromDomain` (factored a shared bare-domain extractor
    with `extractDkimSigningDomain`), the `dmarcHeaderFromDomains` and
    `dmarcHeaderFromMatchesFromDomain` metrics, and `dmarcHeaderFromMismatchRule`,
    which emits a low-severity `dmarc.headerFromMismatch` when the DMARC-evaluated
    `header.from` differs from the visible `From` domain.
  - The metric is gated on both `pass` and trusted authserv-id, so a failed,
    missing, malformed, or untrusted DMARC context never produces a signal —
    `header.from` is not cryptographic, so an untrusted header's value is just an
    attacker assertion and a non-`pass` result vouches for nothing.
  - Added fixtures `dmarc-headerfrom-match.json`, `dmarc-headerfrom-mismatch.json`,
    and `dmarc-headerfrom-untrusted.json`, added
    `test/dmarcHeaderFromMismatch.test.ts`, and extended every existing
    full-metrics fixture with the two new metric fields.

