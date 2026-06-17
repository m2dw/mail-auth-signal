# Changelog

## Unreleased

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

