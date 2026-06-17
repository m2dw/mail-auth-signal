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

