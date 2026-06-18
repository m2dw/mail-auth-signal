# Changelog

## Unreleased

- Added a public mailbox provider catalog and a spoofing candidate signal (issue #47):
  - Bundled a small, explicit, hand-authored catalog of high-confidence public
    mailbox provider registrable domains (`gmail.com`/`googlemail.com`,
    `outlook.com`/`hotmail.com`/`live.com`/`msn.com`,
    `icloud.com`/`me.com`/`mac.com`, `yahoo.com`/`yahoo.co.jp`, `aol.com`),
    exported as `defaultPublicMailboxProviders` with the `PublicMailboxProvider`
    type and a `lookupPublicMailboxProvider(domain, catalog?)` helper. It is
    owned by this project and is **not** an imported PSL/brand/word list, so it
    crosses no external-data license boundary.
  - Added `senderIdentity.fromDomainIsPublicMailboxProvider` and
    `senderIdentity.publicMailboxProviderId`, populated by matching the From
    registrable domain (when a `getRegistrableDomain` resolver is supplied, else
    the exact From domain) against the catalog. Membership is a fact, never a
    verdict.
  - Let callers extend or fully replace the catalog via the new
    `MetricsDependencies.publicMailboxProviders` (kept out of the serializable
    `AnalyzeInput`, like `getRegistrableDomain`); omitting it uses the built-in.
  - Added the opt-in `composite.publicMailboxSpoofingCandidate` rule (medium):
    fires when the visible From is a catalog public-mailbox domain, a trusted
    header evaluated the message, and no aligned, trusted authentication vouches
    for it. Because these providers publish enforcing DMARC, missing alignment is
    the spoof tell on its own. Gated like the other From-spoof composites
    (trusted sender-auth check required, aligned trusted DMARC pass suppresses),
    so it cannot be suppressed without real aligned auth nor manufactured against
    honest mail via a forge-able header. Scoring/policy stays with the caller.
  - Added focused tests and README documentation; updated the existing
    sender-identity fixtures for the two new (additive) metric fields.
- Added whitespace-compacted display-name metrics for brand-style matching (issue #46):
  - Extended `DisplayNameMetrics` with `normalized.compactedWhitespace` (the
    display name with all intra-name whitespace removed), `metrics.whitespaceCompactedChanged`
    (whether compaction changed the effective token), and
    `signals.spacedDisplayNameCamouflageCandidate` (a letter-spacing brand-camouflage
    hint), so consumers can detect spaced brand-style names — e.g.
    `D d a i i c h i L i f e I n s u r a n c e` — without re-implementing the
    normalization. Added the `DisplayNameNormalization`, `DisplayNameDerivedMetrics`,
    and `DisplayNameSignals` types and exported the pure `computeDisplayNameWhitespace`
    helper.
  - The camouflage candidate fires only when single Unicode letters dominate the
    whitespace-separated tokens (≥ 3 tokens, ≥ 3 single letters, single-letter
    majority), so normal multi-word names and one/two-initial names stay unflagged.
    The compacted form is a lexical token only — never parsed or used as an email
    address — and no brand list, word list, or other licensed data is bundled. The
    raw display name remains available, and the library assigns no score.
- Audited Thunderbird add-on core-logic migration completeness (issue #45):
  - Added `MIGRATION-AUDIT.md`, an explicit source-area inventory classifying
    every add-on core-relevant behavior as *Migrated* (with owning source/tests
    named), *Not core* (caller-owned: UI, notifications, mailbox actions,
    storage, Thunderbird/WebExtension APIs, network/DNS, scoring policy, bundled
    PSL/word-list data), *Needs migration*, or *Needs decision*. One reusable
    core item remains *Needs migration* — `jaroWinkler.js`, the pure, data-free
    Jaro-Winkler string-similarity helper, tracked as a concrete follow-up issue
    — and one item is *Needs decision*: `bigramNaturalness.js`, whose naturalness
    scoring needs a license-cleared language-frequency corpus before its
    algorithm can be ported.
  - Replaced the README's ambiguous "early development" / "remaining rules will
    be migrated incrementally" wording (which implied both an incomplete and a
    completed migration) with a "Migration status" section stating that most
    reusable core is migrated but the migration is **not** complete —
    `jaroWinkler.js` remains *Needs migration* and `bigramNaturalness.js` is
    *Needs decision* — and that future add-on logic is evaluated case by case.
    No source or behavior change.

## v0.3.0 — 2026-06-18

- Exported `computeLexicalHeuristics(token)` and the `LexicalHeuristics` type (issue #41):
  - Added data-free, policy-neutral lexical shape metrics: Shannon entropy,
    normalized entropy, vowel ratio, max consonant run, max repeated-character
    run, unique character ratio, and letter/digit transition count.
  - Kept the helper outside `analyzeMessage` output so callers own thresholds,
    scoring, and actions. No word lists, brand dictionaries, language corpora,
    n-gram tables, PSL data, or other licensed datasets are bundled.
  - Added README guidance and focused fixture/invariant tests.

## v0.2.0 — 2026-06-18

- Ported the Layer 4 composite rule framework as reusable signal rules (issue #35):
  - Added a composite-rule framework alongside the per-metric base rules: the
    `CompositeRule` / `CompositeRuleContext` types and `runCompositeRules`. A
    composite rule reads both the extracted metrics and the base signals already
    produced for the message, so it can combine several lower-layer outcomes
    (authentication + consistency + identity) into one higher-confidence
    observation. Composite signals use the new `"composite"` `SignalCategory` and
    name the lower-layer signal keys that justified them in
    `data.contributingSignals`.
  - Composite rules are an opt-in layer: `analyzeMessage(input, rules?, deps?, compositeRules?)`
    gained an optional fourth argument that defaults to none, so the default
    output is unchanged unless a caller passes `defaultCompositeRules`. They emit
    structured signals only — never a Thunderbird action, score, or
    allow/block/move/notify decision.
  - Ported three composites, each with attacker-model documentation:
    - `composite.unauthenticatedFromSpoof` (high): the visible From has no
      aligned, trusted authentication **and** another sender identifier disagrees
      with it — the direct domain-impersonation shape. Guarded to stay silent on
      unevaluable messages (no trusted header) and honest auth misconfigurations
      (no identifier mismatch).
    - `composite.authenticatedDisplayNameSpoof` (medium): a message that
      authenticates for its real From domain yet carries a display name addressing
      a different domain — the authenticated-lookalike case a pure auth/Junk filter
      would wave through.
    - `composite.alignedAuthenticationConfirmed` (info): a false-positive
      mitigation that affirms a clean, aligned, trusted message. It gates on real
      aligned authentication for the visible From (which a spoofer of another
      domain cannot produce) and withholds on any conflicting auth/consistency
      signal or misleading display name, so it cannot be used to launder a
      forgery. Its guard conditions are documented inline.
  - Added `test/composite.test.ts` and the `composite-unauthenticated-from-spoof`,
    `composite-authenticated-displayname-spoof`, and
    `composite-aligned-authentication-confirmed` serializable fixtures. The parity
    corpus and existing fixtures are unchanged, confirming the default pipeline is
    byte-for-byte identical.

- Ported sender-identity metrics (issue #34):
  - Added `MessageMetrics.senderIdentity` (`SenderIdentityMetrics`): a
    serializable, scoring-free view of the sender's identity shape derived from
    the `From` mailbox and the `Message-ID` domain. Includes display-name
    structure (`DisplayNameMetrics`) with address-in-display-name detection
    (`containsEmail`, `embeddedDomains`, `embeddedDomainMatchesFromDomain` — the
    `From: "service@brand.com" <attacker@evil.test>` spoof shape), local-part and
    domain lexical profiles (`LexicalStats`: codepoint `length`, `digitCount`,
    `hyphenCount`, `hasNonAscii`), and domain label decomposition
    (`DomainParts`: `labels`, `labelCount`, `topLabel`).
  - Added an optional registrable-domain comparison
    (`messageIdRegistrableDomainMatchesFromDomain`, plus `DomainParts.registrableDomain`
    and `subdomainDepth`). These require a caller-supplied registrable-domain
    resolver, injected via the new non-serializable `MetricsDependencies`
    argument to `analyzeMessage(input, rules?, deps?)` / `extractMetrics(input, deps?)`.
    **No Public Suffix List, brand list, or word list is bundled** (license
    boundary; see `AGENTS.md` / `NOTICE`); without a resolver the
    registrable-domain fields stay `null` and the label-based fields are still
    populated.
  - Added the `parseFromMailbox` and `extractEmbeddedDomains` domain helpers and
    the `computeSenderIdentity`, `computeDomainParts`, and `computeLexicalStats`
    functions to the public API, with the `SenderIdentityMetrics`,
    `DisplayNameMetrics`, `DomainParts`, `LexicalStats`, and `MetricsDependencies`
    types.
  - Metrics stay separate from scoring/rule policy: no new rule or signal is
    emitted by this change. Added `test/senderIdentity.test.ts` with benign and
    suspicious fixtures (`senderidentity-benign.json`,
    `senderidentity-display-name-spoof.json`) and extended every existing metric
    fixture (and the parity corpus) with the `senderIdentity` field.

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

