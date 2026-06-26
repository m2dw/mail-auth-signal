# Changelog

## Unreleased

- Migrated further Layer 4 composite rule signals into the reusable core (issue #65),
  extending `defaultCompositeRules` with five named, stable, opt-in signals. Each
  emits structured data with severity hints only — no score deltas, thresholds, or
  Review/Junk actions, which stay caller-owned:
  - `composite.deepRandomFromSubdomain` (low): a deep From subdomain
    (`subdomainDepth >= 2`) with at least one random-looking subdomain label and no
    aligned authentication — the random-label twin of
    `composite.unsecuredDeepSubdomainCandidate`.
  - `composite.brandDivergencePhishing` (high): the Layer-4 elevation of the base
    `displayName.brandDomainMismatch` (issue #64) — the From display name reads as a
    catalog brand the From domain does not belong to, with the From's authentication
    posture reported in `data.fromAuthenticated`. Opt-in via `brandCatalog`.
  - `composite.ownDomainSpoofCandidate` (high): an unauthenticated From wearing one of
    the caller's own account domains, supplied via
    `options.context.accountDomains` (exported `OWN_ACCOUNT_DOMAINS_CONTEXT_KEY`).
  - `composite.dkimFailWithAlignedPass` (info): a benign DKIM failure mitigated by an
    aligned, trusted, passing DKIM signature for the From (a broken/extra signature).
  - `composite.dkimAlignedLexicalMitigation` (info): a random-looking From identity
    mitigated by an aligned DKIM signature — a positive counter-signal for
    authenticated automated mail.
  - The two mitigations gate on a *real* aligned DKIM pass that only the From domain
    can produce, so neither is attacker-triggerable; the candidates require no aligned
    authentication and cannot be suppressed without it. Documented in `README.md` and
    covered by `test/compositeMigrated.test.ts` (a spam-like positive and a ham-like
    guardrail for each). No change to base or pre-existing composite output.
- Completed Layer 3 lexical and heuristic parity with the add-on (issue #66):
  - Extended `computeLexicalHeuristics` / `LexicalHeuristics` with the remaining
    add-on `lexicalMetrics.js` fields, all data-free and structural: `alphaLength`,
    the y-inclusive `vowelCount` / `vowelRatioAlphaOnly`, the raw `hyphenCount` and
    `uniqueCharCount` behind the existing ratios, a symbol-skipping
    `letterDigitTransitionCount` (counts a letter↔digit change across separators,
    so `"ab-12"` → `1`), and a digit-required `hasLongHexLikeRun` (a hex run of ≥ 4
    that contains a digit — so `"deadbeef"` has `maxHexRun` 8 but
    `hasLongHexLikeRun` false).
  - Restored `computeRandomLookingCandidate` parity with the add-on's checks:
    lowered the length floor from 8 to 6 so short all-consonant labels such as
    `mpqxyt` flag, and added the add-on's letters-only uppercase rule so labels such
    as `CAQLEV` flag. Known brand/word false positives (`switchbot`, `crowdworks`,
    `github`, …) still read false.
  - Resolved the bigram-naturalness data boundary (the `bigramNaturalness.js`
    "Needs decision" item): the library bundles no language corpus, and
    `computeRandomLookingCandidate(token, { isNatural })` now accepts a caller-
    supplied naturalness model. This closes the one parity gap pure structure
    cannot — a word-shaped gibberish label such as `wlikqkgi` is indistinguishable
    by shape from a real word such as `switchbot`, so it is flagged only when the
    caller injects its own corpus-backed model. Exported `RandomLookingOptions`.
  - Updated `README.md` and `MIGRATION-AUDIT.md` to state what moved and what
    intentionally remains caller-owned; expanded `test/lexicalHeuristics.test.ts`
    and the hand-computed `test/fixtures/lexical-heuristics.json`. No change to the
    pinned `analyzeMessage` / `senderIdentity` output (these stay exported helpers).
- Migrated display-name brand inference into the reusable core (issue #64):
  - Added `src/brandInference.ts` with `computeDisplayNameBrandInference`, plus the
    exported helpers `foldLatinDiacritics` and `normalizeBrandToken` and the
    documented threshold constants (`BRAND_LIKE_MIN_LETTERS`,
    `BRAND_LIKE_MIN_LETTER_RATIO`, `BRAND_MATCH_MIN_JARO_WINKLER`,
    `BRAND_MATCH_MIN_JACCARD`). The inference folds Latin diacritics (the #59
    `HERMÈS` → `HERMES` fix, now a reusable helper), normalizes the display name to
    a brand token (collapsing letter-spacing camouflage), and matches it against a
    caller-supplied catalog using exact / Jaro-Winkler / Jaccard similarity.
  - Added `src/jaccard.ts` with the pure, data-free `computeJaccard(a, b)` bigram
    Jaccard similarity helper, exported from the public API to corroborate
    Jaro-Winkler in brand matching.
  - Added `SenderIdentityMetrics.brandInference` (`DisplayNameBrandInference`),
    populated **only** when a caller supplies `MetricsDependencies.brandCatalog`
    and omitted entirely otherwise, so existing serialized snapshots are
    unaffected. New types: `BrandCatalogEntry`, `BrandMatch`,
    `DisplayNameBrandInference`, `BrandInferenceNotApplicableReason`.
  - Added the opt-in `displayNameBrandDomainMismatchRule`
    (`displayName.brandDomainMismatch`, medium severity, `consistency` category) to
    `defaultRules`, emitting a signal when the display name reads as a known brand
    the From domain does not belong to.
  - Guardrails report explicit not-applicable reasons for non-Latin,
    **mixed-script homoglyph** (refused outright so folding cannot manufacture a
    brand match), insufficient-signal, missing-From-domain, and empty-catalog
    cases.
  - **Data boundary:** the inference logic is library-owned but the brand catalog
    stays **caller-supplied data** — the core bundles no brand/top-domain list (see
    `AGENTS.md` / `NOTICE`), so no license documentation change was required. The
    add-on can now remove or greatly shrink its local `displayNameMetrics.js` and
    keep only its own `topDomains.js` data, passing it as `brandCatalog`.
  - Added `test/brandInference.test.ts` covering HERMES/HERMÈS parity, an obvious
    brand mismatch, a matching brand domain (incl. via the registrable domain),
    letter-spacing camouflage, a Jaro-Winkler/Jaccard near-miss, non-Latin and
    mixed-script/homoglyph guardrails, the remaining not-applicable reasons, and
    `analyzeMessage` opt-in integration.
  - Updated `README.md` (sender-identity table, new "Display-name brand inference"
    and signal sections, Jaccard helper, migration status).
- Made message identity extraction authoritative so the Thunderbird add-on can
  stop owning local `messageIdentity.js` extraction/comparison facts (issue #63):
  - Added RFC 5322 `Sender` header extraction. `MessageMetrics` now carries
    `senderDomain`, `senderDomainMatchesFromDomain` (exact), and
    `senderDomainRegistrableMatchesFromDomain` (PSL registrable). `Sender` is
    parsed with the same hardened mailbox extractor as `From` (angle-addr
    precedence, comment stripping); a missing `Sender` leaves all three `null`.
  - Added registrable-domain complements to the exact From comparisons for the
    Reply-To and Return-Path identity domains
    (`replyToDomainRegistrableMatchesFromDomain`,
    `returnPathDomainRegistrableMatchesFromDomain`), matching the existing
    `senderIdentity.messageIdRegistrableDomainMatchesFromDomain`. All use the
    built-in PSL resolver by default and report `null` when a side is absent or
    unresolvable.
  - Exported the `registrableDomainsMatch` (single domain) and
    `allRegistrableDomainsMatch` (mailbox-list) helpers so callers can run the
    same organizational comparison over their own domains.
  - No new rule, signal, or scoring policy is introduced — these are pure,
    serializable facts. `senderIdentity` and all existing signals are unchanged.
  - Added `test/messageIdentity.test.ts` (Sender extraction, angle-bracket
    precedence, missing domains, `.co.jp` registrable comparisons, helper unit
    tests); extended the parity metric-key set and refreshed fixtures with the
    new keys.
  - Updated `README.md` and `MIGRATION-AUDIT.md`.
- Moved PSL-aware authentication alignment into the core (issue #62):
  - `AuthenticationAlignment` now carries an `organizational`
    (`OrganizationalAlignment`) view alongside the existing exact-domain flags:
    `resolverAvailable`, `spfAligned`, `dkimAligned`, `anySpfAligned`,
    `anyDkimAligned`, `anyAuthAligned`, and the `unalignedPassingSpfDomains` /
    `unalignedPassingDkimDomains` lists. It applies the same trusted + passing
    gating as Layer 2 but compares **registrable (organizational) domains**, so a
    From subdomain aligns with an authenticated organizational identifier — the
    relaxed-mode alignment DMARC actually evaluates, and the practical default a
    consumer should prefer over the exact-domain `anyAuthAligned`. The
    exact-domain flags remain available unchanged.
  - The registrable boundary comes from the caller-supplied
    `MetricsDependencies.getRegistrableDomain` resolver (the core bundles no PSL
    data; license boundary in `NOTICE` / `AGENTS.md`). The resolver is threaded
    through `analyzeMessage`, `extractMetrics`, `runRules`, and
    `runCompositeRules` (each gained an optional `deps` argument) so the
    organizational view stays consistent across the split API. With no resolver
    the fields degrade cleanly to exact-domain comparison and record
    `resolverAvailable: false`.
  - Added the data-free domain helpers `registrableDomainOrSelf`,
    `domainsOrganizationallyAlign`, and `allDomainsOrganizationallyAlign`, and
    exported the `OrganizationalAlignment` type.
  - Added `test/organizationalAlignment.test.ts` covering compound suffixes such
    as `.co.jp`, resolver-override behavior, cross-organization spoofs on a shared
    suffix, the any-vs-all distinction, trust/pass gating, and resolver threading
    through `analyzeMessage` / `runRules`. Updated the serializable fixtures to
    pin the new `organizational` block.
  - The package emits facts/signals only; score weights remain with the caller.

## v0.5.0 — 2026-06-25

- Bundled tldts as a runtime dependency and enabled PSL-backed registrable-domain
  metrics by default (issue #61):
  - `analyzeMessage(input)` now populates `registrableDomain`, `subdomainDepth`,
    and `messageIdRegistrableDomainMatchesFromDomain` without any caller setup.
    The built-in resolver uses ICANN public suffixes only (`allowPrivateDomains:
    false`); unknown TLDs follow tldts's default fallback (TLD as public suffix).
  - A caller-supplied `MetricsDependencies.getRegistrableDomain` still takes
    precedence, enabling custom PSL snapshots or private-registry entries.
  - To opt out of PSL resolution entirely (the pre-v0.5.0 behaviour), pass
    `getRegistrableDomain: () => null`.
  - The built-in resolver is exported as `defaultGetRegistrableDomain` for
    callers that want to reference or extend it.
  - Added `src/psl.ts` with the built-in resolver; no other core module changed
    behavior.
  - Updated `NOTICE` with tldts (MIT) and Public Suffix List (MPL 2.0) license
    attribution.
  - Updated `README.md`, `MIGRATION-AUDIT.md`, and `CHANGELOG.md` to reflect
    that PSL support is now bundled and enabled by default.
  - Added `test/psl.test.ts` covering: compound suffix (`.co.jp`), standard
    subdomain depth, Message-ID/From registrable-domain comparison, and custom
    resolver override.
  - Updated existing fixtures and the `unsecuredDeepSubdomainCandidate` test to
    reflect the new PSL-populated defaults.

## v0.4.0 — 2026-06-19

- Ported Jaro-Winkler string-similarity helper into reusable core (issue #50):
  - Added `src/jaroWinkler.ts` with the pure, data-free `computeJaro(a, b)` and
    `computeJaroWinkler(a, b, p?)` helpers, both exported from the public API.
    Results are rounded to 4 decimal places (same convention as `LexicalHeuristics`)
    for stable, cross-language-comparable fixture values.
  - No brand lists, word lists, language corpora, or other licensed datasets are
    bundled. The implementation is a clean port of the standard algorithm with
    Unicode codepoint-array splitting so multi-byte characters are counted correctly.
  - Added `test/jaroWinkler.test.ts` with a focused fixture/invariant suite and
    the `test/fixtures/jaro-winkler.json` serializable fixture.
  - Updated `MIGRATION-AUDIT.md`: `jaroWinkler.js` moves from *Needs migration*
    to *Migrated* — this was the last outstanding item from the #45 audit.
    `bigramNaturalness.js` remains *Needs decision* (license-cleared corpus required).

- Added DMARC-none deep-subdomain composite signal (issue #48):
  - Added the opt-in `composite.unsecuredDeepSubdomainCandidate` rule (low):
    fires when the visible From is on a deep subdomain (`subdomainDepth ≥ 2`, PSL-
    derived via caller-supplied `getRegistrableDomain`) **and** a trusted verifier
    reported `dmarc=none` for that From's organizational domain. Neither condition
    alone is suspicious — the combination is the disposable-subdomain spoofing
    shape: a pronounceable subdomain stack under a cheap registrable domain with no
    enforced DMARC policy.
  - The rule requires a registrable-domain resolver; without one `subdomainDepth`
    is `null` and the rule stays silent rather than guess. The `dmarc=none` is
    bound to the current From's organizational domain via its `header.from` field,
    so a `none` from a different domain cannot satisfy the guard. No score or
    allow/block/move decision is emitted.
  - Added focused tests in `test/unsecuredDeepSubdomainCandidate.test.ts`.

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
    PSL/word-list data), *Needs migration*, or *Needs decision*. At audit time,
    one reusable core item was *Needs migration* — `jaroWinkler.js` — and one
    was *Needs decision*: `bigramNaturalness.js`. `jaroWinkler.js` has since been
    completed by issue #50 (see above); `bigramNaturalness.js` remains *Needs
    decision* pending a license-cleared language-frequency corpus.
  - Replaced the README's ambiguous "early development" / "remaining rules will
    be migrated incrementally" wording with a "Migration status" section stating
    that most reusable core is migrated but the migration is **not** complete.
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

