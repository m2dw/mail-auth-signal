# Thunderbird Add-on Core Logic Migration Audit

Tracks issue [#45](https://github.com/m2dw/mail-auth-signal/issues/45).

This document is the explicit source-to-source migration inventory between the
`thunderbird-auth-results-filter` Thunderbird add-on and this
`mail-auth-signal` reusable core. It exists so that documentation no longer
implies both "migration incomplete" and "everything has been copied" at the
same time.

Every add-on core-relevant behavior is classified as exactly one of:

- **Migrated** — present in `mail-auth-signal`, with the owning source/tests named.
- **Not core** — UI, notification, mailbox/folder action, storage, Thunderbird/
  WebExtension API, network/DNS, or local policy/score threshold. Caller-owned by
  the boundary in `AGENTS.md`; intentionally **not** migrated.
- **Needs migration** — pure parsing, metric extraction, signal/rule logic, or a
  serializable helper that belongs in this core but is not here yet.
- **Needs decision** — unclear ownership, a license boundary, or a data
  dependency that requires a human choice.

## Evidence base

This audit classifies the add-on's core modules — the `src/core/*.js` files —
file by file, and confirms each classification against direct inspection of this
repository:

- the add-on's `src/core/*.js` module set, including the seven modules the
  reviewer named: `jaroWinkler.js`, `bigramNaturalness.js`, `customFormulas.js`,
  `whitelist.js`, `scoring.js`, `ruleRegistry.js`, and `psl.js`,
- the current `mail-auth-signal` source tree (`src/`, `test/`), inspected
  directly to confirm whether an equivalent is **present or absent** (e.g. a
  repo-wide search shows there is *no* string-similarity / Jaro-Winkler /
  edit-distance code here, and `src/types.ts` already records bigram naturalness
  as a deliberate omission),
- the package boundary fixed in [`AGENTS.md`](./AGENTS.md) and
  [`CLAUDE.md`](./CLAUDE.md), which decides what is core versus caller-owned.

Each named module is mapped below to exactly one classification. Where a module
is *Migrated*, the owning source/tests in this repo are named; where it is
*Needs migration*, its absence here was verified by inspection, not assumed.

**One step not performed here:** a remote line-level re-diff of the add-on at its
current HEAD (a fresh clone / network fetch is restricted in this environment).
That step is *verification only* and is **not** what this audit's conclusion
rests on — the conclusion below already names concrete remaining work
(`jaroWinkler.js`) found by inspecting this repo, rather than declaring the set
empty. If a future HEAD-level diff surfaces additional owner-controlled core
logic, it becomes a new follow-up at that time.

## Per-module classification (`src/core/*.js`)

| Add-on core module | Classification | Basis |
|---|---|---|
| `jaroWinkler.js` (Jaro-Winkler string similarity) | **Migrated** | Ported as `src/jaroWinkler.ts`, exporting `computeJaro` and `computeJaroWinkler`. Tests in `test/jaroWinkler.test.ts` (fixtures + invariants). See issue #50. |
| `bigramNaturalness.js` (bigram "naturalness" scoring) | **Needs decision** | A meaningful naturalness score needs a language-frequency dataset; bundling one crosses the data/license boundary in `AGENTS.md`. `src/types.ts` already documents this as a deliberate omission. The *algorithm* is portable; the *corpus* is the decision. |
| `customFormulas.js` (user-defined scoring formulas) | **Not core** | Caller-configurable scoring/policy. The core emits observations; callers compose formulas and thresholds. |
| `whitelist.js` (allow-list matching) | **Not core** | Allow/block lists are explicitly caller-owned by `AGENTS.md`. The data and the trust decision belong to the caller. |
| `scoring.js` (weights / thresholds) | **Not core** | Local scoring weights and thresholds are policy. The core returns severity-tagged signals; callers score and decide. |
| `ruleRegistry.js` (rule registration / dispatch) | **Migrated** (pattern) | The structured rule-evaluation pattern is present as `src/rules/*` plus the `src/analyze.ts` orchestration and `src/index.ts` exports. Any per-rule enable/disable gated by user preferences, or weight assignment, is the **Not core** policy slice and stays with the caller. |
| `psl.js` (Public Suffix List handling) | **Migrated** (capability) / **Not core** (data) | The registrable-domain *capability* is migrated as a caller-injected resolver (`MetricsDependencies.getRegistrableDomain`); the PSL *data* is intentionally not bundled (license/data boundary). Documented in `src/types.ts` and `src/senderIdentity.ts`. |

## Add-on areas reviewed

The add-on's behavior splits into a pure detection engine (candidate core) and a
Thunderbird integration shell (caller-owned). The functional areas reviewed:

Detection engine (candidate reusable core):

- Header access and normalization.
- `Authentication-Results` parsing — SPF/DKIM/DMARC method and result extraction,
  authserv-id and method-property parsing.
- Trusted authserv-id matching.
- Authentication outcome modeling — raw results and From-alignment/summary.
- Per-identifier domain-consistency checks (Message-ID, Reply-To, Return-Path,
  SPF `smtp.mailfrom`, DKIM `header.d`, DMARC `header.from`, envelope-sender
  agreement).
- Sender-identity shape — display name, address-in-display-name spoof, local-part/
  domain lexical structure, domain-label decomposition, registrable-domain
  comparison.
- Lexical "randomness" heuristics (entropy and related token-shape measures).
- Composite (multi-signal) detection layer.

Thunderbird integration shell (caller-owned):

- Message-display UI, badges, banners, and rendered text.
- Notifications.
- Mailbox/folder actions (move, junk/Junk, delete, tag).
- Storage / preferences / options-page state.
- Thunderbird and WebExtension APIs and message plumbing.
- Network/DNS lookups.
- Local scoring weights, thresholds, and allow/block lists.

## Inventory

### Migrated

| Add-on behavior (area) | `mail-auth-signal` source | Tests | Origin |
|---|---|---|---|
| Header normalization / access | `src/normalizeHeaders.ts` | `test/` parsing + fixtures | scaffold |
| `Authentication-Results` method/result parsing | `src/parseAuthenticationResults.ts` | `test/parseAuthenticationResults.test.ts` (+ fixtures) | scaffold |
| Sender domain / mailbox extraction | `src/domains.ts` | `test/` domain + identity tests | scaffold |
| Trusted authserv-id matching (shared trust resolution) | `src/rules/trust.ts`, `src/rules/untrustedAuthservId.ts` | `test/` AR rule tests | scaffold / #5 |
| Missing `Authentication-Results` detection | `src/rules/missingAuthResults.ts` | `test/` | scaffold |
| Trust-aware auth method-failure signals (SPF/DKIM/DMARC) | `src/rules/authMethodFailure.ts` | `test/authMethodFailure.test.ts` | #5 |
| Layer 1 raw SPF/DKIM/DMARC results projection | `src/metrics.ts` (`collectAuthenticationAlignment`) | `test/` metrics tests | #34-era auth metrics |
| Layer 2 trusted+passing alignment / summary flags | `src/metrics.ts` (`AuthenticationAlignment`) | `test/` metrics tests | auth-metrics issue |
| Message-ID ↔ From domain consistency | `src/rules/messageIdDomainMismatch.ts` | `test/` | consistency issues |
| Reply-To ↔ From domain consistency | `src/rules/replyToDomainMismatch.ts` | `test/` | consistency issues |
| Return-Path ↔ From consistency | `src/rules/returnPathDomainMismatch.ts` | `test/` | consistency issues |
| SPF `smtp.mailfrom` ↔ From consistency | `src/rules/smtpMailfromDomainMismatch.ts` | `test/` | consistency issues |
| Envelope-sender internal disagreement | `src/rules/envelopeSenderDisagreement.ts` | `test/` | consistency issues |
| DKIM `header.d` ↔ From consistency | `src/rules/dkimDomainMismatch.ts` | `test/` | consistency issues |
| DMARC `header.from` ↔ From consistency | `src/rules/dmarcHeaderFromMismatch.ts` | `test/dmarcHeaderFromMismatch.test.ts` | #16 |
| Sender-identity metrics: display name, address-in-display-name spoof, lexical stats, domain parts | `src/senderIdentity.ts` | `test/senderIdentity.test.ts` | #34 |
| Registrable-domain comparison via caller-injected resolver | `src/senderIdentity.ts` + `MetricsDependencies` | `test/senderIdentity.test.ts` | #34 |
| Lexical "randomness" heuristics (entropy, vowel ratio, runs, transitions) | `src/senderIdentity.ts` (`computeLexicalHeuristics`) | `test/` lexical tests | #41 |
| Jaro-Winkler string-similarity helper (`computeJaro`, `computeJaroWinkler`) | `src/jaroWinkler.ts` | `test/jaroWinkler.test.ts` (fixtures + invariants) | #50 |
| Composite (Layer 4) multi-signal rules | `src/rules/composite/*.ts` | `test/composite.test.ts` | #35 |

All five composite rules — `composite.unauthenticatedFromSpoof`,
`composite.publicMailboxSpoofingCandidate` (issue #47),
`composite.authenticatedDisplayNameSpoof`,
`composite.unsecuredDeepSubdomainCandidate` (issue #48), and the
false-positive-mitigating `composite.alignedAuthenticationConfirmed` — are
migrated as structured signals (no Thunderbird action attached).

### Not core (intentionally caller-owned, not migrated)

| Add-on behavior | Why it stays with the caller |
|---|---|
| Message-display UI, badges, banners, rendered text | Presentation; the core returns severity-tagged signals, not UI. |
| Notifications | Caller decides whether/how to notify. |
| Mailbox/folder actions (move, Junk, delete, tag) | Mailbox mutation is out of the pure-core boundary. |
| Storage, preferences, options-page state | Caller-owned configuration and persistence. |
| Thunderbird / WebExtension APIs and message plumbing | Runtime-specific; the core is runtime-neutral. |
| Network / DNS lookups | The core performs no I/O; DNS is a caller concern. |
| Local scoring weights, thresholds, allow/block lists | Policy. The core emits observations; callers score and decide. The `examples/score-stdin.mjs` weights are illustrative caller policy, not part of the library. |
| Public Suffix List / brand / word-list / n-gram data | License/data boundary (see `AGENTS.md` / `NOTICE`). The *capability* is migrated as a caller-injected resolver; the *data* is deliberately not bundled. |

### Needs migration

*(None remaining. `jaroWinkler.js` was the last outstanding item; it was ported
in issue #50 as `src/jaroWinkler.ts` — see the Migrated table above.)*

### Needs decision

1. **`src/core/bigramNaturalness.js` — bigram "naturalness" scoring (data
   dependency).** The algorithm is portable, but a meaningful naturalness score
   needs a language-frequency dataset, and bundling one would cross the
   data/license boundary in `AGENTS.md`. `src/types.ts` already records this as a
   deliberate omission. The decision required from a human is whether to (a) keep
   it out (status quo), or (b) port it gated on a caller-supplied, license-cleared
   frequency table. No code change here until that is decided.
2. **Any future bundling of PSL / brand / word-list / n-gram data.** Remains a
   license decision, already documented as out of scope (covers the `psl.js` data
   and `whitelist.js` reference data). Listed here so the boundary is an explicit
   recorded decision, not an oversight.

## Conclusion

All of the reusable core from the Thunderbird add-on — header normalization,
`Authentication-Results` parsing, trusted-source resolution, authentication
outcome/alignment modeling, the per-identifier domain-consistency rules,
sender-identity metrics, the lexical-heuristics helper, the Jaro-Winkler
string-similarity helper, the structured rule-evaluation pattern
(`ruleRegistry.js` → `src/rules/*` + `src/analyze.ts`), the PSL *capability*
(as an injected resolver), and the composite detection layer — **has been
migrated** into `mail-auth-signal`.

**`bigramNaturalness.js`** is **Needs decision** (it needs a license-cleared
frequency corpus). The caller-owned modules — `customFormulas.js`,
`whitelist.js`, `scoring.js`, and the PSL/reference *data* — are **Not core**
by the package boundary and stay with the caller.

Future add-on logic will be evaluated case by case against this same four-way
classification.
