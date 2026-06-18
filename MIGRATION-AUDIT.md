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

## Evidence base and its limitation

This audit was performed against the authoritative local record of the
migration:

- the current `mail-auth-signal` source tree (`src/`, `test/`),
- the per-issue migration history in [`CHANGELOG.md`](./CHANGELOG.md) and the
  feature documentation in [`README.md`](./README.md), each of which names the
  add-on layer it ported and the originating issue (scaffold plus issues #5,
  #16, #24, #26, #34, #35, #41),
- the package boundary fixed in [`AGENTS.md`](./AGENTS.md) and
  [`CLAUDE.md`](./CLAUDE.md).

The migration has been **issue-driven**: each reusable add-on behavior was
ported under a tracked issue whose changelog entry cites the add-on layer it
came from. This audit reconciles that record into a single classified
inventory.

**Limitation (one residual verification step):** a fresh clone of the
`thunderbird-auth-results-filter` repository could not be re-read in the
environment this audit ran in (network fetches are sandbox-restricted here), so
the inventory is built from the project's own migration record rather than from
a line-by-line re-diff of the add-on at its current HEAD. The classifications
below reflect the add-on's documented detection architecture (the layered model
the README and CHANGELOG describe). One confirmatory re-diff item is recorded
under **Needs decision** so this is not mistaken for a line-level proof. No
behavior change in this package is required by that step; it is verification
only.

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
| Composite (Layer 4) multi-signal rules | `src/rules/composite/*.ts` | `test/composite.test.ts` | #35 |

All three composite rules — `composite.unauthenticatedFromSpoof`,
`composite.authenticatedDisplayNameSpoof`, and the false-positive-mitigating
`composite.alignedAuthenticationConfirmed` — are migrated as structured signals
(no Thunderbird action attached).

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

None identified. Every owner-controlled, Apache-2.0-compatible, reusable core
detection behavior the add-on contains maps to a **Migrated** row above. The
remaining add-on surface is **Not core** by the package boundary.

### Needs decision

1. **Confirmatory source-to-source re-diff against the add-on at its current
   HEAD.** This audit reconciles the project's migration record rather than
   re-reading a fresh add-on clone (see *Limitation* above). When the add-on
   repository is accessible from an environment with network/clone access, a
   line-level diff should confirm no owner-controlled core behavior was added to
   the add-on after its piece was ported here. This is verification only; it
   prescribes no behavior change to this package. If that diff surfaces new
   reusable core logic, it becomes a concrete **Needs migration** follow-up
   issue at that time.
2. **Any future bundling of PSL / brand / word-list / n-gram data.** Remains a
   license decision, already documented as out of scope. Listed here so the
   boundary is an explicit recorded decision, not an oversight.

## Conclusion

The currently identified reusable core from the Thunderbird add-on — header
normalization, `Authentication-Results` parsing, trusted-source resolution,
authentication outcome/alignment modeling, the per-identifier domain-consistency
rules, sender-identity metrics, the lexical-heuristics helper, and the composite
detection layer — **has been migrated** into `mail-auth-signal`. No reusable
core behavior is classified **Needs migration**. The remaining add-on surface is
caller-owned (**Not core**), and the only open items are verification/decision
items, not pending core ports. Future add-on logic will be evaluated case by
case against this same four-way classification.
