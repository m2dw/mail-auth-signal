# Mail Auth Signal

[![CI](https://github.com/m2dw/mail-auth-signal/actions/workflows/ci.yml/badge.svg)](https://github.com/m2dw/mail-auth-signal/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/mail-auth-signal)](https://www.npmjs.com/package/mail-auth-signal)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Mail Auth Signal is a lightweight sender-risk signal engine for email authentication results and header consistency analysis.

It is the standalone, Apache-2.0 licensed core extracted from the Thunderbird Auth Results Filter project. A per-module audit of the add-on's `src/core/*.js` files (see [`MIGRATION-AUDIT.md`](./MIGRATION-AUDIT.md) and [Migration status](#migration-status)) confirms that all reusable detection logic has been migrated here. The library focuses on pure parsing and signal extraction. It does not move messages, show UI, access Thunderbird APIs, perform DNS lookups, or send message data anywhere.

## Goals

- Parse email authentication signals such as `Authentication-Results`, SPF, DKIM, and DMARC outcomes.
- Extract sender-origin consistency signals from headers such as `From` and `Message-ID`.
- Return structured metrics and reason objects that callers can score, log, display, or combine with their own rules.
- Remain runtime-neutral enough for WebExtension, Node.js, CLI, and future native/WASM ports.

## Non-goals

- This is not a full spam filter.
- This is not an MTA, MDA, or mail store.
- The core does not perform network access, DNS queries, mailbox access, notification, or message mutation.
- The core does not decide user policy by itself; callers choose thresholds and actions.

## Install

```sh
npm install mail-auth-signal
```

The package is published to the public npm registry as `mail-auth-signal` and is
installable by any consumer, including the Thunderbird add-on. If the install
above fails with `E404`, the first release has not been cut yet — until then, use
this repository directly.

Maintainers: see [RELEASING.md](./RELEASING.md) for the versioned release and
npm publishing process.

## Usage

```ts
import { analyzeMessage } from "mail-auth-signal";

const result = analyzeMessage({
  headers: {
    from: "Example Sender <notice@example.com>",
    "message-id": "<abc123@example.com>",
    "authentication-results": [
      "mx.example.net; dmarc=pass header.from=example.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com",
    ],
  },
  options: {
    trustedAuthservIds: ["mx.example.net"],
  },
});

console.log(result.signals);
```

## API boundary

`analyzeMessage(input: AnalyzeInput, rules?: readonly Rule[], deps?: MetricsDependencies, compositeRules?: readonly CompositeRule[]): AnalyzeResult`
is the primary public analysis entry point. Internally it runs in separable halves
so detection rules stay independently composable — callers can pass a subset, add
their own, or layer in any future rule without re-parsing headers:

```ts
import { extractMetrics, runRules, defaultRules, analyzeMessage } from "mail-auth-signal";

// analyzeMessage(input) is equivalent to:
const metrics = extractMetrics(input);          // parsing + facts, no interpretation
const signals = runRules(metrics, input.options, defaultRules); // interpretation only
```

- `extractMetrics(input)` — pure parsing/metric extraction. Returns serializable
  facts (`MessageMetrics`) with no signals attached.
- `runRules(metrics, options?, rules?)` — evaluates a rule set over already-extracted
  metrics. Lets callers cache or transport metrics and evaluate rules separately.
- `defaultRules` — the built-in per-metric rule set. Callers pass their own array (a
  subset of `defaultRules`, or custom `Rule`s) as the second argument to `analyzeMessage`.
- `defaultCompositeRules` / `runCompositeRules(...)` — the opt-in Layer 4 composite
  rules, which combine base signals into higher-confidence observations. They are
  **off by default**; pass them as the fourth argument to `analyzeMessage` to enable
  them. See [Composite (Layer 4) signals](#composite-layer-4-signals).

**What belongs in this library (core)**

| Concern | Type | Notes |
|---|---|---|
| Raw header input | `AnalyzeInput.headers` | Any normalized or unnormalized form |
| Caller environment | `AnalyzeInput.options` | Trusted authserv-ids, future policy context |
| Extracted facts | `AnalyzeResult.metrics` | Serializable, no interpretation |
| Keyed observations | `AnalyzeResult.signals` | Severity-tagged, no policy attached |

**What belongs in the caller (not in this library)**

- Threshold evaluation ("is severity ≥ medium a problem for me?")
- Allow/block/move/notify/quarantine decisions
- UI rendering, badge colours, notification text
- Mailbox access, DNS queries, network I/O
- Storage, logging infrastructure, telemetry

**Caller-provided context (`AnalyzeOptions`)**

The core is pure: it reads no globals, no environment variables, and performs no I/O. All context flows in through `AnalyzeOptions`:

- `trustedAuthservIds` — the authserv-ids the caller's mail system stamps on inbound mail. The caller is responsible for this list; the core has no built-in opinion.
- `context` — an open-ended serializable bag for future caller-provided policy context (per-sender overrides, allow-listed domains, metadata). Currently ignored by all rules; reserved as a forward-compatible extension point for caller-supplied policy context.

## Writing a rule

A `Rule` is the unit of extension. Each detection rule is a pure
function of a `RuleContext` (`{ metrics, options }`) that returns zero or more
`Signal`s — never a score or an allow/block decision. A rule that needs a new
fact adds it to metric extraction rather than re-parsing headers, keeping
parsing, metric extraction, and rule evaluation separable.

```ts
import { analyzeMessage, defaultRules } from "mail-auth-signal";
import type { Rule } from "mail-auth-signal";

const fromDomainMissingRule: Rule = {
  key: "from.domainMissing",
  description: "The From header had no parseable domain.",
  evaluate({ metrics }) {
    if (metrics.fromDomain) return [];
    return [{ key: "from.domainMissing", severity: "low", message: "No From domain." }];
  },
};

// Run the built-ins plus your rule:
const result = analyzeMessage(input, [...defaultRules, fromDomainMissingRule]);
```

The `test/fixtures/*.json` files are JSON fixtures (input + expected
`AnalyzeResult`) that pin the serializable output shape for tests and
cross-language ports.

## Signal taxonomy

Every signal carries a stable `key`, a coarse `category`, a `severity`, a
human-readable `message`, and (for most) a serializable `data` payload. The
`category` lets callers group or route signals without string-matching keys, and
draws the distinctions the surface must keep separate — an input that is absent,
a source that is untrusted, an authentication failure, and a domain-consistency
mismatch:

| `category` | Meaning | Signal key(s) |
|---|---|---|
| `absence` | An expected input was not present at all. | `auth.results.missing` |
| `trust` | An `Authentication-Results` header came from an untrusted authserv-id. | `auth.results.untrusted` |
| `auth-failure` | An SPF/DKIM/DMARC method returned a failing or error result. | `auth.method.failure` |
| `consistency` | Two domains that should agree do not. | `messageId.domainMismatch`, `replyTo.domainMismatch`, `returnPath.domainMismatch`, `smtpMailfrom.domainMismatch`, `dkim.domainMismatch`, `dmarc.headerFromMismatch`, `envelopeSender.domainDisagreement` |
| `composite` | A higher-layer observation that combines several of the above (the opt-in Layer 4 rules). | `composite.unauthenticatedFromSpoof`, `composite.publicMailboxSpoofingCandidate`, `composite.authenticatedDisplayNameSpoof`, `composite.unsecuredDeepSubdomainCandidate`, `composite.deepRandomFromSubdomain`, `composite.brandDivergencePhishing`, `composite.ownDomainSpoofCandidate`, `composite.dkimFailWithAlignedPass`, `composite.dkimAlignedLexicalMitigation`, `composite.alignedAuthenticationConfirmed` |

Two conventions keep the surface coherent:

- **Keys never overload multiple dimensions.** The failing method and result live
  in `data` (`{ method: "dmarc", result: "fail", … }`), not in the key, so the
  whole Authentication-Results failure family shares one enumerable
  `auth.method.failure` key instead of a combinatorial `auth.<method>.<result>`.
- **Every consistency signal carries a `mismatchedDomains: string[]`** naming the
  divergent subset, alongside the reference domain and the observed domain(s), so
  a caller reads the same field shape across all seven consistency signals.

Malformed or unparseable input is deliberately **not** a category: the rules stay
silent on it (the relevant match metric is left `null`) rather than emit a
low-confidence signal, so malformed input surfaces as the *absence* of a signal.

### Authentication-Results failure signals

`authMethodFailureRule` reports each SPF/DKIM/DMARC method that returned a
failing or error result (`fail`, `softfail`, `temperror`, `permerror`) as a
single `auth.method.failure` signal (category `auth-failure`), with the specific
`method` and `result` in its `data`. Severity is **trust-aware**, because an
`Authentication-Results` header can be forged by anyone upstream and is only
authoritative when stamped by an authserv-id the caller declared in
`trustedAuthservIds`:

| Result (from a **trusted** authserv-id) | Severity | Rationale |
|---|---|---|
| `dmarc=fail` | high | Message is unaligned with its own From domain — the canonical direct-domain spoofing signal. |
| `spf=fail` / `dkim=fail` | medium | Strong hint, but legitimate forwarding (SPF) and mailing-list body rewrites (DKIM) also break these. |
| `softfail` / `temperror` / `permerror` | low | Deliberately non-committal, or a transient/sender-side configuration error. |
| any of the above from an **untrusted** authserv-id | low | Non-authoritative — the header could be forged. `untrustedAuthservIdRule` flags the source separately. |

Each signal's `data` includes the failing `method` and `result`, the
`authservId`, a `trusted` flag, and the parsed method `properties`. Callers that
want to act on a specific method filter on `data.method`/`data.result` rather
than on the key. The rule emits observations only; thresholds and actions stay
with the caller.

### Message-ID domain consistency signal

`messageIdDomainMismatchRule` compares the `Message-ID` domain against the `From` domain.

| Signal | Compares | Attacker pattern | Common false positive |
|---|---|---|---|
| `messageId.domainMismatch` | Message-ID vs From | A recognizable brand in From, but the Message-ID is stamped by the attacker's own sending infrastructure, leaking the true origin. | Mailing lists, ESPs, and forwarders routinely stamp Message-IDs from their own domain; a sender may also use a separate mail-origin domain. |

Because the `Message-ID` is generated by the originating system and is not normally rewritten in transit, a divergent domain is a weak hint that the message and its claimed sender were produced by different parties. Severity is **low** and the signal is a consistency hint only, never a verdict.

Missing context stays silent: a missing `From`, a missing `Message-ID`, or input the parser cannot resolve to a dotted domain leaves `messageIdDomainMatchesFromDomain` `null` and emits no signal.

### Reply-To domain consistency signal

`replyToDomainMismatchRule` compares the `Reply-To` domain(s) against the `From` domain.

| Signal | Compares | Attacker pattern | Common false positive |
|---|---|---|---|
| `replyTo.domainMismatch` | Reply-To vs From | A recognizable brand displayed in From, but `Reply-To` steers replies to an attacker-controlled domain — a reply-chain and BEC (business-email-compromise) pattern where a recipient who hits "Reply" silently routes the answer to the attacker. | Marketing and transactional mail frequently steers replies to a support, helpdesk, or list domain; a person may send from a corporate address but ask for replies at a personal one. |

Severity is **low**. When `Reply-To` carries several mailboxes, a single domain that differs from `From` is enough to flag (the `mismatchedDomains` subset is reported), since that lone divergent reply target is exactly the attacker pattern.

Missing context stays silent: a missing `From`, a missing `Reply-To`, or mailboxes the parser cannot resolve to a dotted domain leaves `replyToDomainMatchesFromDomain` `null` and emits no signal.

### Sender header consistency metric

The RFC 5322 `Sender` header names the agent that actually submitted the message when it differs from the author (`From`) — e.g. a secretary, mailing-list, or automation account sending on behalf of a person. It is parsed with the same hardened mailbox extractor as `From` (first instance, angle-addr preferred over a quoted display name, RFC 5322 comments stripped), so a `Sender` whose display name embeds an address-shaped fragment cannot mask the real submitting domain.

This is exposed as the `senderDomain` metric plus its `From` comparisons (`senderDomainMatchesFromDomain` exact, `senderDomainRegistrableMatchesFromDomain` registrable) — facts only, with **no bundled rule or signal**, since a divergent `Sender` is normal for delegated and on-behalf-of mail. A missing `Sender` (the common case where author and submitter are the same) leaves all three `null`, so it never reads as a mismatch.

### Envelope-sender consistency signals

The envelope sender — the SMTP `MAIL FROM` / reverse-path — is reported through
two headers: `Return-Path` and the SPF `smtp.mailfrom` property inside
`Authentication-Results`. Three rules compare those domains:

| Signal | Compares | Attacker pattern | Common false positive |
|---|---|---|---|
| `returnPath.domainMismatch` | Return-Path vs From | Recognizable brand in From, attacker-controlled bounce/envelope domain. | ESPs and forwarders legitimately use a distinct bounce/VERP domain. |
| `smtpMailfrom.domainMismatch` | SPF `smtp.mailfrom` vs From | The same spoof seen through SPF — the mechanical basis of DMARC's SPF alignment. | Forwarding/mailing lists re-send under their own envelope (the reason SPF softfails on forwarded mail). |
| `envelopeSender.domainDisagreement` | Return-Path vs `smtp.mailfrom` | An internally inconsistent envelope — a sign one field was rewritten or forged. | An intermediate hop may rewrite one field while an earlier AR retains the original. |

All three are **low** severity consistency hints, never verdicts. The comparison
is exact (a subdomain of From counts as a mismatch), and `smtp.mailfrom` is read
from every `Authentication-Results` header — including untrusted, forge-able ones
— so the caller must correlate these with the authentication results
(`untrustedAuthservIdRule` flags forge-able sources) and its own policy.

Missing envelope context stays silent: a missing `From`, a missing `Return-Path`,
a null reverse-path (`<>`, a bounce/DSN — surfaced via the
`returnPathNullReversePath` metric), or a missing/null `smtp.mailfrom` leaves the
relevant match metric `null` and emits no signal rather than a noisy one.

### DKIM signing-domain consistency signal

`dkimDomainMismatchRule` compares the DKIM signing domain (`header.d`) against the
`From` domain — the DKIM-alignment view of the same check DMARC performs.

| Signal | Compares | Attacker pattern | Common false positive |
|---|---|---|---|
| `dkim.domainMismatch` | DKIM `header.d` vs From | A recognizable brand in From, but the message is validly DKIM-signed by an attacker-controlled domain — authenticated mail that the visible sender's domain never vouched for. | ESPs and platforms legitimately sign brand mail under their own domain or a subdomain, and mail may carry several signatures (author plus forwarder/list). |

**Only passing signatures count.** The `dkimDomains` metric is populated solely
from DKIM results that returned `pass`; a `fail`/`temperror`/`permerror`/`neutral`/`none`
signature authenticates nothing, so its `header.d` never enters the comparison.
This is deliberate: a broken signature claiming `header.d = ` the From domain must
not read as alignment, and a broken signature claiming an attacker domain must not
manufacture a mismatch. `authMethodFailureRule` surfaces the failure itself.

Like the envelope-sender hints, this is a **low**-severity consistency hint, never
a verdict. The comparison is exact (a subdomain of From counts as a mismatch), a
single divergent signing domain among several is enough to flag (the
`mismatchedDomains` subset is reported), and `header.d` is read from every
`Authentication-Results` header — including untrusted, forge-able ones, which
`untrustedAuthservIdRule` flags separately. Missing context stays silent: a missing
`From`, no passing DKIM result, or an unparseable `header.d` leaves
`dkimDomainMatchesFromDomain` `null` and emits no signal.

### DMARC header.from consistency signal

`dmarcHeaderFromMismatchRule` compares the DMARC `header.from` domain — the
receiver's own parse of the visible `From` domain, the domain a DMARC `pass`
actually vouches for — against the `From` domain this library parses.

| Signal | Compares | Attacker pattern | Common false positive |
|---|---|---|---|
| `dmarc.headerFromMismatch` | DMARC `header.from` vs From | A crafted, ambiguous From header (e.g. two From headers or encoded-word tricks) is resolved to one domain by the verifier and another by the recipient's client, so a DMARC `pass` badge ends up displayed against a From the user never sees. | Exact comparison with no PSL/org-domain logic, so a benign subdomain difference, or a verifier that records the organizational domain, also reads as a mismatch. |

**Pass and trust gated.** The `dmarcHeaderFromDomains` metric is populated only
from DMARC results that returned `pass` *and* only from **trusted**
`Authentication-Results` headers. Two gates apply because, unlike a DKIM
signature, `header.from` is not cryptographic: a non-`pass` DMARC vouches for
nothing (and `authMethodFailureRule` already surfaces the failure), while a
forge-able untrusted header's `header.from` is just the attacker's own assertion,
so neither must read as a verified view of the From domain. This is what keeps a
failed, missing, malformed, or untrusted DMARC context from producing a noisy
consistency signal.

Like the other consistency hints this is **low** severity, never a verdict. A
single trusted+passing `header.from` that differs from From is enough to flag
(the `mismatchedDomains` subset is reported). Missing context stays silent: a
missing `From`, no trusted+passing DMARC result, or an unparseable `header.from`
leaves `dmarcHeaderFromMatchesFromDomain` `null` and emits no signal.

### Display name brand domain mismatch signal

`displayNameBrandDomainMismatchRule` compares the brand a `From` **display name**
reads as against the `From` domain, using the
[brand-inference metric](#display-name-brand-inference).

| Signal | Compares | Attacker pattern | Common false positive |
|---|---|---|---|
| `displayName.brandDomainMismatch` | Inferred display-name brand vs From domain | A trusted brand in the display name (`PayPal`, `HERMÈS`, letter-spaced `P a y P a l`) while sending from a domain that brand does not own — the reader sees the brand the client surfaces, not the real address. | A legitimate sender using a brand in its display name while sending from a partner/regional domain the caller's catalog does not list for that brand. |

**Opt-in and gated.** This rule is silent unless a caller supplies a brand catalog
(`MetricsDependencies.brandCatalog`) — the core bundles no brand list — so by
default `brandInference` is absent and no signal is emitted. When opted in, it
fires at **medium** severity only on a *confident* brand match (`brandDomainMatchesFromDomain
=== false`): exact token equality, or high Jaro-Winkler corroborated by Jaccard, on
a pure-Latin display name. Non-Latin names, mixed-script homoglyphs, weak matches,
and a missing From domain all leave the fact `null` and emit nothing. The signal
describes the sender's own message and never asserts anything about the
impersonated brand's real infrastructure.

### Composite (Layer 4) signals

The base rules above each read a single metric. A **composite rule** reads both
the metrics and the base signals already produced for the message, so it can
combine several lower-layer outcomes into one higher-confidence observation — the
reusable port of the Thunderbird add-on's composite detection layer, with one
boundary change: where the add-on mapped a composite match onto a Thunderbird
action, a composite here emits only a structured signal (category `composite`)
whose `data.contributingSignals` names the lower-layer signal keys that justified
it. Thresholds and actions stay with the caller.

Composites are an **opt-in layer**. `analyzeMessage` emits only base signals
unless a caller passes composite rules as the optional fourth argument; the
default output is unchanged:

```ts
import { analyzeMessage, defaultRules, defaultCompositeRules } from "mail-auth-signal";

// Base layer only (default):
const base = analyzeMessage(input);
// Base layer plus the Layer 4 composites:
const full = analyzeMessage(input, defaultRules, undefined, defaultCompositeRules);
```

`runCompositeRules(metrics, baseSignals, options?, compositeRules?)` runs them over
already-extracted metrics and the base signals those metrics produced (pass base
signals computed under the same `options`, exactly as `analyzeMessage` does).

| Signal | Severity | Fires when | Attacker model / guard |
|---|---|---|---|
| `composite.unauthenticatedFromSpoof` | high | A trusted header evaluated the message, **no** aligned authentication vouches for the From domain (`anyAuthAligned === false`), **and** at least one base consistency signal disagrees with From. | Direct domain impersonation. Combines "From is unauthenticated" with "an identifier disagrees". Stays silent on unevaluable messages (no trusted header) and honest auth misconfigurations (no identifier mismatch). The only way to suppress it is to actually authenticate the From domain. |
| `composite.publicMailboxSpoofingCandidate` | medium | The visible From is a known **public mailbox provider** domain (`senderIdentity.fromDomainIsPublicMailboxProvider === true`), a trusted header evaluated the message, and **no** aligned authentication vouches for it (`anyAuthAligned === false`, no aligned trusted DMARC pass). | Borrowing a consumer-mailbox brand (`From: someone@outlook.com`) while sending from other infrastructure — the logged From `outlook.com` / Return-Path `icloud.com` / Message-ID `yahoo.co.jp` shape. These providers publish enforcing DMARC, so genuine mail always aligns; missing alignment is the tell *on its own*, without needing a second divergent identifier. A *candidate*, so medium — a forwarder that breaks both SPF and DKIM lands here too. Cannot be suppressed without real aligned auth, nor manufactured against honest mail (only trusted, passing results count). |
| `composite.authenticatedDisplayNameSpoof` | medium | The message authenticates and aligns for its From (`anyAuthAligned === true`) **and** the display name addresses a different domain (`displayName.containsEmail && embeddedDomainMatchesFromDomain === false`). | Authenticated lookalike with a borrowed display name (`From: "security@paypal.com" <alerts@authed.example>`) — the case a pure auth/Junk filter waves through. The signal points at the attacker's own message, never the impersonated brand. |
| `composite.unsecuredDeepSubdomainCandidate` | low | The visible From sits on a deep subdomain (`fromDomainParts.subdomainDepth >= 2`, PSL-derived), a trusted verifier reported `dmarc=none` for that From's organizational domain, and **no** aligned authentication vouches for it (`anyAuthAligned === false`, no aligned/org trusted SPF/DKIM or DMARC pass). | Disposable deep-subdomain impersonation (`From: …@sivakeso.support.sn5799.com`) — a readable, brand-ish hostname stacked under a cheap registrable domain with no enforced DMARC policy, where per-label randomness heuristics do not fire. `subdomainDepth` is populated by the built-in PSL resolver; pass `getRegistrableDomain: () => null` to disable. Cannot be suppressed without real aligned auth for the visible From's organizational domain, nor manufactured against honest mail. |
| `composite.deepRandomFromSubdomain` | low | The visible From sits on a deep subdomain (`fromDomainParts.subdomainDepth >= 2`, PSL-derived), at least one **subdomain** label reads as random (`computeRandomLookingCandidate`), and **no** aligned authentication vouches for it. | Disposable *random* deep-subdomain impersonation (`From: …@a8f3qz.k2pls.cheapdomain.test`) — the random-label twin of `unsecuredDeepSubdomainCandidate`. Random labels and deep ESP structure are each individually noisy; the combination on the visible From with no aligned auth is the tell. Cannot be suppressed without real aligned auth for the From's organizational domain; needs a PSL resolver for the depth. |
| `composite.brandDivergencePhishing` | high | The From display name reads as a known **brand** the From domain does not belong to (`senderIdentity.brandInference.brandDomainMatchesFromDomain === false`). Reports the From's authentication posture in `data.fromAuthenticated`. | Borrowed-brand phishing (`From: "PayPal" <security@evil.test>`), the Layer-4 elevation of the base `displayName.brandDomainMismatch`. Requires an opt-in `brandCatalog`; the core bundles no brand list. Describes the sender's own message, never the impersonated brand's infrastructure, so it cannot frame a third party. |
| `composite.ownDomainSpoofCandidate` | high | The visible From is one of the caller's **own account domains** (supplied via `options.context.accountDomains`) and **no** aligned authentication vouches for it. | Self-domain spoofing (`From: it-helpdesk@yourcompany.example`) impersonating an internal colleague/system. Mail genuinely from your own domain authenticates, so an unauthenticated own-domain From is a sharp tell on its own. Opt-in via caller context; cannot be suppressed without real aligned auth for the own domain. |
| `composite.dkimFailWithAlignedPass` | info | A trusted `dkim=fail` co-occurs with an aligned, trusted, passing DKIM signature for the From (`anyAlignedDkimPass === true`). | **Mitigation.** A benign broken/extra signature (e.g. a list/forwarder signature failing alongside the author domain's valid one), so the DKIM failure is not an authentication gap. Gates on a *real* aligned DKIM pass only the From domain can produce, so it cannot mark a forged failure benign. |
| `composite.dkimAlignedLexicalMitigation` | info | The From local part or domain reads as random (`computeRandomLookingCandidate`) **but** an aligned, trusted, passing DKIM signature vouches for the From (`anyAlignedDkimPass === true`). | **Mitigation.** A positive counter-signal for "this random-looking identity is cryptographically the From domain" (`a8f3qz9k@example.com` with aligned DKIM), letting a caller avoid penalizing authenticated automated mail. Not attacker-triggerable — only the real From domain can produce the aligned signature. |
| `composite.alignedAuthenticationConfirmed` | info | A trusted header gives aligned, passing authentication for the From **and** there is no base `auth-failure` or `consistency` signal and no misleading display name. | **False-positive mitigation.** The single positive marker a caller needs to confidently lower a score. It gates on *real* aligned authentication for the visible From — which a spoofer of another domain cannot produce — and withholds on any conflicting signal, so it cannot be used to launder a forgery. |

`composite.alignedAuthenticationConfirmed` is the only rule in the package that
*reduces* suspicion, so its guard is deliberately strict and documented inline in
`src/rules/composite/alignedAuthenticationConfirmed.ts`: it is the absence of risk
(severity `info`), never an instruction to deliver or allow anything.

## Authentication & alignment metrics

`MessageMetrics.authentication` (`AuthenticationAlignment`) is a consolidated,
serializable view of the SPF/DKIM/DMARC outcomes, split into the two layers the
Thunderbird add-on modeled. It is a derived projection of
`authenticationResults` — no extra parsing, no signals — so callers that want the
authentication picture without walking each header can read it directly.

### Layer 1 — raw results (faithful, never gated)

| Field | Meaning |
|---|---|
| `trustedHeaderCount` / `untrustedHeaderCount` | How many `Authentication-Results` headers came from a trusted vs untrusted authserv-id. |
| `dmarcResults[]` | Each DMARC result: `{ result, headerFrom, trusted }`. |
| `spfResults[]` | Each SPF result: `{ result, smtpMailfrom, trusted }`. |
| `dkimResults[]` | Each DKIM result: `{ result, headerD, headerI, trusted }` (`headerI` is the normalized `header.i` AUID domain). |

Every result is reported in encounter order and tagged with the trust of its
source header. Nothing is filtered: a `fail`, `softfail`, `none`, or untrusted
result is still present so a caller sees the complete claim set.

### Layer 2 — alignment & summary flags (trusted + passing only)

| Field | Meaning |
|---|---|
| `spfAlignedWithFrom` | Whether every trusted, passing SPF `smtp.mailfrom` matches From. `null` when none to compare. |
| `dkimAlignedWithFrom` | Whether every trusted, passing DKIM `header.d` matches From. `null` when none to compare. |
| `anyAlignedSpfPass` | At least one trusted, passing, From-aligned SPF result. |
| `anyAlignedDkimPass` | At least one trusted, passing, From-aligned DKIM signature (DMARC's DKIM leg passes on any aligned signature). |
| `dmarcPass` | At least one trusted DMARC `pass`. |
| `anyAuthAligned` | `anyAlignedSpfPass || anyAlignedDkimPass` — the DMARC-style summary that From is backed by an aligned authenticated identifier. |

**Why Layer 2 is gated.** The summary flags assert "this message is
authenticated and aligned with the visible From," which is exactly what an
attacker would want to forge. So they count a result only when it is **passing**
(a `fail`/`softfail`/`none` authenticates nothing) and comes from a **trusted**
header (an untrusted `Authentication-Results` header can be stamped by anyone
upstream). Without both gates, a self-applied `spf=pass` / `dkim=pass` would let
the flags vouch for a spoof. The raw Layer 1 results stay ungated so that
forge-able claim is still visible — it just does not move the summary. Alignment
is measured against `fromDomain` with exact comparison (no PSL/org-domain logic),
matching the consistency metrics, so a subdomain of From reads as unaligned.

The two views differ deliberately: `*AlignedWithFrom` is an all-match verdict
(every trusted+passing identifier agrees), while `anyAligned*Pass` is satisfied
by a single aligned identifier — so a message with one aligned author-domain
signature plus a third-party signer has `anyAlignedDkimPass = true` but
`dkimAlignedWithFrom = false`.

### Layer 2b — organizational (PSL-aware) alignment

`authentication.organizational` (`OrganizationalAlignment`) is the same trusted +
passing alignment view computed against **registrable (organizational) domains**
rather than exact domains — the form of alignment DMARC actually evaluates under
relaxed mode, and the practical default for deciding whether the From is backed by
authentication. A `From` at `news.example.co.jp` counts as aligned with an
authenticated `example.co.jp` (or `bounce.example.co.jp`) identifier, where the
exact-domain flags above would read that subdomain difference as unaligned. The
same trust + pass gating applies, so a forged or non-passing result can never make
a spoof read as organizationally aligned.

| Field | Meaning |
|---|---|
| `resolverAvailable` | Whether a registrable-domain resolver was supplied. `false` means these fields fell back to exact-domain comparison (no PSL applied). |
| `spfAligned` | Whether every trusted, passing SPF `smtp.mailfrom` shares a registrable domain with From. `null` when none to compare. |
| `dkimAligned` | Whether every trusted, passing DKIM `header.d` shares a registrable domain with From. `null` when none to compare. |
| `anySpfAligned` | At least one trusted, passing SPF result organizationally aligned with From (DMARC's relaxed SPF leg). |
| `anyDkimAligned` | At least one trusted, passing DKIM signature organizationally aligned with From (DMARC's relaxed DKIM leg). |
| `anyAuthAligned` | `anySpfAligned \|\| anyDkimAligned` — the organizational DMARC-style summary; prefer this over the exact-domain `anyAuthAligned`. |
| `unalignedPassingSpfDomains` / `unalignedPassingDkimDomains` | The trusted, passing SPF/DKIM domains that do **not** share a registrable domain with From (deduplicated). Surfaces "authenticated, but for another organization". |

Computing the registrable boundary correctly (e.g. `co.jp` vs `com`) needs Public
Suffix List data, which this package intentionally does not bundle (license
boundary; see `NOTICE` / `AGENTS.md`). The boundary is taken from the
caller-supplied `MetricsDependencies.getRegistrableDomain` resolver, threaded
through `analyzeMessage` / `extractMetrics` / `runRules` / `runCompositeRules`.
When no resolver is supplied these fields degrade cleanly to exact-domain
comparison (a domain is its own organizational domain) and `resolverAvailable` is
`false`, so they stay populated and usable — just no broader than the exact-domain
flags. The exact-domain flags remain available alongside the organizational view.

## Sender-identity metrics

`MessageMetrics.senderIdentity` (`SenderIdentityMetrics`) is a serializable view
of the *shape* of the sender's identity, derived from the `From` mailbox and the
`Message-ID` domain. Like every metric here it carries **no scoring and no
verdict** — it exposes facts a caller can combine with its own thresholds.

| Field | Meaning |
|---|---|
| `displayName` | Structure of the `From` display name (see below). |
| `localPart` | The `From` address local part, or `null` when From has no parseable address. |
| `localPartLexical` / `fromDomainLexical` | Lexical profile of the local part / From domain: `{ length, digitCount, hyphenCount, hasNonAscii }` (counts are codepoint-based). `null` when the part is absent. |
| `fromDomainParts` / `messageIdDomainParts` | Label decomposition of the From / Message-ID domain (see below). `null` when absent. |
| `messageIdRegistrableDomainMatchesFromDomain` | Whether Message-ID and From share a registrable domain. Requires a resolver (see below); `null` otherwise. |
| `fromDomainIsPublicMailboxProvider` | Whether the From domain is a known public mailbox provider (gmail.com, outlook.com, …) from the built-in catalog. `false` when absent or not in the catalog (see below). |
| `publicMailboxProviderId` | The matched provider's stable catalog id (`"google"`, `"microsoft"`, …), or `null`. |
| `brandInference` | Display-name brand / domain-mismatch inference (see below). **Present only** when a caller-supplied brand catalog is provided via `MetricsDependencies.brandCatalog`; omitted entirely otherwise. |

`displayName` (`DisplayNameMetrics`) reports `present`, the unquoted `text`, its
codepoint `length`, `hasNonAscii`, and — the attacker-relevant part — whether the
display name itself contains an email address (`containsEmail`), the
`embeddedDomains` found in it, and `embeddedDomainMatchesFromDomain`. The last is
`false` for the classic *address-in-display-name* spoof, e.g.
`From: "service@paypal.com" <attacker@evil.test>`, where a client may surface only
the brand address while the real sender is elsewhere. It is `null` when there is
nothing to compare, so a plain display name never reads as a mismatch.

`displayName` also exposes a whitespace-normalized view for brand-style matching
that must see through *letter-spacing camouflage* — a brand name spelled out with
spaces between its letters, e.g.
`From: D d a i i c h i L i f e I n s u r a n c e <noreply@evil.test>`, which a
naive brand-list match against the raw `text` misses entirely.
`normalized.compactedWhitespace` is the display name with every run of intra-name
whitespace removed (`DdaiichiLifeInsurance`) — a lexical token to compare against
your own brand list, never an address. `metrics.whitespaceCompactedChanged` says
whether compaction changed the token (true whenever any whitespace was removed, so
a normal multi-word name compacts too). `signals.spacedDisplayNameCamouflageCandidate`
is the discriminating hint: true only when the display name is dominated by
single-letter tokens (≥ 3 whitespace-separated tokens, ≥ 3 single Unicode letters,
and a single-letter majority), so an ordinary name like `Daiichi Life Insurance`
or one carrying an initial (`John A Smith`, `J P Morgan`) is **not** flagged. As
always, this is a signal, not a verdict — the core assigns no score.

`fromDomainParts` / `messageIdDomainParts` (`DomainParts`) split a domain into its
dot-separated `labels` (with `labelCount` and `topLabel`). The
`registrableDomain`, `subdomainDepth`, and
`messageIdRegistrableDomainMatchesFromDomain` fields are populated by the
built-in PSL-backed resolver described below.

### Registrable-domain metrics and PSL resolver

Deciding where the registrable (organizational) domain boundary falls — e.g.
`example.co.uk` vs `example.com` — requires
[Public Suffix List](https://publicsuffix.org/) data. This package bundles
[tldts](https://github.com/remusao/tldts) as a runtime dependency and uses it
by default, so registrable-domain metrics are populated without any caller setup:

```ts
import { analyzeMessage } from "mail-auth-signal";

const result = analyzeMessage(input);
// PSL-backed metrics are populated by default:
result.metrics.senderIdentity.fromDomainParts?.registrableDomain;
result.metrics.senderIdentity.fromDomainParts?.subdomainDepth;
result.metrics.senderIdentity.messageIdRegistrableDomainMatchesFromDomain;
```

The built-in resolver uses ICANN public suffixes only (`allowPrivateDomains:
false`), so private PSL entries like `s3.amazonaws.com` are not treated as
additional suffixes. Unknown TLDs follow tldts's default fallback: the TLD
itself acts as the public suffix.

To use a different PSL snapshot, private-registry entries, or a pinned dataset,
supply a custom resolver as a non-serializable dependency:

```ts
import { analyzeMessage } from "mail-auth-signal";

const result = analyzeMessage(input, undefined, {
  getRegistrableDomain: (domain) => myPsl.getDomain(domain) ?? null,
});
```

To opt out of PSL resolution entirely and keep the registrable-domain fields
`null` (the behaviour before v0.5.0), pass an explicit no-op:

```ts
analyzeMessage(input, undefined, { getRegistrableDomain: () => null });
```

The resolver should return an already-normalized (lower-cased) registrable
domain, or `null` when it cannot resolve one. These fields complement the
exact-match consistency metrics: for example, `messageIdRegistrableDomainMatchesFromDomain`
lets a caller treat an ESP subdomain (`mailer.example.com` vs `example.com`) as
same-organization, where the exact `messageIdDomainMatchesFromDomain` reads as a
mismatch.

The same registrable complement is provided for every identity domain compared
against `From`, each paired with its exact-match counterpart on `MessageMetrics`:

| Exact match | Registrable-domain complement |
|---|---|
| `senderDomainMatchesFromDomain` | `senderDomainRegistrableMatchesFromDomain` |
| `replyToDomainMatchesFromDomain` | `replyToDomainRegistrableMatchesFromDomain` |
| `returnPathDomainMatchesFromDomain` | `returnPathDomainRegistrableMatchesFromDomain` |
| `messageIdDomainMatchesFromDomain` | `senderIdentity.messageIdRegistrableDomainMatchesFromDomain` |

Each registrable comparison is `null` when either side is absent or has no
registrable form (and, for the Reply-To mailbox-list, when any member is
unresolvable), so an unresolvable domain stays silent rather than guessing
same-organization. The `registrableDomainsMatch` (single domain) and
`allRegistrableDomainsMatch` (mailbox-list) helpers are exported so callers can
run the same comparison over their own domains. License attribution for tldts and
the Public Suffix List data is in `NOTICE`.

### Public mailbox provider catalog

Spoofing often puts a major **public mailbox provider** domain in the visible
From (`outlook.com`, `gmail.com`, `icloud.com`, …) while the real infrastructure
and authentication point elsewhere. Because these providers publish enforcing
DMARC and send only through their own infrastructure, genuine mail from them
always authenticates and aligns — so a public-mailbox From with *no* aligned
authentication is a meaningful spoof candidate. The core bundles a small, explicit
catalog so consumers do not have to hand-maintain a Gmail/Outlook/Yahoo/iCloud
list just to detect this class.

`senderIdentity.fromDomainIsPublicMailboxProvider` and `publicMailboxProviderId`
expose catalog membership of the From domain; the opt-in
[`composite.publicMailboxSpoofingCandidate`](#composite-layer-4-signals)
signal pairs that membership with missing alignment. Membership is matched against the From **registrable** domain via the built-in
PSL resolver (so `mail.gmail.com` still resolves to `gmail.com`), or a custom
resolver if supplied.

The catalog is *bundled data the core owns* — deliberately small and hand-authored,
not an imported PSL/brand list, so it crosses no external-data license boundary
(`AGENTS.md` / `NOTICE`). It is also exported and overridable:

```ts
import {
  analyzeMessage,
  defaultPublicMailboxProviders,
  lookupPublicMailboxProvider,
} from "mail-auth-signal";

lookupPublicMailboxProvider("outlook.com"); // "microsoft"
lookupPublicMailboxProvider("example.com"); // null

// Extend (or fully replace) the catalog via MetricsDependencies:
analyzeMessage(input, undefined, {
  publicMailboxProviders: [
    ...defaultPublicMailboxProviders,
    { id: "fastmail", domains: ["fastmail.com", "fastmail.fm"] },
  ],
});
```

Membership is a **fact, not a verdict** — a public-mailbox From is perfectly
normal. The core forms no opinion; only the candidate composite combines it with
authentication state, and even that stays an observation the caller weighs.

### Display-name brand inference

A common spoof sets the `From` display name to a trusted **brand** — `PayPal`,
`HERMÈS`, or a letter-spaced `P a y P a l` — while sending from a domain that
brand does not own. Mail clients surface the display name far more prominently
than the address, so the reader sees the brand and trusts it.

`computeDisplayNameBrandInference` (surfaced on `senderIdentity.brandInference`
when opted in) folds Latin diacritics, normalizes the display name to a brand
token, matches it against a **caller-supplied** brand catalog using exact,
Jaro-Winkler, and Jaccard similarity, and reports whether the `From` domain
actually belongs to the matched brand:

```ts
import { analyzeMessage } from "mail-auth-signal";
import type { BrandCatalogEntry } from "mail-auth-signal";

// Caller-owned data — the core bundles NO brand list (see "Data boundary" below).
const brandCatalog: BrandCatalogEntry[] = [
  { brand: "paypal", domains: ["paypal.com"] },
  { brand: "hermes", domains: ["hermes.com"] },
];

const result = analyzeMessage(input, undefined, { brandCatalog });
result.metrics.senderIdentity.brandInference;
// e.g. for From: "HERMÈS" <noreply@evil.test> →
// {
//   applicable: true, notApplicableReason: null,
//   brandToken: "hermes", diacriticsFolded: true, brandLike: true,
//   match: { brand: "hermes", domains: ["hermes.com"], exact: true,
//            jaroWinkler: 1, jaccard: 1, similarity: 1 },
//   inferredBrandDomains: ["hermes.com"],
//   fromRegistrableDomain: "evil.test",
//   brandDomainMatchesFromDomain: false   // ← the impersonation tell
// }
```

| Field | Meaning |
|---|---|
| `applicable` | Whether a brand/From comparison was performed. `false` for every guardrail below. |
| `notApplicableReason` | Why no comparison ran, or `null` when applicable: `"no-display-name"`, `"non-latin-script"`, `"mixed-script"`, `"insufficient-signal"`, `"missing-from-domain"`, `"empty-catalog"`. |
| `brandToken` | The normalized display-name token used (diacritics folded, lower-cased, non-alphanumerics stripped: `HERMÈS` → `hermes`, `P a y P a l` → `paypal`). `null` only when no display name. |
| `diacriticsFolded` | Whether Latin diacritic folding changed the name (the #59 `HERMÈS` → `HERMES` fold). |
| `brandLike` | Whether the token is shaped like a brand at all (long enough, mostly letters) — a loose structural gate; the catalog match establishes the brand. |
| `match` | The confidently matched catalog brand with its similarity scores (`BrandMatch`), or `null` when nothing matched confidently. |
| `inferredBrandDomains` | The matched brand's registrable domains, or `[]` when no confident match. |
| `fromRegistrableDomain` | The From registrable domain used for the comparison, or `null` if unresolved. |
| `brandDomainMatchesFromDomain` | `true` when From legitimately belongs to the matched brand, `false` on the impersonation shape, `null` when there was no confident match. |

The opt-in [`displayName.brandDomainMismatch`](#display-name-brand-domain-mismatch-signal)
rule turns `brandDomainMatchesFromDomain === false` into a `medium`-severity
`consistency` signal.

**Guardrails — homoglyph and script safety.** Brand inference operates **only**
on a pure-Latin display name. A name whose letters are entirely non-Latin
(`山本太郎`) reports `non-latin-script`, and a **mixed-script** name — the
homoglyph shape, e.g. `pаypal` with a Cyrillic `а` — reports `mixed-script` and is
**refused outright**, because folding it to a Latin token would *manufacture* a
brand match the raw text never had. (The non-ASCII codepoints still surface via
`displayName.hasNonAscii` and the lexical metrics.) A match also requires a
confident similarity — exact token equality, or a high Jaro-Winkler score
corroborated by Jaccard — so a name that merely resembles a brand fragment cannot
be turned into a false accusation against a benign sender. Because the signal
always points at the sender's *own* message, it cannot be used to frame a third
party.

**Data boundary.** The reusable inference logic is **library-owned**, but the
brand catalog itself is **caller-supplied data** — brand/top-domain lists are
exactly the external data this package keeps out (see `AGENTS.md` / `NOTICE`), so
the core bundles none and `brandInference` is omitted entirely unless a catalog is
passed. `BrandCatalogEntry` is a first-class typed API (`{ brand, domains }`), and
`foldLatinDiacritics` / `normalizeBrandToken` / `computeDisplayNameBrandInference`
are exported so a consumer never re-implements the normalization.

## Lexical heuristics

`computeLexicalHeuristics(token)` (`LexicalHeuristics`) is a richer companion to
the lightweight `localPartLexical` / `fromDomainLexical` counts. Where those
report raw structure (`length`, `digitCount`, …), these report *shape* — how
random, pronounceable, or repetitive a token is — ported from the Thunderbird
Auth Results Filter add-on so a downstream add-on can retire its local copy. It is
an exported helper a caller applies to whatever token it wants to measure (a local
part, a domain label, a subject word); it is **not** baked into
`analyzeMessage`'s output, keeping the heuristic and its thresholds in the
caller's hands.

```ts
import { computeLexicalHeuristics } from "mail-auth-signal";

computeLexicalHeuristics("x9z8q2w1");
// { shannonEntropy, normalizedEntropy, vowelRatio, digitRatio, hyphenRatio,
//   maxHexRun, maxConsonantRun, maxRepeatedCharRun, uniqueCharRatio,
//   letterDigitTransitions, alphaLength, vowelCount, vowelRatioAlphaOnly,
//   hyphenCount, uniqueCharCount, letterDigitTransitionCount, hasLongHexLikeRun }
```

| Field | Meaning |
|---|---|
| `shannonEntropy` | Shannon entropy in bits over the codepoint-frequency distribution. `0` for an empty or single-character token. Higher = a more uniform, less predictable character mix. |
| `normalizedEntropy` | `shannonEntropy` divided by the maximum for this length (`log2(length)`), giving a length-independent `[0, 1]` value. `0` when `length < 2`. |
| `vowelRatio` | ASCII vowels (excluding `y`) ÷ ASCII letters, `[0, 1]`. `0` when there are no ASCII letters. |
| `digitRatio` | ASCII digits ÷ length, `[0, 1]`. `0` when empty. The length-normalized form of `LexicalStats.digitCount`. |
| `hyphenRatio` | ASCII hyphens ÷ length, `[0, 1]`. `0` when empty. Heavy hyphenation is a common shape of padded look-alike labels. |
| `maxHexRun` | Longest run of consecutive ASCII hex characters (`0-9a-fA-F`). A long run hints at a hash / GUID fragment rather than a word. `0` when empty. |
| `maxConsonantRun` | Longest run of consecutive ASCII consonants. |
| `maxRepeatedCharRun` | Longest run of the same codepoint repeated (`3` for `"aaab"`). `0` when empty, else ≥ 1. |
| `uniqueCharRatio` | Distinct codepoints ÷ length, `[0, 1]`. `0` when empty. |
| `letterDigitTransitions` | Adjacent pairs that switch between an ASCII letter and an ASCII digit, either direction (`2` for `"ab12ab"`). |
| `alphaLength` | Number of ASCII letters — the denominator behind the alpha-only ratios. |
| `vowelCount` | ASCII vowels counting `y` (`a e i o u y`, case-insensitive). The y-inclusive companion to `vowelRatio`'s numerator. |
| `vowelRatioAlphaOnly` | `vowelCount` (y-inclusive) ÷ `alphaLength`, `[0, 1]`. `0` when there are no ASCII letters. |
| `hyphenCount` | Raw count of ASCII hyphens behind `hyphenRatio` (mirrors `LexicalStats.hyphenCount`). |
| `uniqueCharCount` | Raw count of distinct codepoints behind `uniqueCharRatio`. |
| `letterDigitTransitionCount` | Like `letterDigitTransitions` but **symbol-skipping**: counts a letter↔digit change across intervening separators, so `"ab-12"` counts `1`. |
| `hasLongHexLikeRun` | Whether a run of ≥ 6 consecutive hex characters **contains a digit** — the hash/GUID-fragment shape (the add-on floor; a short fragment like `"abc12"` stays `false`). Stricter than `maxHexRun`: a real word like `"deadbeef"` makes `maxHexRun` `8` but `hasLongHexLikeRun` `false`. |

### Random-looking token candidate

`computeRandomLookingCandidate(token, options?)` rolls the metrics above into a single
boolean flag, ported from the add-on's random-looking local-part / domain-label checks
so a downstream add-on can retire its local copy. A token is a candidate when it is at
least 6 codepoints long **and** matches any one machine-generated shape: a high digit
ratio, frequent letter/digit alternation, a long hex run, a low vowel ratio paired with
a long consonant run (e.g. `mpqxyt`), or the add-on's letters-only uppercase rule (an
all-uppercase ASCII-letter token such as `CAQLEV`).

```ts
import { computeRandomLookingCandidate } from "mail-auth-signal";

computeRandomLookingCandidate("x9z8q2w1");  // true  — alternation + digit ratio
computeRandomLookingCandidate("deadbeef");  // true  — eight-char hex run
computeRandomLookingCandidate("mpqxyt");    // true  — all-consonant, no vowels
computeRandomLookingCandidate("CAQLEV");    // true  — letters-only uppercase
computeRandomLookingCandidate("switchbot"); // false — pronounceable brand word
computeRandomLookingCandidate("crowdworks");// false — short consonant run, no digits
```

The thresholds are deliberately tuned so known false-positive brand/word labels from
the add-on's history (`switchbot`, `crowdworks`, and similar low-vowel but
pronounceable words) read `false`, while spam-style random labels read `true`. Like
every helper here it is a **candidate flag, not a verdict** — the caller decides
whether a random-looking token matters in its context, since legitimate DKIM
selectors, hashes, and ESP labels also look random.

**One add-on-positive class needs a corpus.** A structurally word-like gibberish label
such as `wlikqkgi` (vowel ratio `0.25`, longest consonant run `4`) is *indistinguishable
by shape alone* from a real word such as `switchbot` (vowel ratio `0.22`, longest
consonant run `4`): no codepoint-only threshold can flag one without the other.
Separating them needs a language-frequency corpus, which this package deliberately does
not bundle (the data/license boundary below). That class therefore stays **caller-owned**:
pass a naturalness model via `options.isNatural` and an all-letter token the model rejects
is also flagged, letting a caller holding its own bigram/trigram corpus reach full add-on
parity. Omitting it keeps the helper purely structural, and such tokens read `false`.

```ts
const isNatural = (token: string) => myBigramModel.scoresAsWord(token);
computeRandomLookingCandidate("wlikqkgi", { isNatural });  // true  — model rejects it
computeRandomLookingCandidate("switchbot", { isNatural }); // false — model accepts it
```

**Use and limitations.** These are weak, policy-neutral hints, not verdicts — a
high-entropy or vowel-poor token is only suspicious in a context the caller
supplies (legitimate DKIM selectors, hashes, and ESP subdomains all look
"random"). Counts and codepoints are codepoint-based, but letter/vowel/consonant
classification is **ASCII-only**: a non-ASCII codepoint still counts toward
length, entropy, the unique ratio, and repeated runs, but is not treated as a
letter (deciding vowel-ness across scripts needs Unicode tables this core does not
bundle). Floating-point fields are rounded to 4 decimals so fixtures and
cross-language ports compare exactly.

**No bundled data.** Every value is computed from the token alone — no word list,
brand dictionary, language corpus, or n-gram table. Bigram/trigram "naturalness"
was considered and **deliberately left caller-owned**: a meaningful naturalness score
needs a language-frequency dataset, and bundling one would cross the data/license
boundary this package keeps clear (see `AGENTS.md` / `NOTICE`). It is the one Layer 3
heuristic the library does not compute itself; instead `computeRandomLookingCandidate`
accepts the caller's model through `options.isNatural` (above) so a caller with its own
licensed corpus reaches full add-on parity without the library shipping the corpus.

## Jaro-Winkler string similarity

`computeJaro(a, b)` and `computeJaroWinkler(a, b, prefixScalingFactor?)` are
exported helpers that compute string similarity, ported from the Thunderbird Auth
Results Filter add-on so downstream callers can retire their local copies. Both
return a value in `[0, 1]` (1 = identical, 0 = nothing in common), rounded to 4
decimal places for stable fixture comparison.

```ts
import { computeJaro, computeJaroWinkler } from "mail-auth-signal";

computeJaro("MARTHA", "MARHTA");        // 0.9444
computeJaroWinkler("MARTHA", "MARHTA"); // 0.9611 — prefix bonus for shared "MAR"
computeJaroWinkler("a", "b", 0);        // same as computeJaro (no prefix bonus)
```

| Function | Description |
|---|---|
| `computeJaro(a, b)` | Jaro similarity. Counts characters that match within a window of `⌊max(|a|, |b|) / 2⌋ − 1` positions and penalises transpositions. |
| `computeJaroWinkler(a, b, p?)` | Extends Jaro with a prefix bonus: up to 4 shared leading characters increase the score by `p × prefixLength × (1 − jaro)`. Default `p = 0.1`; keep `p ≤ 0.25` to stay in `[0, 1]`. |
| `computeJaccard(a, b)` | Bigram Jaccard similarity: `\|A ∩ B\| / \|A ∪ B\|` over each string's set of adjacent-codepoint bigrams. Rewards shared substrings irrespective of position (and is order-sensitive: `"abc"` vs `"cba"` scores `0`), complementing Jaro-Winkler's prefix weighting. |

```ts
import { computeJaccard } from "mail-auth-signal";

computeJaccard("paypal", "paypai"); // shared "pa"/"ay"/"yp" bigrams
```

**Policy-neutral.** These helpers form no opinion on what similarity score is
"suspicious" — that threshold belongs to the caller. All three functions are
codepoint-based (a multi-byte Unicode character counts as one unit) and consult no
external word list, brand dictionary, or corpus. The display-name
[brand inference](#display-name-brand-inference) corroborates one with the other:
a confident brand match needs a high Jaro-Winkler score **and** a Jaccard floor.

## CLI example — stdin scoring

`examples/score-stdin.mjs` reads a raw email from stdin, parses its headers,
runs `analyzeMessage`, and prints a JSON result with an example caller-side score.

```sh
# Build once before running (dist/ is gitignored):
npm run build

cat sample.eml | node examples/score-stdin.mjs
# with a trusted authserv-id:
cat sample.eml | node examples/score-stdin.mjs --trusted mx.example.net
```

Output shape:

```json
{
  "score": 9,
  "severityCounts": { "info": 0, "low": 1, "medium": 0, "high": 1 },
  "signals": [ … ],
  "metrics": { … }
}
```

**The numeric score and severity weights are an example caller policy, not a
library standard.** The library returns `signals` and `metrics`; thresholds,
weights, and allow/block decisions belong to the caller. The weights used in the
example are `info: 0`, `low: 1`, `medium: 3`, `high: 8`.

Pass `--trusted <authserv-id>` (repeatable) to declare trusted
`Authentication-Results` sources. Without it, all `Authentication-Results`
headers are treated as untrusted and authentication-failure signals are
downgraded to `low` severity.

## Migration status

The Thunderbird Auth Results Filter add-on's core modules (`src/core/*.js`) were
audited file by file in [`MIGRATION-AUDIT.md`](./MIGRATION-AUDIT.md), which
classifies each as *Migrated*, *Not core* (caller-owned), *Needs migration*, or
*Needs decision*. All reusable core is now **migrated** (listed below).
**`bigramNaturalness.js`** is *Needs decision* because it needs a license-cleared
language-frequency corpus. Future add-on logic will be evaluated case by case
against that same classification.

Migrated core (pure parsing, metrics, signals — no UI, storage, mailbox actions,
network, or scoring policy):

- Header normalization
- Mailbox/domain extraction
- `Authentication-Results` method/result extraction
- Trusted authserv-id matching, with shared trust resolution for all AR rules
- Trust-aware Authentication-Results failure signals (SPF/DKIM/DMARC)
- Message-ID domain consistency (`messageId.domainMismatch`)
- Reply-To domain consistency (`replyTo.domainMismatch`)
- Envelope-sender consistency (Return-Path and SPF `smtp.mailfrom` vs From, and the two against each other)
- DKIM signing-domain consistency (passing `header.d` vs From)
- DMARC From-domain consistency (trusted, passing `header.from` vs the visible From)
- Authentication & alignment metrics (`MessageMetrics.authentication`): Layer 1 raw SPF/DKIM/DMARC results and Layer 2 trusted+passing alignment/summary flags
- Sender-identity metrics (`MessageMetrics.senderIdentity`): display-name structure (including address-in-display-name detection), local-part/domain lexical profiles, domain label decomposition, and PSL-backed registrable-domain comparison (bundled via tldts; overridable)
- Display-name brand inference (`senderIdentity.brandInference`, `computeDisplayNameBrandInference`): Latin diacritic folding, brand-token normalization (incl. letter-spacing camouflage), catalog matching via Jaro-Winkler + Jaccard, brand/domain-mismatch fact, and the opt-in `displayName.brandDomainMismatch` signal — library-owned logic over a **caller-supplied** brand catalog (the core bundles none; see [Display-name brand inference](#display-name-brand-inference))
- Richer lexical heuristics helper (`computeLexicalHeuristics`): entropy, normalized entropy, vowel ratio, digit ratio, hyphen ratio, max hex/consonant/repeated runs, unique-character ratio, and letter/digit transitions — data-free and policy-neutral
- Random-looking token candidate helper (`computeRandomLookingCandidate`): a single boolean folding the lexical heuristics into the add-on's random local-part / domain-label shape check, tuned against known brand/word false positives — data-free and policy-neutral
- **Jaro-Winkler / Jaccard string similarity** (`computeJaro`, `computeJaroWinkler`, `computeJaccard`): data-free, policy-neutral similarity primitives (see [Jaro-Winkler string similarity](#jaro-winkler-string-similarity))
- Composite (Layer 4) signals combining the base layers (opt-in)

Add-on behavior that is intentionally **not** migrated — UI, notifications,
mailbox/folder actions, storage, Thunderbird/WebExtension APIs, network/DNS, and
the caller-owned policy modules `customFormulas.js`, `whitelist.js`, `scoring.js`,
plus brand/word-list data — stays caller-owned by the boundary in
[`AGENTS.md`](./AGENTS.md).

Open items in the audit: one **license decision** — whether to ever bundle the
language-frequency corpus that `bigramNaturalness.js` would require (*Needs
decision*).

## License

Apache-2.0. See [LICENSE](./LICENSE).

