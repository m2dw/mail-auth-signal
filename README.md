# Mail Auth Signal

[![CI](https://github.com/m2dw/mail-auth-signal/actions/workflows/ci.yml/badge.svg)](https://github.com/m2dw/mail-auth-signal/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/mail-auth-signal)](https://www.npmjs.com/package/mail-auth-signal)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Mail Auth Signal is a lightweight sender-risk signal engine for email authentication results and header consistency analysis.

It is intended to be the standalone, Apache-2.0 licensed core extracted from the Thunderbird Auth Results Filter project. The library focuses on pure parsing and signal extraction. It does not move messages, show UI, access Thunderbird APIs, perform DNS lookups, or send message data anywhere.

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
so detection rules can be migrated incrementally:

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
- `context` — an open-ended serializable bag for future caller-provided policy context (per-sender overrides, allow-listed domains, metadata). Currently ignored by all rules; reserved for rule migration from the Thunderbird add-on.

## Writing a rule

A `Rule` is the unit of incremental migration. Each detection rule is a pure
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
| `composite` | A higher-layer observation that combines several of the above (the opt-in Layer 4 rules). | `composite.unauthenticatedFromSpoof`, `composite.authenticatedDisplayNameSpoof`, `composite.alignedAuthenticationConfirmed` |

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
| `composite.authenticatedDisplayNameSpoof` | medium | The message authenticates and aligns for its From (`anyAuthAligned === true`) **and** the display name addresses a different domain (`displayName.containsEmail && embeddedDomainMatchesFromDomain === false`). | Authenticated lookalike with a borrowed display name (`From: "security@paypal.com" <alerts@authed.example>`) — the case a pure auth/Junk filter waves through. The signal points at the attacker's own message, never the impersonated brand. |
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

`displayName` (`DisplayNameMetrics`) reports `present`, the unquoted `text`, its
codepoint `length`, `hasNonAscii`, and — the attacker-relevant part — whether the
display name itself contains an email address (`containsEmail`), the
`embeddedDomains` found in it, and `embeddedDomainMatchesFromDomain`. The last is
`false` for the classic *address-in-display-name* spoof, e.g.
`From: "service@paypal.com" <attacker@evil.test>`, where a client may surface only
the brand address while the real sender is elsewhere. It is `null` when there is
nothing to compare, so a plain display name never reads as a mismatch.

`fromDomainParts` / `messageIdDomainParts` (`DomainParts`) split a domain into its
dot-separated `labels` (with `labelCount` and `topLabel`). These need no external
data. The `registrableDomain` and `subdomainDepth` fields, and
`messageIdRegistrableDomainMatchesFromDomain`, are **only** populated when the
caller supplies a registrable-domain resolver — see below.

### Registrable-domain metrics and the PSL boundary

Deciding where the registrable (organizational) domain boundary falls — e.g.
`example.co.uk` vs `example.com` — cannot be done correctly without
[Public Suffix List](https://publicsuffix.org/) data. **This package bundles no
PSL, brand list, or word list** (see `AGENTS.md` / `NOTICE`), so it never guesses
that boundary. Instead the caller may inject a resolver as a non-serializable
dependency — kept out of the JSON-serializable `AnalyzeInput`, exactly like
`Rule`s:

```ts
import { analyzeMessage } from "mail-auth-signal";

const result = analyzeMessage(input, undefined, {
  // Supply your own PSL-backed lookup; the core bundles none.
  getRegistrableDomain: (domain) => myPsl.getDomain(domain) ?? null,
});
result.metrics.senderIdentity.messageIdRegistrableDomainMatchesFromDomain;
```

The resolver should return an already-normalized (lower-cased) registrable domain,
or `null` when it cannot resolve one. Without it, the registrable-domain fields
stay `null` and the label-based fields are still populated. This complements the
exact-match consistency metrics: a caller with PSL data can treat an ESP subdomain
(`mailer.example.com` vs `example.com`) as same-organization, where the exact
`messageIdDomainMatchesFromDomain` reads as a mismatch.

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
// { shannonEntropy, normalizedEntropy, vowelRatio, maxConsonantRun,
//   maxRepeatedCharRun, uniqueCharRatio, letterDigitTransitions }
```

| Field | Meaning |
|---|---|
| `shannonEntropy` | Shannon entropy in bits over the codepoint-frequency distribution. `0` for an empty or single-character token. Higher = a more uniform, less predictable character mix. |
| `normalizedEntropy` | `shannonEntropy` divided by the maximum for this length (`log2(length)`), giving a length-independent `[0, 1]` value. `0` when `length < 2`. |
| `vowelRatio` | ASCII vowels ÷ ASCII letters, `[0, 1]`. `0` when there are no ASCII letters. |
| `maxConsonantRun` | Longest run of consecutive ASCII consonants. |
| `maxRepeatedCharRun` | Longest run of the same codepoint repeated (`3` for `"aaab"`). `0` when empty, else ≥ 1. |
| `uniqueCharRatio` | Distinct codepoints ÷ length, `[0, 1]`. `0` when empty. |
| `letterDigitTransitions` | Adjacent pairs that switch between an ASCII letter and an ASCII digit, either direction (`2` for `"ab12ab"`). |

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
was considered and **deliberately omitted**: a meaningful naturalness score needs
a language-frequency dataset, and bundling one would cross the data/license
boundary this package keeps clear (see `AGENTS.md` / `NOTICE`). A caller with its
own licensed corpus can layer that on top of these metrics.

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

## Current status

This repository is in early development. Implemented so far:

- Header normalization
- Basic mailbox/domain extraction
- `Authentication-Results` method/result extraction
- Trusted authserv-id matching, with shared trust resolution for all AR rules
- Trust-aware Authentication-Results failure signals (SPF/DKIM/DMARC)
- Message-ID domain consistency (`messageId.domainMismatch`)
- Reply-To domain consistency (`replyTo.domainMismatch`)
- Envelope-sender consistency (Return-Path and SPF `smtp.mailfrom` vs From, and the two against each other)
- DKIM signing-domain consistency (passing `header.d` vs From)
- DMARC From-domain consistency (trusted, passing `header.from` vs the visible From)
- Authentication & alignment metrics (`MessageMetrics.authentication`): Layer 1 raw SPF/DKIM/DMARC results and Layer 2 trusted+passing alignment/summary flags
- Sender-identity metrics (`MessageMetrics.senderIdentity`): display-name structure (including address-in-display-name detection), local-part/domain lexical profiles, domain label decomposition, and an optional registrable-domain comparison via a caller-supplied PSL resolver (no list bundled)
- Richer lexical heuristics helper (`computeLexicalHeuristics`): entropy, normalized entropy, vowel ratio, max consonant/repeated runs, unique-character ratio, and letter/digit transitions — data-free and policy-neutral

The remaining rules from the Thunderbird add-on will be migrated incrementally after API boundaries and fixtures are stable.

## License

Apache-2.0. See [LICENSE](./LICENSE).

