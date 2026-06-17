# Mail Auth Signal

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

The package is not published yet. During early development, use this repository directly.

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

`analyzeMessage(input: AnalyzeInput, rules?: readonly Rule[]): AnalyzeResult` is the
primary public analysis entry point. Internally it runs in two separable halves
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
- `defaultRules` — the built-in rule set. Callers pass their own array (a subset of
  `defaultRules`, or custom `Rule`s) as the second argument to `analyzeMessage`.

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

The remaining rules from the Thunderbird add-on will be migrated incrementally after API boundaries and fixtures are stable.

## License

Apache-2.0. See [LICENSE](./LICENSE).

