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

`analyzeMessage(input: AnalyzeInput): AnalyzeResult` is the single public analysis entry point.

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

## Current status

This repository is in the initial scaffold stage. The first implementation intentionally covers only a small, stable subset:

- Header normalization
- Basic mailbox/domain extraction
- Basic `Authentication-Results` method/result extraction
- Trusted authserv-id matching
- Message-ID domain comparison

The richer Layer 1-5 rules from the Thunderbird add-on will be migrated incrementally after API boundaries and fixtures are stable.

## License

Apache-2.0. See [LICENSE](./LICENSE).

