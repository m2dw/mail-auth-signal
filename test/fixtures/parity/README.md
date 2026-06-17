# Parity fixtures

These fixtures freeze the analyzer's output for the copied Thunderbird detection
behavior now implemented in `mail-auth-signal` (Authentication-Results failures,
sender/Message-ID, Reply-To, Return-Path / SPF `smtp.mailfrom`, DKIM `header.d`,
and DMARC `header.from` consistency, plus the normalized signal taxonomy). They
exist so a future rule change that drifts from the current behavior is caught,
and so behavior can be compared across future ports or other-language
implementations.

`test/parity.test.ts` drives every fixture in this directory.

## What a fixture is

One JSON file per representative case. The shape matches the existing
rule-level fixtures (`test/fixtures/*.json`), with one extra `family` field:

```jsonc
{
  "family": "dkim.domainMismatch",        // the signal key this case is the canonical example of,
                                           // or "combined" (several families) / "none" (silent baseline)
  "description": "Human-readable…",        // what the case demonstrates and why the output looks this way
  "input": {                               // a complete AnalyzeInput
    "headers": { /* sanitized, minimal headers */ },
    "options": { "trustedAuthservIds": ["mx.example.net"] }
  },
  "expected": {                            // the exact analyzeMessage(input) output, JSON round-tripped
    "metrics": { /* all 16 MessageMetrics keys */ },
    "signals": [ /* zero or more signals */ ]
  }
}
```

The test computes `analyzeMessage(input)`, round-trips it through JSON (proving
the output is fully serializable), and asserts it deep-equals `expected`. Because
`expected` is committed literally, any behavior change shows up as a fixture diff.

## Conventions

- **Sanitized and minimal only.** Use the reserved example domains: `example.com`
  for the legitimate sender, `evil.test` for the attacker, `mailer.example.net`
  for a distinct mail-origin domain, and `mx.example.net` / `relay.unknown.test`
  for trusted / untrusted authserv-ids. Never include real mail, message bodies,
  personal data, third-party datasets, brand lists, or PSL data. Include only the
  headers a case needs.
- **One family per fixture where practical.** Hold the other rules silent (keep
  the other domains From-aligned) so the fixture isolates the family named in
  `family`. The test enforces this: a single-family fixture may only emit its
  declared `family` key (plus `auth.results.untrusted`, which is flagged
  separately for an untrusted source).
- **`combined` and `none`.** Use `family: "combined"` for a multi-signal showcase
  that also locks down cross-rule ordering, and `family: "none"` for the silent
  clean-mail baseline. These are exempt from the single-family check.
- **`allowedCompanions`.** A few families cannot be exercised in true isolation —
  e.g. `envelopeSender.domainDisagreement` with a From-aligned Return-Path forces
  an `smtpMailfrom.domainMismatch` too. List the inherently coupled signal keys
  in an optional `allowedCompanions` array so the single-family check permits
  them. `auth.results.untrusted` is always allowed and need not be listed.
- **Pin the whole metrics object.** `expected.metrics` must list all 16
  `MessageMetrics` keys, not just the ones a rule reads, so a change to any
  extracted fact surfaces.
- **No interpretation in `expected`.** The core never returns a score or an
  allow/block/move/notify decision; fixtures only contain metrics and signals.

## Adding a case

1. Add a `<family>.json` (or scenario-named) file following the shape above.
2. Import it in `test/parity.test.ts` and add it to the `fixtures` array.
3. Run `npm test`. If you are unsure of the exact `expected` output, write the
   `input` first, let the round-trip assertion fail, and copy the analyzer's
   actual output from the diff once you have confirmed it is correct.
4. If the case exercises a brand-new rule family, add its signal key to
   `REQUIRED_FAMILY_KEYS` in the test so the corpus keeps covering it.
