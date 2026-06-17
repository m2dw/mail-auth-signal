# Repository Guidelines

This repository contains the standalone `mail-auth-signal` library. It is Apache-2.0 licensed and should remain independent from Thunderbird-specific code.

## Project Scope

- Build a pure sender-risk signal engine for email authentication and header consistency analysis.
- Keep the core free of UI, storage, Thunderbird APIs, mailbox operations, notifications, folder moves, and network access.
- Prefer structured outputs over direct policy decisions. Callers decide thresholds and actions.
- Treat this package as the reusable core that may be consumed by Thunderbird add-ons, Node tools, WebExtension code, and future ports.

## Licensing

- New source files must be compatible with Apache-2.0.
- Do not copy third-party code or data unless its license is verified and documented.
- Do not import Public Suffix List data, brand lists, word lists, or spam datasets without adding license documentation.
- If logic is migrated from `thunderbird-auth-results-filter`, keep only code that is owned by this project owner or explicitly compatible with Apache-2.0.

## Architecture Rules

- `src/` must stay runtime-neutral TypeScript.
- Avoid direct use of `fs`, `dns`, browser globals, Thunderbird APIs, and process-global configuration in core modules.
- Accept all external context through input objects or dependency injection.
- Return serializable data structures suitable for logs, UI display, tests, and cross-language fixture comparison.
- Keep parsing, metric extraction, and scoring/rule evaluation separate where practical.

## Testing

- Add focused tests for every parser edge case and rule change.
- Prefer JSON fixtures for cross-language portability.
- Run `npm test` before committing behavior changes.
- Run `npm run build` before release-oriented changes.

## AI Agent Notes

- Read this file before making changes.
- Do not add Thunderbird-specific behavior to this repository.
- Keep public comments and generated docs free of local absolute paths.
- When adding a rule, document what attacker or false-positive pattern it is meant to handle.
- When uncertain whether a change belongs here or in the Thunderbird add-on, keep this package narrower and push integration behavior to the caller.

