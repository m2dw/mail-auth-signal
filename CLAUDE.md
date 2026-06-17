# Claude Development Notes

This repository is the Apache-2.0 standalone core for sender-risk signal extraction.

Before editing:

1. Read `AGENTS.md`.
2. Check `git status --short --branch`.
3. Use the `n8n-ai-cli-loop` workflow mechanism by default unless the user explicitly asks for direct local-only work.
4. Keep changes scoped to the requested issue.

Implementation expectations:

- Use TypeScript.
- Keep APIs small, typed, and serializable.
- Do not introduce runtime network access in core code.
- Do not add Thunderbird, WebExtension, or n8n dependencies.
- Keep n8n workflow state and generated automation artifacts outside this repository.
- Add tests with every behavior change.
- Run `npm test` and `npm run build` when possible.

Review expectations:

- Highlight security boundary changes first.
- Pay special attention to false-positive mitigation rules that an attacker could intentionally trigger.
- Check whether added data or code has a compatible license.
