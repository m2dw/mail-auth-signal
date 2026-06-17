# Releasing `mail-auth-signal`

This document describes how a maintainer cuts a versioned release and publishes
it to the public npm registry as [`mail-auth-signal`](https://www.npmjs.com/package/mail-auth-signal).

The package is published under the [Apache-2.0](./LICENSE) license and ships only
the built library: `dist/`, `README.md`, `LICENSE`, and `NOTICE`. Local
automation state (`.n8n-artifacts/`), the repo lockfile, and source/test files
are **not** published — see [Package contents](#package-contents).

> Releases are maintainer-controlled. The CI workflow never publishes on its own;
> it runs only when a maintainer pushes a `vX.Y.Z` tag and (optionally) approves
> the `release` environment.

## Versioning policy

This package follows [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`).

- **PATCH** — backward-compatible bug fixes; no change to the public signal
  taxonomy, types, or rule output shapes.
- **MINOR** — backward-compatible additions: new rules, new signals, new
  optional inputs/metrics, additive type fields.
- **MAJOR** — breaking changes to the public API: renamed/removed exports,
  changed `AnalyzeResult` shape, changed signal names/severities, or any change
  that a downstream consumer (e.g. the Thunderbird add-on) would have to adapt
  to.

While the package is pre-`1.0.0`, treat **MINOR** as the breaking-change channel
per SemVer's `0.y.z` rules, and reserve `1.0.0` for the first commitment to API
stability.

## Prerequisites for the maintainer

1. **npm account** with publish rights and 2FA enabled.
2. One of the two publishing methods configured (trusted publishing preferred):
   - **Trusted publishing (recommended).** On npmjs.com, configure this GitHub
     repository and the `Release` workflow as a trusted publisher for the
     package. This uses short-lived OIDC tokens — no long-lived secret is stored
     in GitHub. Trusted publishing for a brand-new package name may require an
     initial manual publish first (see [First release](#first-release)).
   - **Automation token (fallback).** Create an npm **Automation** access token
     and add it to the repository as the `NPM_TOKEN` secret (Settings →
     Secrets and variables → Actions). Scope it to this package only if using a
     granular token.
3. A `release` **Environment** in repo settings (Settings → Environments). Add
   yourself as a required reviewer so every automated publish needs explicit
   approval, and attach the `NPM_TOKEN` secret to that environment if you use the
   token fallback.

## Release steps

Run these on an up-to-date `main` with a clean working tree.

1. **Choose the next version.** Decide PATCH / MINOR / MAJOR from the
   [versioning policy](#versioning-policy) based on what changed since the last
   tag.

2. **Update the changelog.** Move the relevant `## Unreleased` notes in
   [`CHANGELOG.md`](./CHANGELOG.md) under a new `## vX.Y.Z — YYYY-MM-DD`
   heading, and leave a fresh empty `## Unreleased` section on top.

3. **Bump the version.** This updates both `package.json` and
   `package-lock.json`. Use `--no-git-tag-version` if you want to review the diff
   before tagging:

   ```sh
   npm version <patch|minor|major> --no-git-tag-version
   ```

4. **Verify the release locally.** This runs typecheck, tests, build, and a
   dry-run package inspection in one shot:

   ```sh
   npm run release:check
   ```

   Equivalent to running each step manually:

   ```sh
   npm test
   npm run build
   npm pack --dry-run
   ```

   Confirm the [package contents](#package-contents) are exactly the intended
   files.

5. **Commit, tag, and push.** The tag must be `v` + the exact `package.json`
   version (the release workflow enforces this match):

   ```sh
   git add CHANGELOG.md package.json package-lock.json
   git commit -m "release: vX.Y.Z"
   git tag vX.Y.Z
   git push origin main
   git push origin vX.Y.Z
   ```

6. **Approve the publish.** Pushing the tag triggers the
   [`Release` workflow](./.github/workflows/release.yml). If the `release`
   environment requires a reviewer, approve the run. The workflow re-runs tests
   and build, verifies the tag/version match, inspects the package, and publishes
   with provenance.

7. **Verify the publish.**

   ```sh
   npm view mail-auth-signal version
   ```

## First release

The package name was unpublished on npm when this process was added
(`npm view mail-auth-signal` returned `E404`). The very first publish needs
extra care:

- **Confirm the name is still available** right before publishing:

  ```sh
  npm view mail-auth-signal name version --json
  ```

  An `E404` means the name is free.

- **Publish as a public, scope-less package.** The first `npm publish` must use
  `--access public` (already set in the workflow and recommended for the manual
  path) so the package is installable by everyone.

- **Trusted publishing bootstrap.** Some npm trusted-publishing setups require an
  existing package before the publisher can be linked. If you cannot configure
  trusted publishing for a non-existent package, perform the **first** publish
  manually from a clean checkout, then configure trusted publishing for all
  subsequent releases:

  ```sh
  npm run release:check     # typecheck + test + build + pack --dry-run
  npm publish --access public
  ```

  Do **not** pass `--provenance` here: provenance generation only works in a
  supported CI/OIDC environment (such as the `Release` workflow), not from a
  local checkout, so it would make this manual publish fail. `npm publish` will
  prompt for 2FA. After this initial publish succeeds, configure trusted
  publishing and use the tag-driven workflow — which publishes with provenance —
  for later releases.

- **Do not commit npm credentials.** Never add an `NPM_TOKEN` to the repository
  in plaintext or to any committed file; use GitHub Actions secrets or trusted
  publishing only.

## Package contents

The published tarball is restricted by the `files` allowlist in `package.json`:

```
dist/index.js        # ESM build
dist/index.cjs       # CommonJS build
dist/index.d.ts      # ESM type declarations
dist/index.d.cts     # CommonJS type declarations
README.md
LICENSE
NOTICE
package.json         # always included by npm
```

Everything else — `src/`, `test/`, `.n8n-artifacts/`, `package-lock.json`,
`tsconfig.json`, CI config, and local automation state — is excluded. Always
confirm with:

```sh
npm pack --dry-run
```

If that command ever lists `.n8n-artifacts/`, a lockfile, source, or test files,
**stop and do not publish** — the `files` allowlist or `.gitignore` has
regressed.

## Installing the published package

Once published, downstream consumers (including the Thunderbird add-on) install
it from npm:

```sh
npm install mail-auth-signal
```
