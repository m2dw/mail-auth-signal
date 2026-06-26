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

## Repositories

Development and release happen in two different GitHub repositories:

- **`m2dw/mail-auth-signal-ai` (private)** — the development workspace. All
  issue-driven work, AI workflow commits, and local automation state live here.
  This is the repository you normally clone and where `origin` points. **npm is
  never published from here.**
- **`m2dw/mail-auth-signal` (public)** — the release and npm **provenance**
  source. The published tree and the `vX.Y.Z` tags live here so npm provenance
  points at a public source repository. The `Release` workflow that publishes to
  npm runs only in this repository.

To keep the public history clean, the private commit history (fine-grained AI
workflow commits and private issue numbers) is **not** pushed to the public
repository. Instead, the final development tree is promoted as a single squashed
release commit.

## Two-stage release flow

Releasing is two explicit stages, each a single command. Add the public
repository as a git remote named `public` once per clone:

```sh
git remote add public git@github.com:m2dw/mail-auth-signal.git
```

### Stage 1 — promote to the public repository

From an up-to-date private `main` with a clean working tree and the intended
`package.json` version already bumped (see [Release steps](#release-steps)):

```sh
# Preview everything first — no git/gh changes are made.
npm run release:promote -- 0.5.0 --dry-run

# Then promote for real (optionally open the PR with --open-pr):
npm run release:promote -- 0.5.0 --open-pr
```

This command:

1. Verifies the version argument matches `package.json`.
2. Verifies the `public` remote exists and points at `m2dw/mail-auth-signal`.
3. Refuses a dirty worktree (unless `--dry-run`).
4. Runs `npm run release:check` on the tree being promoted.
5. Builds a tree from the current `HEAD` with private-only paths
   (`.n8n-artifacts/`) stripped.
6. Creates **one** commit `release: prepare vX.Y.Z` on top of `public/main` —
   no private commit history is copied.
7. Shows a diff summary, pushes `release/vX.Y.Z` to the public repository, and
   (with `--open-pr`) opens a public PR whose title and body are free of private
   issue numbers, local paths, and AI workflow internals.

Review and merge the public release PR before continuing.

> Everything after the single `--` is forwarded to the script, so the version
> and flags go together: `npm run release:promote -- 0.5.0 --dry-run`.

Useful flags: `--dry-run`, `--open-pr`, `--force` (overwrite an existing public
release branch), `--remote <name>`, `--base <branch>`.

### Stage 2 — publish from the public repository

After the public release PR is **merged**, tag the merged public commit:

```sh
# Preview first.
npm run release:publish-tag -- 0.5.0 --dry-run

# Then tag and push (this triggers the npm publish).
npm run release:publish-tag -- 0.5.0
```

This command:

1. Verifies the `public` remote and fetches `public/main`.
2. Verifies `public/main` `package.json` version matches the argument (i.e. the
   Stage 1 PR really merged).
3. Refuses if the tag already exists (unless `--force`).
4. Creates `vX.Y.Z` on the merged public commit and pushes it to the public
   repository.

Pushing the tag triggers the public
[`Release` workflow](./.github/workflows/release.yml), which publishes to npm
with provenance. **The publish-tag command never publishes to npm directly and
never touches the private remote.**

### Required GitHub Environment and npm Trusted Publisher settings

The publish step relies on npm **Trusted Publishing** (OIDC) configured on the
public repository:

| Setting | Value |
| --- | --- |
| Source repository | `m2dw/mail-auth-signal` |
| Workflow filename | `release.yml` |
| GitHub Environment | `release` |
| Allowed action | `npm publish` |

- Configure the trusted publisher on npmjs.com (package settings → **Trusted
  Publisher**) with exactly these values.
- Create a `release` **Environment** in the public repo (Settings →
  Environments) and add yourself as a required reviewer so each publish needs
  explicit approval.
- The `Release` workflow runs on **Node 24** and upgrades npm to
  **`>=11.5.1`**, the minimum that supports OIDC trusted publishing with
  provenance.

The remaining sections below cover versioning, the per-release prep that feeds
Stage 1, the very first publish, and what ends up in the tarball.

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

All publishing configuration lives on the **public** repository
(`m2dw/mail-auth-signal`), since that is where the `Release` workflow runs.

1. **npm account** with publish rights and 2FA enabled.
2. One of the two publishing methods configured (trusted publishing preferred):
   - **Trusted publishing (recommended).** On npmjs.com, configure the public
     `m2dw/mail-auth-signal` repository and the `release.yml` workflow as a
     trusted publisher for the package (see
     [Required GitHub Environment and npm Trusted Publisher settings](#required-github-environment-and-npm-trusted-publisher-settings)).
     This uses short-lived OIDC tokens — no long-lived secret is stored in
     GitHub. Trusted publishing for a brand-new package name may require an
     initial manual publish first (see [First release](#first-release)).
   - **Automation token (fallback).** Create an npm **Automation** access token
     and add it to the **public** repository as the `NPM_TOKEN` secret (Settings
     → Secrets and variables → Actions). Scope it to this package only if using a
     granular token.
3. A `release` **Environment** in the **public** repo settings (Settings →
   Environments). Add yourself as a required reviewer so every automated publish
   needs explicit approval, and attach the `NPM_TOKEN` secret to that
   environment if you use the token fallback.

## Release steps

These steps prepare the private `main` so it is ready for **Stage 1** of the
[two-stage release flow](#two-stage-release-flow). Run them on an up-to-date
private `main` with a clean working tree.

1. **Choose the next version.** Decide PATCH / MINOR / MAJOR from the
   [versioning policy](#versioning-policy) based on what changed since the last
   tag.

2. **Update the changelog.** Move the relevant `## Unreleased` notes in
   [`CHANGELOG.md`](./CHANGELOG.md) under a new `## vX.Y.Z — YYYY-MM-DD`
   heading, and leave a fresh empty `## Unreleased` section on top.

3. **Bump the version.** This updates both `package.json` and
   `package-lock.json`. Use `--no-git-tag-version` so the commit and tag are
   created later, by the public release flow rather than locally:

   ```sh
   npm version <patch|minor|major> --no-git-tag-version
   ```

   Commit the changelog and version bump to the private `main`.

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
   files. (Stage 1 re-runs this check on the exact tree it promotes.)

5. **Promote and publish.** Run the two-stage flow:

   ```sh
   npm run release:promote -- X.Y.Z -- --open-pr   # Stage 1: public release PR
   # ...review and merge the public PR...
   npm run release:publish-tag -- X.Y.Z            # Stage 2: tag → npm publish
   ```

   See [Two-stage release flow](#two-stage-release-flow) for details, flags, and
   dry-run previews. Stage 2 pushes the `vX.Y.Z` tag to the **public**
   repository, whose [`Release` workflow](./.github/workflows/release.yml)
   verifies the tag/version match, re-runs tests and build, inspects the package,
   and publishes with provenance. If the `release` environment requires a
   reviewer, approve the run.

6. **Verify the publish.**

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
