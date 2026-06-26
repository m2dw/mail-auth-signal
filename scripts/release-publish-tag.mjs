#!/usr/bin/env node
// Stage 2 of the two-stage public release flow: after the public release PR is
// merged, tag the merged public commit so the public `Release` workflow
// publishes to npm.
//
//   npm run release:publish-tag -- 0.5.0 [options]
//
// What it does:
//   1. Validates the version argument.
//   2. Resolves and validates the public remote (must be m2dw/mail-auth-signal).
//   3. Fetches the public base and verifies its package.json version matches.
//   4. Refuses if the tag already exists (unless --force).
//   5. Creates `vX.Y.Z` pointing at the merged public commit and pushes it to
//      the public remote — which triggers the public Release workflow.
//
// This script NEVER publishes to npm directly and NEVER touches the private
// remote. Publishing is done only by the public Release workflow on tag push.
//
// Options:
//   --dry-run         Print every action without touching git.
//   --force           Overwrite an existing tag on the public remote.
//   --remote <name>   Public remote name (default: "public").
//   --base <branch>   Public base branch to tag (default: "main").

import {
  DEFAULT_PUBLIC_BASE,
  DEFAULT_PUBLIC_REMOTE,
  PUBLIC_REPO,
  exec,
  execTry,
  fail,
  info,
  parseArgs,
  remoteRefExists,
  requireVersionArg,
  resolvePublicRemote,
  run,
  step,
  tryRun,
  warn,
} from './lib/release-common.mjs';

const { version: versionArg, flags } = parseArgs(process.argv.slice(2), {
  booleanFlags: ['dry-run', 'force'],
  valueFlags: ['remote', 'base'],
});

const dryRun = Boolean(flags['dry-run']);
const force = Boolean(flags.force);
const remoteName = flags.remote || DEFAULT_PUBLIC_REMOTE;
const baseBranch = flags.base || DEFAULT_PUBLIC_BASE;

const version = requireVersionArg(versionArg);
const tag = `v${version}`;

step(`Stage 2: tag v${version} on ${PUBLIC_REPO} to trigger npm publish`);
if (dryRun) info('  mode: DRY RUN (no git changes will be made)');

// 1 + 2. Validate the public remote.
const remote = resolvePublicRemote(remoteName);
info(`  remote: ${remote.name} -> ${remote.slug}`);
info(`  base:   ${remote.name}/${baseBranch}`);
info(`  tag:    ${tag}`);

// 3. Fetch the public base and verify the merged version.
step(`Fetching ${remote.name}/${baseBranch}`);
exec('git', ['fetch', remote.name, baseBranch], { dryRun });

if (dryRun) {
  info(`  [dry-run] would read ${remote.name}/${baseBranch}:package.json and require version ${version}`);
} else {
  const pkgJson = run('git', ['show', `${remote.name}/${baseBranch}:package.json`]);
  const publicVersion = JSON.parse(pkgJson).version;
  if (publicVersion !== version) {
    fail(
      `${remote.slug} ${baseBranch} package.json version is "${publicVersion}", not "${version}".\n` +
        `  Has the Stage 1 release PR been merged? Tag only a merged public commit.`,
    );
  }
  info(`  verified ${remote.name}/${baseBranch} package.json version = ${version}`);
}

// 4. Tag-existence guard.
if (remoteRefExists(remote.name, `refs/tags/${tag}`)) {
  if (!force) {
    fail(
      `tag "${tag}" already exists on ${remote.slug}.\n` +
        `  A published version must never be re-tagged. Re-run with --force only if you are\n` +
        `  certain the tag was created in error and nothing was published from it.`,
    );
  }
  warn(`tag "${tag}" already exists on ${remote.slug}; will overwrite it (--force).`);
}

// 5. Create the tag at the merged public commit and push it.
step(`Tagging ${remote.name}/${baseBranch} as ${tag} and pushing`);

if (dryRun) {
  info(`  [dry-run] would create annotated tag ${tag} at ${remote.name}/${baseBranch}`);
  info(`  [dry-run] would push ${tag} to ${remote.name} (triggers the public Release workflow)`);
} else {
  const target = run('git', ['rev-parse', `${remote.name}/${baseBranch}`]);

  // Always create the local tag with --force. The remote-tag guard above has
  // already ensured we are not overwriting a published tag, so a leftover local
  // tag here can only be from a previous run whose push failed. Replacing it
  // deliberately keeps the command idempotent: a safe retry must not require
  // manual `git tag -d` or the scary remote --force path.
  const tagArgs = ['tag', '--force', '-a', tag, '-m', `mail-auth-signal ${tag}`, target];
  exec('git', tagArgs, { dryRun });

  const pushArgs = ['push'];
  if (force) pushArgs.push('--force');
  pushArgs.push(remote.name, tag);

  // If the push is rejected or hits a transient network/auth failure, remove
  // the local tag we just created so rerunning the normal command works without
  // manual cleanup.
  const pushStatus = execTry('git', pushArgs, { dryRun });
  if (pushStatus !== 0) {
    tryRun('git', ['tag', '-d', tag]);
    fail(
      `pushing ${tag} to ${remote.name} failed (exit ${pushStatus}).\n` +
        `  The local tag was removed so you can safely rerun this command once the cause is fixed.`,
    );
  }
}

step(
  dryRun
    ? 'Dry run complete. No tag was created or pushed.'
    : `Stage 2 complete. The public Release workflow will publish v${version} to npm.`,
);
info('  Verify with:  npm view mail-auth-signal version');
