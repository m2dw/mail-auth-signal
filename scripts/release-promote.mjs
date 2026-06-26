#!/usr/bin/env node
// Stage 1 of the two-stage public release flow: promote the private development
// state to the public repository as a clean, single squash commit.
//
//   npm run release:promote -- 0.5.0 [options]
//
// What it does:
//   1. Validates the version argument and that it matches package.json.
//   2. Resolves and validates the public remote (must be m2dw/mail-auth-signal).
//   3. Refuses a dirty worktree (unless --dry-run).
//   4. Runs the existing release checks on the tree being promoted.
//   5. Builds a tree from the current HEAD with private-only paths stripped.
//   6. Creates ONE commit `release: prepare vX.Y.Z` on top of public `main`
//      (no private commit history is copied).
//   7. Shows a diff summary, pushes `release/vX.Y.Z` to the public remote, and
//      optionally opens a public PR.
//
// Options:
//   --dry-run            Print every action without touching git/gh.
//   --open-pr            Open a PR on the public repo via the gh CLI.
//   --force              Overwrite an existing public release branch.
//   --skip-checks        Skip `npm run release:check` (not recommended).
//   --remote <name>      Public remote name (default: "public").
//   --base <branch>      Public base branch (default: "main").

import {
  DEFAULT_PUBLIC_BASE,
  DEFAULT_PUBLIC_REMOTE,
  PRIVATE_PATHS,
  PUBLIC_REPO,
  assertCleanWorktree,
  exec,
  fail,
  info,
  parseArgs,
  readPackageVersion,
  remoteRefOid,
  requireVersionArg,
  resolvePublicRemote,
  run,
  step,
  warn,
} from './lib/release-common.mjs';

import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const { version: versionArg, flags } = parseArgs(process.argv.slice(2), {
  booleanFlags: ['dry-run', 'open-pr', 'force', 'skip-checks'],
  valueFlags: ['remote', 'base'],
});

const dryRun = Boolean(flags['dry-run']);
const openPr = Boolean(flags['open-pr']);
const force = Boolean(flags.force);
const remoteName = flags.remote || DEFAULT_PUBLIC_REMOTE;
const baseBranch = flags.base || DEFAULT_PUBLIC_BASE;

const version = requireVersionArg(versionArg);
const tag = `v${version}`;
const branch = `release/${tag}`;

step(`Stage 1: promote v${version} to ${PUBLIC_REPO}`);
if (dryRun) info('  mode: DRY RUN (no git/gh changes will be made)');

// 1. Version must match the tree we are about to promote.
const pkgVersion = readPackageVersion();
if (pkgVersion !== version) {
  fail(
    `version argument "${version}" does not match package.json version "${pkgVersion}".\n` +
      `  Bump package.json first, or pass the matching version.`,
  );
}
info(`  version:   ${version} (matches package.json)`);

// 2. Validate the public remote before doing anything else.
const remote = resolvePublicRemote(remoteName);
info(`  remote:    ${remote.name} -> ${remote.slug}`);
info(`  base:      ${remote.name}/${baseBranch}`);
info(`  branch:    ${branch}`);
info(`  tag later: ${tag} (created in Stage 2, not here)`);

// 3. Clean worktree.
assertCleanWorktree(dryRun);

// Fetch the public base so we build on top of the latest public main.
step(`Fetching ${remote.name}/${baseBranch}`);
exec('git', ['fetch', remote.name, baseBranch], { dryRun });

// 4. Existing release checks on the exact tree being promoted (current HEAD).
if (flags['skip-checks']) {
  warn('skipping release checks because --skip-checks is set.');
} else {
  step('Running release checks (npm run release:check)');
  exec('npm', ['run', 'release:check'], { dryRun });
}

// 5. Branch-existence guard. Capture the remote OID so the later force-push can
// use an explicit lease that works even without a local tracking ref.
const existingBranchOid = remoteRefOid(remote.name, `refs/heads/${branch}`);
if (existingBranchOid) {
  if (!force) {
    fail(
      `branch "${branch}" already exists on ${remote.slug}.\n` +
        `  Re-run with --force to overwrite it (force-push), or pick a new version.`,
    );
  }
  warn(`branch "${branch}" already exists on ${remote.slug}; will force-push (--force).`);
}

// 6. Build the promoted tree: current HEAD tree minus private-only paths.
step('Composing public release commit (squash of the final tree)');

if (dryRun) {
  info('  [dry-run] would build a tree from HEAD with these paths stripped:');
  for (const p of PRIVATE_PATHS) info(`              - ${p}`);
  info(`  [dry-run] would show a diff summary of ${remote.name}/${baseBranch} vs the stripped tree`);
  info(`  [dry-run] would create commit "release: prepare v${version}" on top of ${remote.name}/${baseBranch}`);
} else {
  const baseCommit = run('git', ['rev-parse', `${remote.name}/${baseBranch}`]);

  // Compose the tree in a throwaway index so the real index is untouched.
  const tmpIndex = join(tmpdir(), `mas-promote-${randomBytes(6).toString('hex')}.index`);
  const idxEnv = { env: { ...process.env, GIT_INDEX_FILE: tmpIndex } };
  run('git', ['read-tree', 'HEAD'], idxEnv);
  run('git', ['rm', '--cached', '-r', '--quiet', '--ignore-unmatch', ...PRIVATE_PATHS], idxEnv);
  const tree = run('git', ['write-tree'], idxEnv);

  // Diff summary BEFORE creating the commit so the operator sees exactly what
  // the public release would change relative to the public base.
  step('Diff summary against public base');
  const diffstat = run('git', ['diff', '--stat', baseCommit, tree]);
  info(diffstat || '  (no changes — public base already matches this tree)');

  const commitMessage =
    `release: prepare v${version}\n\n` +
    `Public release of mail-auth-signal v${version}.\n` +
    `Promoted as a single squashed commit from the development repository.\n`;
  const newCommit = run('git', ['commit-tree', tree, '-p', baseCommit, '-m', commitMessage]);
  info(`  created commit ${newCommit.slice(0, 12)} on top of ${baseCommit.slice(0, 12)}`);

  // 7a. Push the composed commit to the release branch.
  step(`Pushing ${branch} to ${remote.name}`);
  const pushArgs = ['push'];
  if (force && existingBranchOid) {
    // Pin the lease to the OID we just read from the remote. A bare
    // `--force-with-lease` relies on a `${remote.name}/${branch}` tracking ref,
    // which a fresh clone may not have, and would be rejected as a stale lease.
    pushArgs.push(`--force-with-lease=refs/heads/${branch}:${existingBranchOid}`);
  }
  pushArgs.push(remote.name, `${newCommit}:refs/heads/${branch}`);
  exec('git', pushArgs, { dryRun });
}

// 7b. Optionally open a public PR. Body is kept free of private internals.
if (openPr) {
  step('Opening public release PR');
  const prTitle = `release: prepare v${version}`;
  const prBody =
    `Public release of \`mail-auth-signal\` v${version}.\n\n` +
    `This branch is a single squashed promotion of the final development tree ` +
    `onto \`${baseBranch}\`. After review and merge, tag the merged commit with ` +
    `Stage 2:\n\n` +
    '```sh\n' +
    `npm run release:publish-tag -- ${version}\n` +
    '```\n\n' +
    `which pushes \`${tag}\` and lets the public Release workflow publish to npm.`;
  exec(
    'gh',
    [
      'pr',
      'create',
      '--repo',
      PUBLIC_REPO,
      '--base',
      baseBranch,
      '--head',
      branch,
      '--title',
      prTitle,
      '--body',
      prBody,
    ],
    { dryRun },
  );
} else {
  step('Next steps');
  info(`  Open a PR on ${PUBLIC_REPO} from "${branch}" into "${baseBranch}" (or re-run with --open-pr).`);
  info(`  After it merges, run Stage 2:  npm run release:publish-tag -- ${version}`);
}

step(dryRun ? 'Dry run complete. No changes were made.' : 'Stage 1 complete.');
