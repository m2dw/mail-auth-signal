// Shared helpers for the two-stage public release flow.
//
// Stage 1 (`release-promote.mjs`) copies the final private development tree onto
// the public repository as a single squash commit. Stage 2
// (`release-publish-tag.mjs`) tags the merged public commit so the public
// `Release` workflow publishes to npm.
//
// These are maintainer operational scripts, not part of the published library,
// so they live outside `src/` and stay dependency-free (plain Node + git/gh).

import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { readFileSync } from 'node:fs';

// The one and only repository the public release flow is allowed to touch.
export const PUBLIC_REPO = 'm2dw/mail-auth-signal';

// Default name of the git remote that must point at the public repository.
export const DEFAULT_PUBLIC_REMOTE = 'public';

// Default branch on the public repository that release branches build on top of.
export const DEFAULT_PUBLIC_BASE = 'main';

// Paths that are private-only and must never reach the public tree. This must
// cover every tracked private-only path, not just gitignored state, because
// Stage 1 promotes the rest of HEAD verbatim:
//   - `.n8n-artifacts/` is gitignored local workflow state (belt-and-braces).
//   - `AGENTS.md` / `CLAUDE.md` are AI/automation workflow docs that contain
//     local absolute paths and n8n orchestration internals, so they are
//     development-only and must not appear in the public release tree.
export const PRIVATE_PATHS = ['.n8n-artifacts', 'AGENTS.md', 'CLAUDE.md'];

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = resolve(SCRIPT_DIR, '..', '..');

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

export function info(message) {
  process.stdout.write(`${message}\n`);
}

export function step(message) {
  process.stdout.write(`\n› ${message}\n`);
}

export function warn(message) {
  process.stderr.write(`warning: ${message}\n`);
}

export function fail(message) {
  process.stderr.write(`error: ${message}\n`);
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Command execution
// ---------------------------------------------------------------------------

// Run a command and return trimmed stdout. Throws (via fail) on a non-zero exit.
export function run(cmd, args, opts = {}) {
  const result = spawnSync(cmd, args, {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    ...opts,
  });
  if (result.error) {
    fail(`failed to run \`${cmd} ${args.join(' ')}\`: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const stderr = (result.stderr || '').trim();
    fail(`command failed (\`${cmd} ${args.join(' ')}\`): ${stderr || `exit ${result.status}`}`);
  }
  return (result.stdout || '').trim();
}

// Run a command without throwing. Returns { status, stdout, stderr }.
export function tryRun(cmd, args, opts = {}) {
  const result = spawnSync(cmd, args, {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    ...opts,
  });
  return {
    status: result.status,
    stdout: (result.stdout || '').trim(),
    stderr: (result.stderr || '').trim(),
  };
}

// Echo a command and run it, inheriting stdio so the operator sees live output.
// In dry-run mode the command is printed but not executed.
export function exec(cmd, args, { dryRun = false } = {}) {
  const pretty = `${cmd} ${args.join(' ')}`.trim();
  if (dryRun) {
    info(`  [dry-run] would run: ${pretty}`);
    return;
  }
  info(`  + ${pretty}`);
  const result = spawnSync(cmd, args, { cwd: REPO_ROOT, stdio: 'inherit' });
  if (result.status !== 0) {
    fail(`command failed (\`${pretty}\`): exit ${result.status}`);
  }
}

// Like `exec`, but returns the exit status instead of aborting on failure so the
// caller can clean up (e.g. remove a just-created tag) before deciding how to
// fail. Still echoes the command and inherits stdio. In dry-run mode nothing
// runs and 0 is returned.
export function execTry(cmd, args, { dryRun = false } = {}) {
  const pretty = `${cmd} ${args.join(' ')}`.trim();
  if (dryRun) {
    info(`  [dry-run] would run: ${pretty}`);
    return 0;
  }
  info(`  + ${pretty}`);
  const result = spawnSync(cmd, args, { cwd: REPO_ROOT, stdio: 'inherit' });
  return result.status ?? 1;
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

// Parse `npm run <script> -- <version> [flags]`. Returns { version, flags }.
// `flags` is a plain object: --dry-run -> { 'dry-run': true },
// --remote upstream -> { remote: 'upstream' }.
export function parseArgs(argv, { booleanFlags = [], valueFlags = [] } = {}) {
  const flags = {};
  const positionals = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    // A bare `--` is an argument separator (e.g. an extra one forwarded by
    // `npm run ... -- ... -- ...`). Ignore it rather than treating it as a flag.
    if (arg === '--') {
      continue;
    }
    if (!arg.startsWith('--')) {
      positionals.push(arg);
      continue;
    }
    const name = arg.slice(2);
    if (booleanFlags.includes(name)) {
      flags[name] = true;
    } else if (valueFlags.includes(name)) {
      const value = argv[i + 1];
      if (value === undefined || value.startsWith('--')) {
        fail(`flag --${name} requires a value`);
      }
      flags[name] = value;
      i += 1;
    } else if (name.includes('=')) {
      const [key, value] = name.split(/=(.*)/s);
      if (booleanFlags.includes(key)) {
        // Boolean flags only accept explicit `true`/`false` in `=` form so
        // that `--force=false` disables rather than silently enabling force.
        if (value === 'true') {
          flags[key] = true;
        } else if (value === 'false') {
          flags[key] = false;
        } else {
          fail(`boolean flag --${key} only accepts "true" or "false" (got "${value}")`);
        }
      } else if (valueFlags.includes(key)) {
        flags[key] = value;
      } else {
        fail(`unknown flag: --${key}`);
      }
    } else {
      fail(`unknown flag: --${name}`);
    }
  }
  return { version: positionals[0], positionals, flags };
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

const SEMVER_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

// Require a bare `X.Y.Z` version argument (no leading `v`).
export function requireVersionArg(version) {
  if (!version) {
    fail('missing version argument (expected, e.g., `0.5.0`)');
  }
  if (version.startsWith('v')) {
    fail(`pass the version without a leading "v" (got "${version}", expected "${version.slice(1)}")`);
  }
  if (!SEMVER_RE.test(version)) {
    fail(`version "${version}" is not a valid X.Y.Z semver`);
  }
  return version;
}

// Read the `version` field from the working-tree package.json.
export function readPackageVersion() {
  const raw = readFileSync(resolve(REPO_ROOT, 'package.json'), 'utf8');
  return JSON.parse(raw).version;
}

// Extract `owner/repo` from any common git remote URL form, or null.
//
// The host is parsed and validated explicitly rather than matched anywhere in
// the string: a URL like `ssh://git@example.com/github.com/m2dw/mail-auth-signal`
// is NOT on GitHub even though `github.com` appears in its path, and accepting
// its slug would let a release be pushed to an attacker-controlled host. This is
// the safety check guarding the public push target, so it must only accept a
// slug when the actual host is `github.com`.
export function parseRepoSlug(url) {
  const cleaned = url.trim().replace(/\.git$/, '');

  let host;
  let path;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(cleaned)) {
    // Scheme-based URL: ssh://, https://, git://, etc.
    let parsed;
    try {
      parsed = new URL(cleaned);
    } catch {
      return null;
    }
    host = parsed.hostname;
    path = parsed.pathname;
  } else {
    // scp-style `[user@]host:path` (no scheme; host has no slash).
    const scp = cleaned.match(/^(?:[^@/]+@)?([^/:]+):(.+)$/);
    if (!scp) return null;
    host = scp[1];
    path = scp[2];
  }

  if (host.toLowerCase() !== 'github.com') return null;

  const segments = path.split('/').filter(Boolean);
  if (segments.length < 2) return null;
  const [owner, repo] = segments.slice(-2);
  return `${owner}/${repo}`;
}

// Resolve and validate the public remote. Refuses if the remote is missing or
// points anywhere other than the canonical public repository — this is the
// guard that prevents ever pushing a release to the private repo by mistake.
export function resolvePublicRemote(remoteName) {
  const fetch = tryRun('git', ['remote', 'get-url', '--all', remoteName]);
  if (fetch.status !== 0 || !fetch.stdout) {
    fail(
      `public remote "${remoteName}" is not configured.\n` +
        `  Add it with:\n` +
        `    git remote add ${remoteName} git@github.com:${PUBLIC_REPO}.git`,
    );
  }

  // `git push <remote>` writes to the push URL, which can differ from the fetch
  // URL when a separate `remote.<name>.pushurl` is set. Validating only the
  // fetch URL would let a stale/mistaken push URL slip a release onto the wrong
  // repository, so validate every fetch AND push URL the remote can resolve to.
  // `--push` falls back to the fetch URL when no pushurl is configured.
  const push = tryRun('git', ['remote', 'get-url', '--push', '--all', remoteName]);
  const pushUrls = (push.status === 0 ? push.stdout : '').split('\n').map((u) => u.trim()).filter(Boolean);
  const fetchUrls = fetch.stdout.split('\n').map((u) => u.trim()).filter(Boolean);

  for (const url of [...fetchUrls, ...pushUrls]) {
    const slug = parseRepoSlug(url);
    if (slug !== PUBLIC_REPO) {
      fail(
        `public remote "${remoteName}" resolves to "${slug ?? url}", not "${PUBLIC_REPO}".\n` +
          `  (checked both fetch and push URLs)\n` +
          `  Refusing to run the public release flow against the wrong repository.`,
      );
    }
  }

  // Report the push URL as canonical since that is where writes land.
  return { name: remoteName, url: pushUrls[0] ?? fetchUrls[0], slug: PUBLIC_REPO };
}

// Refuse to run with uncommitted changes unless dry-run is set. A promotion
// copies the committed HEAD tree, so a dirty tree means the operator's intent
// is ambiguous.
export function assertCleanWorktree(dryRun) {
  const { stdout } = tryRun('git', ['status', '--porcelain']);
  if (stdout) {
    if (dryRun) {
      warn('working tree is dirty; continuing because --dry-run is set.');
      return;
    }
    fail(
      'working tree is dirty. Commit or stash changes first, or re-run with --dry-run.\n' +
        `  Uncommitted paths:\n${stdout.split('\n').map((l) => `    ${l}`).join('\n')}`,
    );
  }
}

// True if `ref` (e.g. `refs/heads/release/v0.5.0` or `refs/tags/v0.5.0`) exists
// on the given remote.
export function remoteRefExists(remoteName, ref) {
  const { stdout } = tryRun('git', ['ls-remote', remoteName, ref]);
  return stdout.length > 0;
}

// Return the object id `ref` currently points at on the remote, or null if it
// does not exist. Used to build an explicit `--force-with-lease=<ref>:<oid>`
// that works even in clones with no local remote-tracking ref for `ref`.
export function remoteRefOid(remoteName, ref) {
  const { stdout } = tryRun('git', ['ls-remote', remoteName, ref]);
  if (!stdout) return null;
  // `ls-remote` lines are "<oid>\t<ref>"; take the first line's oid.
  return stdout.split('\n')[0].split(/\s+/)[0] || null;
}
