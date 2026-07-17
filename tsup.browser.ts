import type { Options } from "tsup";

/**
 * Shared with tsup.browser.config.ts (the real published build) and
 * test/browserArtifact.test.ts (which rebuilds into a scratch directory to
 * verify the artifact resolves with no bare module specifiers). Keeping one
 * definition means the test always exercises the exact bundling strategy
 * that ships.
 */
export function browserBuildOptions(outDir: string): Options {
  return {
    entry: { "mail-auth-signal.esm": "src/index.ts" },
    format: ["esm"],
    dts: false,
    clean: true,
    outDir,
    platform: "browser",
    target: "es2020",
    splitting: false,
    minify: false,
    sourcemap: false,
    noExternal: ["tldts", "tldts-core"],
  };
}

export const BROWSER_ARTIFACT_FILENAME = "mail-auth-signal.esm.js";
