import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { build } from "tsup";
import { BROWSER_ARTIFACT_FILENAME, browserBuildOptions } from "../tsup.browser.js";

// Rebuilds the exact browser bundling strategy declared in
// tsup.browser.config.ts (shared via tsup.browser.ts) into a scratch
// directory, so this test always exercises what actually ships rather than
// a hand-written approximation.
const outDir = mkdtempSync(join(tmpdir(), "mail-auth-signal-browser-"));
let artifactSource = "";
let artifactPath = "";

beforeAll(async () => {
  await build({ ...browserBuildOptions(outDir), silent: true, config: false });
  artifactPath = join(outDir, BROWSER_ARTIFACT_FILENAME);
  artifactSource = readFileSync(artifactPath, "utf8");
  // The artifact ships as plain ESM syntax in a ".js" file (browsers don't
  // care about the extension), but Node's own loader treats a bare ".js" as
  // CommonJS unless the nearest package.json declares "type": "module". Add
  // one here so the isolated-subprocess test below reflects how any
  // Node-based consumer would actually load this file, without changing the
  // shipped artifact itself.
  writeFileSync(join(outDir, "package.json"), JSON.stringify({ type: "module" }), "utf8");
}, 60_000);

afterAll(() => {
  rmSync(outDir, { recursive: true, force: true });
});

describe("browser artifact — no unresolved bare specifiers", () => {
  it("contains no bare (non-relative, non-URL) import/export specifiers", () => {
    // Anything that isn't relative (./, ../), absolute (/), or a URL scheme
    // (e.g. data:, node:) is a bare specifier a browser cannot resolve.
    // minify: false keeps source comments in the artifact (e.g. tldts-core's
    // "different from '-'"), which can otherwise look like a bare `from "x"`
    // specifier to a naive scan, so comments are stripped first.
    const withoutComments = artifactSource
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/\/\/.*$/gm, "");
    const specifierPatterns = [
      // Requires at least one space between `from` and the quote so this
      // doesn't false-positive on unrelated string/property-key content
      // like `properties["header.from"]` or `getFirstHeaderValue(headers,
      // "from")`, which have zero whitespace before the quote.
      /\bfrom\s+["']([^"']+)["']/g, // import ... from "x" / export ... from "x"
      /\bimport\s*\(\s*["']([^"']+)["']/g, // dynamic import("x")
      /^\s*import\s*["']([^"']+)["']/gm, // bare side-effect import "x"
    ];
    const bareSpecifiers: string[] = [];
    for (const pattern of specifierPatterns) {
      for (const match of withoutComments.matchAll(pattern)) {
        const specifier = match[1];
        if (specifier === undefined) {
          continue;
        }
        if (!/^(\.|\/|[a-z]+:)/i.test(specifier)) {
          bareSpecifiers.push(specifier);
        }
      }
    }
    expect(bareSpecifiers).toEqual([]);
    // In particular, the reported bare `tldts` import must be gone.
    expect(artifactSource).not.toMatch(/from\s*["']tldts(-core)?["']/);
  });

  it("loads and runs from a directory with no node_modules ancestor (no Node bare-specifier resolution)", () => {
    // os.tmpdir() sits outside this repo's node_modules tree, so importing
    // from here fails with ERR_MODULE_NOT_FOUND if the artifact still depends
    // on Node resolving a bare "tldts" specifier. Run this in a real `node`
    // subprocess (rather than a dynamic `import()` here) so it exercises
    // Node's own ESM resolution instead of Vitest's Vite-based module loader,
    // which cannot load arbitrary files outside its module graph.
    const runnerPath = join(outDir, "run-isolated.mjs");
    writeFileSync(
      runnerPath,
      `
      import { pathToFileURL } from "node:url";
      const mod = await import(pathToFileURL(${JSON.stringify(artifactPath)}).href);
      const domain = mod.defaultGetRegistrableDomain("mail.example.co.jp");
      if (domain !== "example.co.jp") {
        throw new Error("unexpected registrable domain: " + domain);
      }
      const result = mod.analyzeMessage({
        headers: { from: "Test <user@mail.example.com>" },
      });
      if (!result.metrics.senderIdentity) {
        throw new Error("missing senderIdentity in analyzeMessage result");
      }
      const naturalness = mod.computeRegistrableLabelNaturalness("dessert.axgporj.com", {
        scoreLabelNaturalness: () => 5.582,
      });
      if (naturalness.label !== "axgporj" || naturalness.score !== 5.582) {
        throw new Error("unexpected label naturalness: " + JSON.stringify(naturalness));
      }
      `,
      "utf8",
    );

    // Exercises the bundled tldts/PSL data end-to-end, not just its presence.
    expect(() => execFileSync(process.execPath, [runnerPath], { encoding: "utf8" })).not.toThrow();
  });
});
