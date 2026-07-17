import { defineConfig } from "tsup";
import { browserBuildOptions } from "./tsup.browser.js";

// Browser/Thunderbird-vendorable artifact: a single ESM file with the
// `tldts` (and `tldts-core`) dependency graph inlined, so it has no bare
// module specifiers left to resolve. Consumers that cannot use import maps
// (e.g. Thunderbird 102-107 add-ons) can copy this file byte-for-byte. See
// README.md "Browser / Thunderbird vendoring" for usage and NOTICE for the
// bundled tldts/Public Suffix List attribution.
//
// Kept in a separate config file (run after tsup.node.config.ts, not as a
// second entry in the same config array) because tsup runs array entries
// concurrently — that would race this build's own `dist/browser` clean
// against the node build's `clean: true` wipe of the whole `dist` directory.
export default defineConfig(browserBuildOptions("dist/browser"));
