/**
 * score-stdin.mjs — caller-side scoring example for mail-auth-signal.
 *
 * Reads a raw email from stdin, parses its headers, runs analyzeMessage,
 * and prints a JSON result that includes an example numeric score.
 *
 * Usage:
 *   cat sample.eml | node examples/score-stdin.mjs
 *   cat sample.eml | node examples/score-stdin.mjs --trusted mx.example.net
 *
 * The score and severity weights below are an EXAMPLE CALLER POLICY.
 * The mail-auth-signal library deliberately does not produce a score —
 * thresholds, weights, and allow/block decisions belong to the caller.
 */

import { createInterface } from "readline";

// When run from the repo, resolve through the built dist. When consumed as an
// installed package the "mail-auth-signal" specifier works directly, but inside
// the repo it resolves through package.json exports to ./dist/index.js which
// requires `npm run build` first.
let analyzeMessage;
try {
  ({ analyzeMessage } = await import("../dist/index.js"));
} catch {
  // Fallback: package installed as a dependency (e.g. in a consumer project).
  ({ analyzeMessage } = await import("mail-auth-signal"));
}

// ---------------------------------------------------------------------------
// Example caller policy — weights are yours to adjust.
// ---------------------------------------------------------------------------
const SEVERITY_WEIGHT = { info: 0, low: 1, medium: 3, high: 8 };

// ---------------------------------------------------------------------------
// CLI: collect --trusted <id> flags
// ---------------------------------------------------------------------------
const trustedAuthservIds = [];
for (let i = 2; i < process.argv.length; i++) {
  if (process.argv[i] === "--trusted" && process.argv[i + 1]) {
    trustedAuthservIds.push(process.argv[++i]);
  }
}

// ---------------------------------------------------------------------------
// Read stdin
// ---------------------------------------------------------------------------
const lines = [];
const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of rl) {
  lines.push(line);
}

// ---------------------------------------------------------------------------
// Split at the first blank line to isolate the header block.
// The body is intentionally ignored — this is a header-analysis example.
// ---------------------------------------------------------------------------
const blankIndex = lines.findIndex((l) => l.trim() === "");
const headerLines = blankIndex === -1 ? lines : lines.slice(0, blankIndex);

// ---------------------------------------------------------------------------
// Unfold RFC 5322 header continuation lines, then parse into HeaderInput.
// A continuation line starts with horizontal whitespace (SP or HT).
// ---------------------------------------------------------------------------
const unfoldedHeaders = [];
for (const line of headerLines) {
  if (/^[ \t]/.test(line) && unfoldedHeaders.length > 0) {
    unfoldedHeaders[unfoldedHeaders.length - 1] += " " + line.trim();
  } else {
    unfoldedHeaders.push(line);
  }
}

/** @type {Array<{name: string, value: string}>} */
const headers = [];
for (const line of unfoldedHeaders) {
  const colon = line.indexOf(":");
  if (colon === -1) continue;
  headers.push({
    name: line.slice(0, colon).trim().toLowerCase(),
    value: line.slice(colon + 1).trim(),
  });
}

// ---------------------------------------------------------------------------
// Analyze
// ---------------------------------------------------------------------------
const result = analyzeMessage(
  { headers, options: { trustedAuthservIds } },
);

// ---------------------------------------------------------------------------
// Score — example caller policy, not a library standard.
// ---------------------------------------------------------------------------
const severityCounts = { info: 0, low: 0, medium: 0, high: 0 };
let score = 0;
for (const signal of result.signals) {
  const sev = signal.severity;
  severityCounts[sev] = (severityCounts[sev] ?? 0) + 1;
  score += SEVERITY_WEIGHT[sev] ?? 0;
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------
console.log(
  JSON.stringify(
    {
      // NOTE: This score is an example caller policy — not a library standard.
      // Weights: info=0, low=1, medium=3, high=8
      score,
      severityCounts,
      signals: result.signals,
      metrics: result.metrics,
    },
    null,
    2,
  ),
);
