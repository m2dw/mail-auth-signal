import { extractMetrics } from "./metrics.js";
import { defaultRules, runRules } from "./rules/index.js";
import { runCompositeRules } from "./rules/composite/index.js";
import type {
  AnalyzeInput,
  AnalyzeResult,
  CompositeRule,
  MetricsDependencies,
  Rule,
} from "./types.js";

/**
 * Analyze a single message: extract serializable metrics, then evaluate rules.
 *
 * The pipeline is intentionally separable halves — extractMetrics (parsing +
 * facts), runRules (per-metric interpretation), and an optional composite
 * (Layer 4) layer — so rule migration can proceed one rule at a time against
 * stable types.
 *
 * Rules are code, not data, so they arrive as a second argument rather than
 * inside the JSON-serializable AnalyzeInput. Callers may pass a narrowed or
 * extended rule set; omitting it uses defaultRules.
 *
 * Non-serializable runtime dependencies (e.g. a custom Public Suffix List
 * resolver) arrive as the optional third argument, also kept out of the
 * serializable AnalyzeInput. Structural domain parts (fromDomainParts,
 * messageIdDomainParts) use the built-in tldts resolver by default; equality
 * comparisons (messageIdRegistrableDomainMatchesFromDomain) and provider
 * subdomain lookup require an explicit `getRegistrableDomain` in deps. Pass
 * `getRegistrableDomain: () => null` to opt out of PSL resolution entirely.
 *
 * Composite rules arrive as the optional fourth argument and default to none, so
 * the base output stays unchanged unless a caller opts in (e.g. by passing
 * defaultCompositeRules). When supplied, each composite is evaluated over the
 * metrics plus the base signals just produced, and its signals are appended after
 * them — base observations first, then the cross-cutting composites derived from
 * them.
 *
 * The result never contains an allow/block/move/notify decision or a score;
 * thresholds and policy belong entirely to the caller.
 */
export function analyzeMessage(
  input: AnalyzeInput,
  rules: readonly Rule[] = defaultRules,
  deps?: MetricsDependencies,
  compositeRules: readonly CompositeRule[] = [],
): AnalyzeResult {
  const options = input.options ?? {};
  const metrics = extractMetrics(input, deps);
  const signals = runRules(metrics, options, rules, deps);
  if (compositeRules.length > 0) {
    signals.push(...runCompositeRules(metrics, signals, options, compositeRules, deps));
  }
  return { metrics, signals };
}
