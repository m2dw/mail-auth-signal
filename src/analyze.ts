import { extractMetrics } from "./metrics.js";
import { defaultRules, runRules } from "./rules/index.js";
import type { AnalyzeInput, AnalyzeResult, Rule } from "./types.js";

/**
 * Analyze a single message: extract serializable metrics, then evaluate rules.
 *
 * The pipeline is intentionally two separable halves — extractMetrics (parsing
 * + facts) and runRules (interpretation) — so rule migration can proceed one
 * rule at a time against stable types.
 *
 * Rules are code, not data, so they arrive as a second argument rather than
 * inside the JSON-serializable AnalyzeInput. Callers may pass a narrowed or
 * extended rule set; omitting it uses defaultRules.
 *
 * The result never contains an allow/block/move/notify decision or a score;
 * thresholds and policy belong entirely to the caller.
 */
export function analyzeMessage(input: AnalyzeInput, rules: readonly Rule[] = defaultRules): AnalyzeResult {
  const metrics = extractMetrics(input);
  const signals = runRules(metrics, input.options ?? {}, rules);
  return { metrics, signals };
}
