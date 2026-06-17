import type { MessageMetrics, AnalyzeOptions, Rule, Signal } from "../types.js";
import { missingAuthResultsRule } from "./missingAuthResults.js";
import { untrustedAuthservIdRule } from "./untrustedAuthservId.js";
import { authMethodFailureRule } from "./authMethodFailure.js";
import { messageIdDomainMismatchRule } from "./messageIdDomainMismatch.js";

export { missingAuthResultsRule } from "./missingAuthResults.js";
export { untrustedAuthservIdRule } from "./untrustedAuthservId.js";
export { authMethodFailureRule } from "./authMethodFailure.js";
export { messageIdDomainMismatchRule } from "./messageIdDomainMismatch.js";

/**
 * The built-in rule set, applied in order by analyzeMessage.
 *
 * This array is the migration surface: follow-up issues add a migrated rule by
 * appending its Rule here (or compose their own set and pass it to
 * analyzeMessage / runRules). Order is stable but carries no policy meaning —
 * signals are observations, not a ranked verdict.
 */
export const defaultRules: readonly Rule[] = [
  missingAuthResultsRule,
  untrustedAuthservIdRule,
  authMethodFailureRule,
  messageIdDomainMismatchRule,
];

/**
 * Run a rule set against already-extracted metrics.
 *
 * Exposed so callers can evaluate rules over metrics they extracted (and
 * possibly cached or transported) without re-parsing headers, keeping metric
 * extraction and rule evaluation independently composable.
 */
export function runRules(
  metrics: MessageMetrics,
  options: AnalyzeOptions = {},
  rules: readonly Rule[] = defaultRules,
): Signal[] {
  return rules.flatMap((rule) => rule.evaluate({ metrics, options }));
}
