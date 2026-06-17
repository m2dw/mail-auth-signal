import type { AuthenticationResultsHeader, MessageMetrics, AnalyzeOptions, Rule, Signal } from "../types.js";
import { missingAuthResultsRule } from "./missingAuthResults.js";
import { untrustedAuthservIdRule } from "./untrustedAuthservId.js";
import { authMethodFailureRule } from "./authMethodFailure.js";
import { messageIdDomainMismatchRule } from "./messageIdDomainMismatch.js";
import { replyToDomainMismatchRule } from "./replyToDomainMismatch.js";
import { returnPathDomainMismatchRule } from "./returnPathDomainMismatch.js";
import { smtpMailfromDomainMismatchRule } from "./smtpMailfromDomainMismatch.js";
import { envelopeSenderDisagreementRule } from "./envelopeSenderDisagreement.js";

export { missingAuthResultsRule } from "./missingAuthResults.js";
export { untrustedAuthservIdRule } from "./untrustedAuthservId.js";
export { authMethodFailureRule } from "./authMethodFailure.js";
export { messageIdDomainMismatchRule } from "./messageIdDomainMismatch.js";
export { replyToDomainMismatchRule } from "./replyToDomainMismatch.js";
export { returnPathDomainMismatchRule } from "./returnPathDomainMismatch.js";
export { smtpMailfromDomainMismatchRule } from "./smtpMailfromDomainMismatch.js";
export { envelopeSenderDisagreementRule } from "./envelopeSenderDisagreement.js";

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
  replyToDomainMismatchRule,
  returnPathDomainMismatchRule,
  smtpMailfromDomainMismatchRule,
  envelopeSenderDisagreementRule,
];

/**
 * Run a rule set against already-extracted metrics.
 *
 * Exposed so callers can evaluate rules over metrics they extracted (and
 * possibly cached or transported) without re-parsing headers, keeping metric
 * extraction and rule evaluation independently composable.
 *
 * Message-scoped rules (the default) are evaluated once against the whole
 * metrics object, in array order. A consecutive run of header-scoped rules is
 * instead evaluated header-by-header — for each Authentication-Results header,
 * every rule in the run runs against metrics narrowed to that one header — so
 * the signals for one header stay grouped together. This preserves the
 * per-header ordering a single combined loop produced: for two headers, the
 * first header's failure signals precede the second header's untrusted signal,
 * rather than all untrusted signals being grouped ahead of all failure signals.
 */
export function runRules(
  metrics: MessageMetrics,
  options: AnalyzeOptions = {},
  rules: readonly Rule[] = defaultRules,
): Signal[] {
  const signals: Signal[] = [];

  for (let i = 0; i < rules.length; ) {
    const rule = rules[i];
    if (rule === undefined) {
      i += 1;
      continue;
    }
    if (rule.scope !== "header") {
      signals.push(...rule.evaluate({ metrics, options }));
      i += 1;
      continue;
    }

    // Collect the consecutive run of header-scoped rules and evaluate them
    // header-by-header so each header's signals stay contiguous.
    let end = i;
    while (end < rules.length && rules[end]?.scope === "header") end += 1;
    const headerRules = rules.slice(i, end);

    for (const header of metrics.authenticationResults) {
      const headerMetrics = headerScopedMetrics(metrics, header);
      for (const rule of headerRules) {
        signals.push(...rule.evaluate({ metrics: headerMetrics, options }));
      }
    }

    i = end;
  }

  return signals;
}

/**
 * Narrow metrics to a single Authentication-Results header for header-scoped
 * rule evaluation. All other facts are preserved so header-scoped rules can
 * still read message-level metrics (e.g. fromDomain) if they need to.
 */
function headerScopedMetrics(
  metrics: MessageMetrics,
  header: AuthenticationResultsHeader,
): MessageMetrics {
  return { ...metrics, authenticationResults: [header] };
}
