export { analyzeMessage } from "./analyze.js";
export { extractMetrics } from "./metrics.js";
export { normalizeHeaders } from "./normalizeHeaders.js";
export { parseAuthenticationResults } from "./parseAuthenticationResults.js";
export {
  extractDomainFromMailbox,
  extractDomainFromMessageId,
  extractDomainsFromMailboxList,
} from "./domains.js";
export {
  defaultRules,
  runRules,
  missingAuthResultsRule,
  untrustedAuthservIdRule,
  authMethodFailureRule,
  messageIdDomainMismatchRule,
  replyToDomainMismatchRule,
} from "./rules/index.js";
export type {
  AnalyzeInput,
  AnalyzeOptions,
  AnalyzeResult,
  AuthenticationMethodResult,
  AuthenticationResultsHeader,
  HeaderInput,
  HeaderLine,
  MessageMetrics,
  Rule,
  RuleContext,
  RuleScope,
  Signal,
  SignalSeverity,
} from "./types.js";
