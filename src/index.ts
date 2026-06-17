export { analyzeMessage } from "./analyze.js";
export { extractMetrics } from "./metrics.js";
export { normalizeHeaders } from "./normalizeHeaders.js";
export { parseAuthenticationResults } from "./parseAuthenticationResults.js";
export {
  extractDkimSigningDomain,
  extractDmarcHeaderFromDomain,
  extractDomainFromMailbox,
  extractDomainFromMessageId,
  extractDomainsFromMailboxList,
  extractEnvelopeSenderDomain,
  isNullReversePath,
} from "./domains.js";
export {
  defaultRules,
  runRules,
  missingAuthResultsRule,
  untrustedAuthservIdRule,
  authMethodFailureRule,
  messageIdDomainMismatchRule,
  replyToDomainMismatchRule,
  returnPathDomainMismatchRule,
  smtpMailfromDomainMismatchRule,
  dkimDomainMismatchRule,
  dmarcHeaderFromMismatchRule,
  envelopeSenderDisagreementRule,
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
  SignalCategory,
  SignalSeverity,
} from "./types.js";
