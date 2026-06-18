export { analyzeMessage } from "./analyze.js";
export { collectAuthenticationAlignment, extractMetrics } from "./metrics.js";
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
  AuthenticationAlignment,
  AuthenticationMethodResult,
  AuthenticationResultsHeader,
  DkimResult,
  DmarcResult,
  HeaderInput,
  HeaderLine,
  MessageMetrics,
  SpfResult,
  Rule,
  RuleContext,
  RuleScope,
  Signal,
  SignalCategory,
  SignalSeverity,
} from "./types.js";
