export { analyzeMessage } from "./analyze.js";
export { computeJaro, computeJaroWinkler } from "./jaroWinkler.js";
export { collectAuthenticationAlignment, extractMetrics } from "./metrics.js";
export {
  computeDomainParts,
  computeLexicalHeuristics,
  computeLexicalStats,
  computeSenderIdentity,
} from "./senderIdentity.js";
export { normalizeHeaders } from "./normalizeHeaders.js";
export { parseAuthenticationResults } from "./parseAuthenticationResults.js";
export {
  extractDkimSigningDomain,
  extractDmarcHeaderFromDomain,
  extractDomainFromMailbox,
  extractDomainFromMessageId,
  extractDomainsFromMailboxList,
  extractEmbeddedDomains,
  extractEnvelopeSenderDomain,
  isNullReversePath,
  parseFromMailbox,
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
export {
  defaultCompositeRules,
  runCompositeRules,
  unauthenticatedFromSpoofRule,
  authenticatedDisplayNameSpoofRule,
  alignedAuthenticationConfirmedRule,
} from "./rules/composite/index.js";
export type {
  AnalyzeInput,
  AnalyzeOptions,
  AnalyzeResult,
  AuthenticationAlignment,
  CompositeRule,
  CompositeRuleContext,
  AuthenticationMethodResult,
  AuthenticationResultsHeader,
  DisplayNameMetrics,
  DkimResult,
  DmarcResult,
  DomainParts,
  HeaderInput,
  HeaderLine,
  LexicalHeuristics,
  LexicalStats,
  MessageMetrics,
  MetricsDependencies,
  SenderIdentityMetrics,
  SpfResult,
  Rule,
  RuleContext,
  RuleScope,
  Signal,
  SignalCategory,
  SignalSeverity,
} from "./types.js";
