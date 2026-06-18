export { analyzeMessage } from "./analyze.js";
export { collectAuthenticationAlignment, extractMetrics } from "./metrics.js";
export {
  computeDisplayNameWhitespace,
  computeDomainParts,
  computeLexicalHeuristics,
  computeLexicalStats,
  computeSenderIdentity,
} from "./senderIdentity.js";
export {
  defaultPublicMailboxProviders,
  lookupPublicMailboxProvider,
} from "./publicMailboxProviders.js";
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
  publicMailboxSpoofingCandidateRule,
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
  DisplayNameDerivedMetrics,
  DisplayNameMetrics,
  DisplayNameNormalization,
  DisplayNameSignals,
  DkimResult,
  DmarcResult,
  DomainParts,
  HeaderInput,
  HeaderLine,
  LexicalHeuristics,
  LexicalStats,
  MessageMetrics,
  MetricsDependencies,
  PublicMailboxProvider,
  SenderIdentityMetrics,
  SpfResult,
  Rule,
  RuleContext,
  RuleScope,
  Signal,
  SignalCategory,
  SignalSeverity,
} from "./types.js";
