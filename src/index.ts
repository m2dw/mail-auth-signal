export { analyzeMessage } from "./analyze.js";
export { getRegistrableDomain as defaultGetRegistrableDomain } from "./psl.js";
export { computeJaro, computeJaroWinkler } from "./jaroWinkler.js";
export { computeJaccard } from "./jaccard.js";
export {
  BRAND_LIKE_MIN_LETTERS,
  BRAND_LIKE_MIN_LETTER_RATIO,
  BRAND_MATCH_MIN_JACCARD,
  BRAND_MATCH_MIN_JARO_WINKLER,
  computeDisplayNameBrandInference,
  foldLatinDiacritics,
  normalizeBrandToken,
} from "./brandInference.js";
export { collectAuthenticationAlignment, extractMetrics } from "./metrics.js";
export {
  computeDisplayNameWhitespace,
  computeDomainParts,
  computeLexicalHeuristics,
  computeLexicalStats,
  computeRandomLookingCandidate,
  computeSenderIdentity,
} from "./senderIdentity.js";
export type { RandomLookingOptions } from "./senderIdentity.js";
export {
  defaultPublicMailboxProviders,
  lookupPublicMailboxProvider,
} from "./publicMailboxProviders.js";
export { normalizeHeaders } from "./normalizeHeaders.js";
export { parseAuthenticationResults } from "./parseAuthenticationResults.js";
export {
  allDomainsOrganizationallyAlign,
  allRegistrableDomainsMatch,
  domainsOrganizationallyAlign,
  extractDkimSigningDomain,
  extractDmarcHeaderFromDomain,
  extractDomainFromMailbox,
  extractDomainFromMessageId,
  extractDomainsFromMailboxList,
  extractEmbeddedDomains,
  extractEnvelopeSenderDomain,
  isNullReversePath,
  parseFromMailbox,
  registrableDomainOrSelf,
  registrableDomainsMatch,
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
  displayNameBrandDomainMismatchRule,
} from "./rules/index.js";
export {
  defaultCompositeRules,
  runCompositeRules,
  unauthenticatedFromSpoofRule,
  publicMailboxSpoofingCandidateRule,
  authenticatedDisplayNameSpoofRule,
  unsecuredDeepSubdomainCandidateRule,
  deepRandomFromSubdomainRule,
  brandDivergencePhishingRule,
  ownDomainSpoofCandidateRule,
  OWN_ACCOUNT_DOMAINS_CONTEXT_KEY,
  dkimFailWithAlignedPassRule,
  dkimAlignedLexicalMitigationRule,
  alignedAuthenticationConfirmedRule,
} from "./rules/composite/index.js";
export type {
  AnalyzeInput,
  AnalyzeOptions,
  AnalyzeResult,
  AuthenticationAlignment,
  BrandCatalogEntry,
  BrandInferenceNotApplicableReason,
  BrandMatch,
  CompositeRule,
  CompositeRuleContext,
  AuthenticationMethodResult,
  AuthenticationResultsHeader,
  DisplayNameBrandInference,
  DisplayNameDerivedMetrics,
  DisplayNameMetrics,
  DisplayNameNormalization,
  DisplayNameSignals,
  DkimResult,
  DmarcResult,
  DomainLabelMetrics,
  DomainParts,
  HeaderInput,
  HeaderLine,
  LexicalHeuristics,
  LexicalStats,
  MessageMetrics,
  MetricsDependencies,
  OrganizationalAlignment,
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
