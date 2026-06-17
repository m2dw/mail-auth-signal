export { analyzeMessage } from "./analyze.js";
export { normalizeHeaders } from "./normalizeHeaders.js";
export { parseAuthenticationResults } from "./parseAuthenticationResults.js";
export { extractDomainFromMailbox, extractDomainFromMessageId } from "./domains.js";
export type {
  AnalyzeInput,
  AnalyzeOptions,
  AnalyzeResult,
  AuthenticationMethodResult,
  AuthenticationResultsHeader,
  HeaderInput,
  HeaderLine,
  MessageMetrics,
  Signal,
  SignalSeverity,
} from "./types.js";

