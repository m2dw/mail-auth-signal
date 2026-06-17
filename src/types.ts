export type HeaderLine = {
  name: string;
  value: string;
};

export type HeaderInput = HeaderLine[] | Record<string, string | string[] | undefined>;

export type AuthenticationMethodResult = {
  method: string;
  result: string;
  properties: Record<string, string>;
};

export type AuthenticationResultsHeader = {
  raw: string;
  authservId: string;
  /** True when authservId appears in AnalyzeOptions.trustedAuthservIds. */
  trusted: boolean;
  methods: AuthenticationMethodResult[];
};

export type SignalSeverity = "info" | "low" | "medium" | "high";

/**
 * A keyed, severity-tagged observation produced by the core.
 *
 * Callers are responsible for deciding what to do with signals — thresholds,
 * UI presentation, notifications, mailbox actions, and allow/block policy all
 * belong outside this library.
 */
export type Signal = {
  key: string;
  severity: SignalSeverity;
  message: string;
  data?: Record<string, unknown>;
};

/**
 * Extracted facts about a single message. All values are serializable so they
 * can be logged, written to fixtures, or sent across process boundaries.
 */
export type MessageMetrics = {
  fromDomain: string | null;
  messageIdDomain: string | null;
  messageIdDomainMatchesFromDomain: boolean | null;
  authenticationResults: AuthenticationResultsHeader[];
};

/**
 * Caller-provided context that configures the analysis.
 *
 * This is the single entry point for external configuration. The core never
 * reads from the environment, network, storage, or any global state — all
 * context must arrive here so the function stays pure and testable.
 *
 * - trustedAuthservIds: the authserv-ids the caller's mail system stamps on
 *   inbound messages. Only headers from these ids are treated as authoritative.
 *   Callers are responsible for maintaining this list; the core has no opinion
 *   on which ids are trustworthy.
 *
 * - context: an open-ended bag for future caller-provided policy context
 *   (e.g. per-sender overrides, allow-listed domains, caller version metadata).
 *   Values must remain serializable. The core currently ignores this field;
 *   rule implementations may read it once the migration from the Thunderbird
 *   add-on is underway.
 */
export type AnalyzeOptions = {
  trustedAuthservIds?: string[];
  context?: Record<string, unknown>;
};

/**
 * Input envelope for analyzeMessage.
 *
 * Boundary contract:
 *   - headers supplies the raw message headers, in any of the supported formats.
 *   - options carries the caller's environmental context (see AnalyzeOptions).
 *   - No other runtime state — no globals, no singletons, no I/O — may be used
 *     by the core. New rules must accept any additional context via options.
 */
export type AnalyzeInput = {
  headers: HeaderInput;
  options?: AnalyzeOptions;
};

/**
 * Return value of analyzeMessage.
 *
 * Boundary contract:
 *   - metrics contains extracted facts with no interpretation applied.
 *   - signals contains keyed observations the caller may act on.
 *   - The core never returns an allow/block/move/notify decision; that policy
 *     layer belongs entirely to the caller.
 *   - All fields are JSON-serializable for logging, test fixtures, and
 *     cross-language comparison.
 */
export type AnalyzeResult = {
  metrics: MessageMetrics;
  signals: Signal[];
};
