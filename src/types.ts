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
  /**
   * Every resolvable, normalized domain parsed from the Reply-To header(s), in
   * encounter order and deduplicated. Empty when Reply-To is absent or no
   * mailbox in it yields a real dotted domain.
   */
  replyToDomains: string[];
  /**
   * Whether all replyToDomains exactly match fromDomain. null when no
   * comparison was possible (missing From, or no Reply-To domain), so a missing
   * Reply-To never reads as a mismatch. false when any Reply-To domain differs.
   */
  replyToDomainMatchesFromDomain: boolean | null;
  /**
   * The normalized domain of the Return-Path (envelope reverse-path), or null
   * when Return-Path is absent, a null reverse-path (`<>`), or yields no real
   * dotted domain.
   */
  returnPathDomain: string | null;
  /**
   * True only when Return-Path is an explicit null reverse-path (`<>`), i.e. a
   * bounce / delivery-status notification with no envelope sender. Lets callers
   * tell an intentional `<>` apart from a missing or unparseable Return-Path,
   * both of which leave returnPathDomain null.
   */
  returnPathNullReversePath: boolean;
  /**
   * Whether returnPathDomain exactly matches fromDomain. null when no comparison
   * was possible (missing From, or no Return-Path domain), so a missing or null
   * Return-Path never reads as a mismatch. false when the domains differ.
   */
  returnPathDomainMatchesFromDomain: boolean | null;
  /**
   * Every resolvable, normalized domain parsed from an SPF `smtp.mailfrom`
   * property across all Authentication-Results headers, in encounter order and
   * deduplicated. Empty when no SPF result carries a parseable envelope-from
   * domain (absent, null `<>`, or unparseable).
   */
  smtpMailfromDomains: string[];
  /**
   * Whether all smtpMailfromDomains exactly match fromDomain. null when no
   * comparison was possible (missing From, or no smtp.mailfrom domain), so a
   * missing SPF smtp.mailfrom never reads as a mismatch. false when any differs.
   */
  smtpMailfromDomainMatchesFromDomain: boolean | null;
  /**
   * Whether the Return-Path domain and every smtp.mailfrom domain agree with
   * each other (the two views of the same envelope sender). null when no
   * comparison was possible (no Return-Path domain, or no smtp.mailfrom domain).
   * false when they disagree — an internally inconsistent envelope sender.
   */
  envelopeSenderDomainsAgree: boolean | null;
  /**
   * Every resolvable, normalized DKIM signing domain (`header.d`) taken only
   * from DKIM results that passed, across all Authentication-Results headers, in
   * encounter order and deduplicated. A failed/error/neutral DKIM signature
   * authenticates nothing, so its header.d is deliberately excluded — a broken
   * signature's claimed domain must never read as From-alignment. Empty when no
   * passing DKIM result carries a parseable header.d.
   */
  dkimDomains: string[];
  /**
   * Whether all dkimDomains exactly match fromDomain (the DKIM-alignment view of
   * the same check DMARC performs). null when no comparison was possible (missing
   * From, or no passing DKIM signing domain), so a failed or missing DKIM
   * signature never reads as a mismatch. false when any signing domain differs.
   */
  dkimDomainMatchesFromDomain: boolean | null;
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

/**
 * Read-only input handed to every Rule.
 *
 * Rules evaluate already-extracted facts; they never re-parse headers or reach
 * for external state. Everything a rule may legitimately read arrives here:
 *
 *   - metrics: facts produced by extractMetrics, with no interpretation applied.
 *   - options: the caller-provided context (trustedAuthservIds and the
 *     open-ended `context` bag). Rules read policy context from here.
 *
 * This is the stable contract that follow-up rule-migration issues target. A
 * rule that needs a new fact should add it to MessageMetrics (via metric
 * extraction) rather than parsing headers itself, keeping parsing, metric
 * extraction, and rule evaluation separable.
 */
export type RuleContext = {
  readonly metrics: MessageMetrics;
  readonly options: AnalyzeOptions;
};

/**
 * Evaluation granularity for a Rule (see Rule.scope). Defaults to "message".
 */
export type RuleScope = "message" | "header";

/**
 * A single detection rule.
 *
 * Rules are the unit of incremental migration: each rule from the Thunderbird
 * add-on becomes one Rule with its own key, tests, and fixtures. Rules are
 * pure functions of RuleContext — given the same context they must return the
 * same signals, with no I/O, globals, or randomness.
 *
 * A Rule is code, not data, so it travels as a separate argument to
 * analyzeMessage and never inside the JSON-serializable AnalyzeInput.
 *
 * Boundary contract:
 *   - evaluate returns zero or more Signals describing observations only.
 *   - A rule must not emit an allow/block/move/notify decision or a numeric
 *     score; thresholds and policy belong to the caller.
 */
export type Rule = {
  /**
   * Stable identifier for the rule. Distinct from the signal `key`s it emits;
   * lets callers select, disable, or document individual rules.
   */
  key: string;
  /**
   * Evaluation granularity, defaulting to "message".
   *
   * - "message": evaluate once against the whole metrics object.
   * - "header": evaluate once per Authentication-Results header, with
   *   metrics.authenticationResults narrowed to that single header. runRules
   *   evaluates a consecutive run of header-scoped rules header-by-header, so
   *   each header's signals stay grouped together (the order a single
   *   per-header loop produces) instead of being grouped per rule. Rules that
   *   read no per-header facts can ignore this and stay "message"-scoped.
   */
  scope?: RuleScope;
  /** Optional human-readable description of what the rule detects. */
  description?: string;
  /** Derive zero or more signals from already-extracted facts. */
  evaluate(context: RuleContext): Signal[];
};
