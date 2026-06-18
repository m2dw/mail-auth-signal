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
 * Coarse classification shared by every built-in signal, so callers can group,
 * route, or filter signals by what kind of observation they are without
 * string-matching individual keys.
 *
 *   - "absence":      an expected input was simply not present (e.g. no
 *                     Authentication-Results header at all). Distinct from a
 *                     malformed or a failing input.
 *   - "trust":        an Authentication-Results header came from a source the
 *                     caller did not declare trusted, so its claims are not
 *                     authoritative on their own.
 *   - "auth-failure": an authentication method (SPF/DKIM/DMARC/…) returned a
 *                     failing or error result.
 *   - "consistency":  two header-derived domains that should agree do not — a
 *                     domain-consistency mismatch.
 *
 * Malformed input is deliberately not a category: the rules stay silent on
 * unparseable input rather than emit a low-confidence signal, so malformed
 * input surfaces as the absence of a signal, never as a category of one. This
 * keeps the four distinctions the surface must draw — absence, malformed,
 * auth failure, and consistency mismatch — from collapsing into one key shape.
 */
export type SignalCategory = "absence" | "trust" | "auth-failure" | "consistency";

/**
 * A keyed, severity-tagged observation produced by the core.
 *
 * Callers are responsible for deciding what to do with signals — thresholds,
 * UI presentation, notifications, mailbox actions, and allow/block policy all
 * belong outside this library.
 *
 * `category` is the coarse classification of the observation (see
 * SignalCategory). Every built-in rule sets it; it is optional only so a
 * caller-supplied custom rule may omit it. `key` stays the stable, fine-grained
 * identifier and never overloads multiple dimensions into its string — variable
 * specifics (the failing method, the divergent domains) live in `data`, not in
 * the key.
 */
export type Signal = {
  key: string;
  category?: SignalCategory;
  severity: SignalSeverity;
  message: string;
  data?: Record<string, unknown>;
};

/**
 * One DMARC result observed in an Authentication-Results header (Layer 1: the
 * raw authentication outcome, before any alignment interpretation).
 *
 * - result:     the verifier's verdict token, lower-cased (e.g. "pass", "fail",
 *               "none", "temperror", "permerror"). Faithfully echoed, never gated.
 * - headerFrom: the normalized domain of the `header.from` property the verifier
 *               evaluated, or null when absent or unparseable.
 * - trusted:    whether the carrying Authentication-Results header's authserv-id
 *               was declared trusted, so a caller can tell a verifier's own claim
 *               apart from a forge-able upstream one without re-deriving trust.
 */
export type DmarcResult = {
  result: string;
  headerFrom: string | null;
  trusted: boolean;
};

/**
 * One SPF result observed in an Authentication-Results header (Layer 1).
 *
 * - result:       the verdict token, lower-cased (e.g. "pass", "fail",
 *                 "softfail", "neutral", "none", "temperror", "permerror").
 * - smtpMailfrom: the normalized domain of the `smtp.mailfrom` property SPF
 *                 authenticated, or null when absent, a null `<>`, or unparseable.
 * - trusted:      whether the carrying header's authserv-id was declared trusted.
 */
export type SpfResult = {
  result: string;
  smtpMailfrom: string | null;
  trusted: boolean;
};

/**
 * One DKIM result observed in an Authentication-Results header (Layer 1). A
 * message commonly carries several DKIM signatures (author domain plus a
 * forwarder or list), so these are reported as a list.
 *
 * - result:  the verdict token, lower-cased (e.g. "pass", "fail", "neutral",
 *            "none", "temperror", "permerror").
 * - headerD: the normalized signing domain from `header.d`, or null when absent
 *            or unparseable.
 * - headerI: the normalized domain of the `header.i` agent/user identity (AUID),
 *            or null when absent or unparseable. May be a subdomain of headerD.
 * - trusted: whether the carrying header's authserv-id was declared trusted.
 */
export type DkimResult = {
  result: string;
  headerD: string | null;
  headerI: string | null;
  trusted: boolean;
};

/**
 * Authentication and alignment metrics ported from the Thunderbird add-on, split
 * into the two layers it modeled:
 *
 *   - Layer 1 (raw results): the SPF/DKIM/DMARC outcomes exactly as reported,
 *     each tagged with the trust of its source. No gating — a caller sees every
 *     claim, trusted or not, and decides what to do with it.
 *   - Layer 2 (alignment + summary flags): derived booleans answering "is this
 *     message authenticated and aligned with the visible From?". These are the
 *     attacker-relevant assertions, so they are computed only from **trusted**
 *     Authentication-Results headers and only from **passing** results: an
 *     untrusted header is forge-able and a non-pass result authenticates nothing,
 *     so neither may make a message read as authenticated. This gating is the
 *     false-positive/false-negative mitigation — without it, an attacker could
 *     stamp a fake `spf=pass` / `dkim=pass` in a self-applied header and have the
 *     summary flags vouch for a spoof.
 *
 * Alignment is measured against the visible From domain (MessageMetrics.fromDomain
 * — the "Header From"), the exact identity DMARC alignment protects. Comparison is
 * exact, with no Public Suffix List / organizational-domain logic, so a subdomain
 * of From counts as unaligned (mirroring the existing consistency metrics).
 *
 * All values are JSON-serializable for logging, fixtures, and cross-language
 * comparison.
 */
export type AuthenticationAlignment = {
  /** Count of Authentication-Results headers whose authserv-id was trusted. */
  trustedHeaderCount: number;
  /** Count of Authentication-Results headers whose authserv-id was not trusted. */
  untrustedHeaderCount: number;
  /** Every DMARC result across all headers, in encounter order (Layer 1). */
  dmarcResults: DmarcResult[];
  /** Every SPF result across all headers, in encounter order (Layer 1). */
  spfResults: SpfResult[];
  /** Every DKIM result across all headers, in encounter order (Layer 1). */
  dkimResults: DkimResult[];
  /**
   * Whether every trusted, passing SPF `smtp.mailfrom` domain matches the From
   * domain (SPF alignment, the mechanical basis of DMARC's SPF leg). null when no
   * comparison was possible (missing From, or no trusted+passing SPF carrying a
   * smtp.mailfrom domain). false when any such domain differs from From.
   */
  spfAlignedWithFrom: boolean | null;
  /**
   * Whether every trusted, passing DKIM `header.d` domain matches the From domain
   * (DKIM alignment, the basis of DMARC's DKIM leg). null when no comparison was
   * possible (missing From, or no trusted+passing DKIM carrying a header.d). false
   * when any such signing domain differs from From.
   */
  dkimAlignedWithFrom: boolean | null;
  /**
   * True when at least one trusted, passing SPF result's smtp.mailfrom matches
   * From. Distinct from spfAlignedWithFrom: "any" tolerates an additional
   * non-aligned SPF result, matching how DMARC passes on a single aligned leg.
   */
  anyAlignedSpfPass: boolean;
  /**
   * True when at least one trusted, passing DKIM signature's header.d matches
   * From. A message may carry several signatures, and DMARC's DKIM leg passes if
   * any aligned signature passes; this captures exactly that.
   */
  anyAlignedDkimPass: boolean;
  /** True when at least one trusted DMARC result returned `pass`. */
  dmarcPass: boolean;
  /**
   * True when the message has any aligned, trusted, passing authentication —
   * anyAlignedSpfPass || anyAlignedDkimPass. This is the DMARC-style summary: a
   * From domain backed by at least one aligned authenticated identifier.
   */
  anyAuthAligned: boolean;
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
  /**
   * Every resolvable, normalized DMARC `header.from` domain — the visible-From
   * domain a verifier evaluated — taken only from DMARC results that passed and
   * only from *trusted* Authentication-Results headers, in encounter order and
   * deduplicated. Two gates apply because, unlike a DKIM signature, header.from
   * is not cryptographic: an untrusted (forge-able) header's header.from is just
   * the attacker's own assertion, and a non-pass DMARC vouches for nothing, so
   * neither must read as a verified view of the From domain. Empty when no
   * trusted, passing DMARC result carries a parseable header.from.
   */
  dmarcHeaderFromDomains: string[];
  /**
   * Whether all dmarcHeaderFromDomains exactly match fromDomain. null when no
   * comparison was possible (missing From, or no trusted+passing DMARC
   * header.from), so a failed, missing, malformed, or untrusted DMARC context
   * never reads as a mismatch. false when a verifier passed DMARC for a From
   * domain the recipient does not see — a "pass" badge applied to a domain other
   * than the visible sender.
   */
  dmarcHeaderFromMatchesFromDomain: boolean | null;
  /**
   * Ported authentication + alignment metrics (Layer 1 raw results, Layer 2
   * alignment and summary flags). See AuthenticationAlignment. This is a derived
   * view over authenticationResults, surfaced alongside the per-comparison match
   * fields above for callers that want the consolidated authentication picture.
   */
  authentication: AuthenticationAlignment;
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
