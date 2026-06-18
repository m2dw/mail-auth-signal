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
 *   - "composite":    a higher-layer observation derived by combining several
 *                     lower-layer facts/signals (auth + consistency + identity)
 *                     rather than a single metric. A composite signal is still an
 *                     observation, never a verdict; it names the lower-layer
 *                     signals that fed it in `data.contributingSignals` so a
 *                     caller can trace it back to its constituents.
 *
 * Malformed input is deliberately not a category: the rules stay silent on
 * unparseable input rather than emit a low-confidence signal, so malformed
 * input surfaces as the absence of a signal, never as a category of one. This
 * keeps the four base distinctions the surface must draw — absence, malformed,
 * auth failure, and consistency mismatch — from collapsing into one key shape,
 * with composite layered on top as an explicitly cross-cutting fifth.
 */
export type SignalCategory =
  | "absence"
  | "trust"
  | "auth-failure"
  | "consistency"
  | "composite";

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
 * Lexical statistics for a single string token (a local part or a domain),
 * computed without any external word list, brand dictionary, or other bundled
 * data — only structural facts an attacker cannot launder away by choosing a
 * benign-looking domain. Callers combine these with their own thresholds; the
 * core forms no opinion. All counts are codepoint-based so a Unicode/IDN value
 * is measured by what a reader sees, not by its UTF-16 unit count.
 *
 * - length:      number of Unicode codepoints.
 * - digitCount:  number of ASCII digits (0-9). A high ratio is a weak hint of a
 *                machine-generated or obfuscated identifier.
 * - hyphenCount: number of '-' characters. Hyphen-heavy hosts (e.g.
 *                "paypal-secure-login") are a common phishing pattern.
 * - hasNonAscii: whether any codepoint is outside ASCII (> U+007F). A true value
 *                flags a raw IDN / possible homoglyph host the caller may want to
 *                punycode-normalize before trusting; the core never guesses intent.
 */
export type LexicalStats = {
  length: number;
  digitCount: number;
  hyphenCount: number;
  hasNonAscii: boolean;
};

/**
 * Richer lexical heuristics for a single string token (a local part, a domain
 * label, a subject word — whatever the caller chooses to measure), ported from
 * the Thunderbird Auth Results Filter add-on so callers can retire their local
 * copies. These complement the lightweight LexicalStats: where LexicalStats
 * reports raw structural counts, these report shape — how random, how
 * pronounceable, how repetitive a token is.
 *
 * Every value is computed from the token alone, with **no bundled word list,
 * brand dictionary, language corpus, or n-gram table** — only structural facts an
 * attacker cannot launder away by choosing a benign-looking string. (Bigram /
 * trigram "naturalness" was a candidate but is deliberately omitted: a meaningful
 * naturalness score needs a language-frequency dataset, and bundling one would
 * cross the data/license boundary this package keeps clear. A caller with its own
 * licensed corpus can layer that on top of these metrics.)
 *
 * The core forms no opinion: these are inputs to a caller's own thresholds, never
 * a verdict. A "high entropy" or "long consonant run" token is suspicious only in
 * a context the caller supplies. All values are JSON-serializable, and the
 * floating-point fields are rounded to 4 decimal places so fixtures stay stable
 * and cross-language comparison is exact.
 *
 * Counts and codepoints are measured the same codepoint-based way as LexicalStats
 * (so a Unicode/IDN token is measured by what a reader sees), while the letter,
 * vowel, and consonant classifications are intentionally **ASCII-only**: deciding
 * whether an arbitrary Unicode codepoint is a vowel is locale- and script-
 * dependent and would need Unicode tables this core does not bundle, so a
 * non-ASCII codepoint is simply not counted as a letter/vowel/consonant. It still
 * participates in length, entropy, unique-ratio, and repeated-run, and still sets
 * LexicalStats.hasNonAscii, so a raw IDN token is never silently ignored.
 *
 * - shannonEntropy:        Shannon entropy in bits over the codepoint-frequency
 *                          distribution. 0 for an empty or single-character token.
 *                          A higher value means a more uniform, less predictable
 *                          mix of characters (a weak hint of a random/generated
 *                          identifier).
 * - normalizedEntropy:     shannonEntropy divided by the maximum possible entropy
 *                          for a token of this length (log2(length), reached when
 *                          every character is distinct), giving a length-
 *                          independent value in [0, 1]. 0 when length < 2.
 * - vowelRatio:            ASCII vowels (a, e, i, o, u; case-insensitive) divided
 *                          by ASCII letters, in [0, 1]. 0 when the token has no
 *                          ASCII letters. An unusually low ratio is a weak hint of
 *                          an unpronounceable / machine-generated token.
 * - maxConsonantRun:       length of the longest run of consecutive ASCII
 *                          consonants. Long runs are atypical of natural words.
 * - maxRepeatedCharRun:    length of the longest run of the same codepoint
 *                          repeated consecutively (e.g. 3 for "aaab"). 0 for an
 *                          empty token, at least 1 otherwise.
 * - uniqueCharRatio:       distinct codepoints divided by length, in [0, 1]. 0 for
 *                          an empty token. A low ratio means heavy character reuse.
 * - letterDigitTransitions: number of adjacent codepoint pairs that switch between
 *                          an ASCII letter and an ASCII digit in either direction
 *                          (e.g. 2 for "ab12ab"). Frequent letter/digit
 *                          alternation is a common shape of obfuscated tokens.
 */
export type LexicalHeuristics = {
  shannonEntropy: number;
  normalizedEntropy: number;
  vowelRatio: number;
  maxConsonantRun: number;
  maxRepeatedCharRun: number;
  uniqueCharRatio: number;
  letterDigitTransitions: number;
};

/**
 * Structural decomposition of a domain into its dot-separated labels, plus an
 * optional registrable-domain view.
 *
 * The label-based fields (labels/labelCount/topLabel) need no external data and
 * are always populated. The registrable-domain fields require a caller-supplied
 * Public Suffix List resolver (MetricsDependencies.getRegistrableDomain) because
 * deciding where the registrable boundary falls (e.g. "co.uk" vs "com") cannot be
 * done correctly without PSL data, which this package intentionally does not
 * bundle (see the licensing boundary in NOTICE / AGENTS.md). When no resolver is
 * supplied — the default — those fields stay null rather than being guessed.
 *
 * - domain:             the normalized domain these parts describe.
 * - labels:             dot-separated labels, left to right (e.g.
 *                       ["mail","example","com"]).
 * - labelCount:         number of labels — the raw subdomain depth.
 * - topLabel:           the rightmost label (a syntactic TLD-ish label, with no
 *                       PSL applied, so "co" for "example.co.uk").
 * - registrableDomain:  the registrable (organizational) domain when a resolver
 *                       supplied one, else null.
 * - subdomainDepth:     labels appearing above the registrable domain (0 when the
 *                       domain *is* its registrable domain), else null when no
 *                       resolver supplied a registrable domain.
 */
export type DomainParts = {
  domain: string;
  labels: string[];
  labelCount: number;
  topLabel: string;
  registrableDomain: string | null;
  subdomainDepth: number | null;
};

/**
 * Metrics derived from the From header's display name (the human-readable phrase
 * before the angle-addr, e.g. `Example Support` in
 * `Example Support <a@example.com>`).
 *
 * The attacker-relevant pattern these capture, without any caller-specific
 * policy, is a display name that itself looks like an email address at a
 * different domain — e.g. From: `"service@paypal.com" <attacker@evil.test>`,
 * where a mail client may surface only `service@paypal.com` while the real
 * sender is evil.test. embeddedDomains/containsEmail/embeddedDomainMatchesFromDomain
 * expose exactly that without deciding it is malicious.
 *
 * - present:     whether a non-empty display name was parsed.
 * - text:        the unquoted display-name text, or null when absent.
 * - length:      codepoint length of text (0 when absent).
 * - hasNonAscii: whether the display name contains a non-ASCII codepoint.
 * - containsEmail: whether the display name contains an email-like address (i.e.
 *                  embeddedDomains is non-empty).
 * - embeddedDomains: every normalized domain found inside the display name, in
 *                    encounter order and deduplicated. Empty when none.
 * - embeddedDomainMatchesFromDomain: whether every embedded domain matches the
 *                  From domain. null when no comparison was possible (no embedded
 *                  domain, or no From domain); false when any embedded domain
 *                  differs from From — the address-in-display-name spoof shape.
 * - normalized:   whitespace-normalized views of the display name for brand-style
 *                  matching. See DisplayNameNormalization.
 * - metrics:      derived facts about what normalization changed. See
 *                  DisplayNameDerivedMetrics.
 * - signals:      boolean shape hints derived from the normalization. See
 *                  DisplayNameSignals.
 */
export type DisplayNameMetrics = {
  present: boolean;
  text: string | null;
  length: number;
  hasNonAscii: boolean;
  containsEmail: boolean;
  embeddedDomains: string[];
  embeddedDomainMatchesFromDomain: boolean | null;
  normalized: DisplayNameNormalization;
  metrics: DisplayNameDerivedMetrics;
  signals: DisplayNameSignals;
};

/**
 * Whitespace-normalized views of the From display name, for brand-style matching
 * that must see through letter-spacing camouflage.
 *
 * Thunderbird add-on logs showed brand spoofing that inserts spaces between the
 * letters of a brand name — e.g. `D d a i i c h i L i f e I n s u r a n c e` — so
 * that a naive substring/brand-list match against the raw display name misses the
 * brand entirely. Exposing the compacted form here lets a consumer match against
 * its own brand list without re-implementing the normalization.
 *
 * - compactedWhitespace: the display name with every run of intra-name whitespace
 *   removed, collapsing a spaced-out brand name into a single matchable token
 *   (`D d a i i c h i L i f e` -> `DdaiichiLife`). null when no display name is
 *   present. Casing is preserved and no other folding is applied — the core forms
 *   no opinion and bundles no brand list. This is a lexical token for the caller
 *   to compare, **never** an email address: it is not parsed, validated, or used
 *   as a mailbox by the core, so a normal multi-word name compacting to something
 *   address-shaped carries no address meaning here.
 */
export type DisplayNameNormalization = {
  compactedWhitespace: string | null;
};

/**
 * Derived facts about the display-name normalization (see
 * DisplayNameNormalization).
 *
 * - whitespaceCompactedChanged: whether whitespace compaction changed the
 *   effective display-name token, i.e. the raw display name contained any
 *   intra-name whitespace that compaction removed. false when no display name is
 *   present or it held no whitespace. This is a plain metric, not a verdict: a
 *   normal multi-word name ("Example Sender") also compacts, so a true value alone
 *   says nothing about intent — pair it with spacedDisplayNameCamouflageCandidate.
 */
export type DisplayNameDerivedMetrics = {
  whitespaceCompactedChanged: boolean;
};

/**
 * Boolean shape hints derived from the display-name normalization. Like every
 * other field in this package these are observations, never verdicts — the caller
 * owns thresholds and policy, and the core assigns no score.
 *
 * - spacedDisplayNameCamouflageCandidate: whether the display name looks like a
 *   brand name camouflaged by letter-spacing — many single-character,
 *   whitespace-separated alphabetic tokens (`D d a i i c h i L i f e`). It is
 *   true only when the display name has at least 3 whitespace-separated tokens, at
 *   least 3 of them are single Unicode letters, and single-letter tokens make up a
 *   majority (>= 60%) of all tokens. These thresholds keep normal multi-word human
 *   names ("Example Sender") and names with an initial or two ("John A Smith",
 *   "J P Morgan") from reading as camouflage, while still firing on a fully or
 *   mostly letter-spaced brand. Computed from the token itself with no bundled
 *   word list or brand dictionary.
 */
export type DisplayNameSignals = {
  spacedDisplayNameCamouflageCandidate: boolean;
};

/**
 * Sender-identity metrics derived from the From mailbox and the Message-ID
 * domain: display-name structure, the From local part and domain lexical
 * profiles, label-based domain decomposition, and (only when a PSL resolver is
 * supplied) a registrable-domain comparison between Message-ID and From.
 *
 * These are pure, serializable facts with no scoring applied — the caller owns
 * thresholds and policy. They complement the exact-match consistency metrics
 * (e.g. messageIdDomainMatchesFromDomain): the registrable-domain comparison here
 * lets a caller with PSL data treat an ESP subdomain as same-organization rather
 * than a bare mismatch, while the lexical/structural fields surface the shape of
 * the identity itself.
 *
 * - displayName:      see DisplayNameMetrics.
 * - localPart:        the From address local part, or null when From has no
 *                     parseable address. Reported only alongside a real From
 *                     domain so it always pairs with fromDomainParts.
 * - localPartLexical: lexical profile of localPart, or null when absent.
 * - fromDomainLexical: lexical profile of the From domain, or null when absent.
 * - fromDomainParts:  label decomposition of the From domain, or null when absent.
 * - messageIdDomainParts: label decomposition of the Message-ID domain, or null
 *                     when absent.
 * - messageIdRegistrableDomainMatchesFromDomain: whether the Message-ID and From
 *                     domains share a registrable domain. Requires a resolver;
 *                     null when none is supplied, either domain is absent, or
 *                     either has no registrable form. true/false otherwise.
 */
export type SenderIdentityMetrics = {
  displayName: DisplayNameMetrics;
  localPart: string | null;
  localPartLexical: LexicalStats | null;
  fromDomainLexical: LexicalStats | null;
  fromDomainParts: DomainParts | null;
  messageIdDomainParts: DomainParts | null;
  messageIdRegistrableDomainMatchesFromDomain: boolean | null;
};

/**
 * Non-serializable runtime dependencies for metric extraction.
 *
 * Like Rules, these are *code, not data*, so they travel as a separate argument
 * to extractMetrics/analyzeMessage and never inside the JSON-serializable
 * AnalyzeInput — keeping the input contract serializable while still allowing a
 * caller to inject capabilities the core must not bundle.
 *
 * - getRegistrableDomain: maps a normalized domain to its registrable
 *   (organizational) domain — the label below the public suffix, e.g.
 *   "mail.corp.example.co.uk" -> "example.co.uk". Supplied by the caller because
 *   computing it correctly requires Public Suffix List data, which this package
 *   intentionally does not bundle (license boundary; see AGENTS.md / NOTICE).
 *   Return null when the domain has no registrable form or the caller cannot
 *   resolve it; the registrable-domain metrics then stay null rather than guessed.
 *   The resolver should return an already-normalized (lower-cased) domain.
 */
export type MetricsDependencies = {
  getRegistrableDomain?: (domain: string) => string | null;
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
  /**
   * Sender-identity metrics derived from the From mailbox and the Message-ID
   * domain (display-name structure, local-part/domain lexical profiles, label
   * decomposition, and an optional registrable-domain comparison). Pure facts
   * with no scoring applied. See SenderIdentityMetrics.
   */
  senderIdentity: SenderIdentityMetrics;
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

/**
 * Read-only input handed to every CompositeRule (the Layer 4 framework).
 *
 * A composite rule differs from a base Rule in one way: besides the extracted
 * metrics, it also receives the `signals` the base rules already produced for
 * this message, so it can reason over a *combination* of lower-layer outcomes
 * (an authentication failure plus a consistency mismatch plus an identity
 * shape) instead of a single metric. This is the whole point of the composite
 * layer — it composes facts that individually are only hints into a single,
 * higher-confidence observation, while staying a pure function of its input.
 *
 *   - metrics: facts produced by extractMetrics, with the `authentication`
 *     projection recomputed for the current options' trust (so anyAuthAligned,
 *     dmarcPass, and the per-method result lists reflect rule-time trust, not
 *     the trust baked at extraction). Mirrors what message-scoped base rules see.
 *   - signals: the base signals already produced for this message, in emission
 *     order. Read-only — a composite reads them but never mutates them.
 *   - options: the caller-provided context (trustedAuthservIds and the
 *     open-ended `context` bag).
 *
 * Because trust drives whether a forged header is believed at all, callers that
 * use runCompositeRules directly must pass `signals` produced under the same
 * options, exactly as analyzeMessage does — otherwise a composite could read a
 * spoof's self-stamped header as authenticated.
 */
export type CompositeRuleContext = {
  readonly metrics: MessageMetrics;
  readonly signals: readonly Signal[];
  readonly options: AnalyzeOptions;
};

/**
 * A Layer 4 composite detection rule.
 *
 * Composite rules are the reusable port of the Thunderbird add-on's composite
 * detection layer, with one deliberate boundary change: where the add-on mapped
 * a composite match onto a Thunderbird action (move to Junk, prompt the user),
 * a CompositeRule emits only a structured Signal whose `data.contributingSignals`
 * names the lower-layer signal keys that justified it. The action/threshold
 * decision stays entirely with the caller, same as for base rules.
 *
 * Like a Rule, a CompositeRule is code, not data: it travels as a separate
 * argument to analyzeMessage / runCompositeRules and never inside the
 * serializable AnalyzeInput, and given the same context it must return the same
 * signals with no I/O, globals, or randomness.
 *
 * Boundary contract:
 *   - evaluate returns zero or more Signals (category "composite") describing a
 *     combined observation only.
 *   - A composite must not emit an allow/block/move/notify decision or a numeric
 *     score; thresholds and policy belong to the caller.
 *   - A composite that *lowers* suspicion (a false-positive mitigation) must gate
 *     on conditions an attacker spoofing someone else's domain cannot satisfy
 *     (real aligned authentication), and must document that guard.
 */
export type CompositeRule = {
  /**
   * Stable identifier for the composite rule. Distinct from the signal `key`s it
   * emits; lets callers select, disable, or document individual composites.
   */
  key: string;
  /** Optional human-readable description of what the composite detects. */
  description?: string;
  /** Derive zero or more composite signals from metrics plus base signals. */
  evaluate(context: CompositeRuleContext): Signal[];
};
