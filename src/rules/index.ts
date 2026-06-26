import type {
  AuthenticationResultsHeader,
  AuthenticationAlignment,
  MessageMetrics,
  AnalyzeOptions,
  MetricsDependencies,
  Rule,
  Signal,
} from "../types.js";
import { collectAuthenticationAlignment } from "../metrics.js";
import { resolveHeaderTrust } from "./trust.js";
import { missingAuthResultsRule } from "./missingAuthResults.js";
import { untrustedAuthservIdRule } from "./untrustedAuthservId.js";
import { authMethodFailureRule } from "./authMethodFailure.js";
import { messageIdDomainMismatchRule } from "./messageIdDomainMismatch.js";
import { replyToDomainMismatchRule } from "./replyToDomainMismatch.js";
import { returnPathDomainMismatchRule } from "./returnPathDomainMismatch.js";
import { smtpMailfromDomainMismatchRule } from "./smtpMailfromDomainMismatch.js";
import { dkimDomainMismatchRule } from "./dkimDomainMismatch.js";
import { dmarcHeaderFromMismatchRule } from "./dmarcHeaderFromMismatch.js";
import { envelopeSenderDisagreementRule } from "./envelopeSenderDisagreement.js";
import { displayNameBrandDomainMismatchRule } from "./displayNameBrandDomainMismatch.js";

export { missingAuthResultsRule } from "./missingAuthResults.js";
export { untrustedAuthservIdRule } from "./untrustedAuthservId.js";
export { authMethodFailureRule } from "./authMethodFailure.js";
export { messageIdDomainMismatchRule } from "./messageIdDomainMismatch.js";
export { replyToDomainMismatchRule } from "./replyToDomainMismatch.js";
export { returnPathDomainMismatchRule } from "./returnPathDomainMismatch.js";
export { smtpMailfromDomainMismatchRule } from "./smtpMailfromDomainMismatch.js";
export { dkimDomainMismatchRule } from "./dkimDomainMismatch.js";
export { dmarcHeaderFromMismatchRule } from "./dmarcHeaderFromMismatch.js";
export { envelopeSenderDisagreementRule } from "./envelopeSenderDisagreement.js";
export { displayNameBrandDomainMismatchRule } from "./displayNameBrandDomainMismatch.js";

/**
 * The built-in rule set, applied in order by analyzeMessage.
 *
 * This array is the migration surface: follow-up issues add a migrated rule by
 * appending its Rule here (or compose their own set and pass it to
 * analyzeMessage / runRules). Order is stable but carries no policy meaning —
 * signals are observations, not a ranked verdict.
 */
export const defaultRules: readonly Rule[] = [
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
];

/**
 * Run a rule set against already-extracted metrics.
 *
 * Exposed so callers can evaluate rules over metrics they extracted (and
 * possibly cached or transported) without re-parsing headers, keeping metric
 * extraction and rule evaluation independently composable.
 *
 * Message-scoped rules (the default) are evaluated once against the whole
 * metrics object, in array order. A consecutive run of header-scoped rules is
 * instead evaluated header-by-header — for each Authentication-Results header,
 * every rule in the run runs against metrics narrowed to that one header — so
 * the signals for one header stay grouped together. This preserves the
 * per-header ordering a single combined loop produced: for two headers, the
 * first header's failure signals precede the second header's untrusted signal,
 * rather than all untrusted signals being grouped ahead of all failure signals.
 */
export function runRules(
  metrics: MessageMetrics,
  options: AnalyzeOptions = {},
  rules: readonly Rule[] = defaultRules,
  deps?: MetricsDependencies,
): Signal[] {
  const signals: Signal[] = [];

  // Recompute the authentication projection with rule-time trust so a caller
  // using the split API (extractMetrics without trust, then runRules with
  // trustedAuthservIds) sees trusted passes reflected in metrics.authentication.
  // Without this, message-scoped rules would read the extraction-time projection
  // (every header untrusted), disagreeing with analyzeMessage for the same
  // options and with the per-header projection headerScopedMetrics builds. The
  // PSL resolver is threaded through so the organizational alignment view stays
  // consistent with analyzeMessage; when no rule-time resolver is available and
  // no trust override is in effect, the extracted organizational block is
  // preserved rather than downgraded (see messageScopedMetrics).
  const messageMetrics = messageScopedMetrics(metrics, options, deps);

  for (let i = 0; i < rules.length; ) {
    const rule = rules[i];
    if (rule === undefined) {
      i += 1;
      continue;
    }
    if (rule.scope !== "header") {
      signals.push(...rule.evaluate({ metrics: messageMetrics, options }));
      i += 1;
      continue;
    }

    // Collect the consecutive run of header-scoped rules and evaluate them
    // header-by-header so each header's signals stay contiguous.
    let end = i;
    while (end < rules.length && rules[end]?.scope === "header") end += 1;
    const headerRules = rules.slice(i, end);

    for (const header of metrics.authenticationResults) {
      const headerMetrics = headerScopedMetrics(metrics, header, options, deps);
      for (const rule of headerRules) {
        signals.push(...rule.evaluate({ metrics: headerMetrics, options }));
      }
    }

    i = end;
  }

  return signals;
}

/**
 * Rebuild the whole-message `authentication` projection with rule-time trust so
 * message-scoped rules read the same trust analyzeMessage would for the given
 * options. Trust is resolved through resolveHeaderTrust (mirroring
 * headerScopedMetrics and the Authentication-Results rules): with no
 * trustedAuthservIds override this reproduces the extraction-time projection,
 * and with an override the trusted passes a split-API caller declared at rule
 * time are reflected, instead of the stale projection baked into
 * metrics.authentication at extraction.
 *
 * The PSL-aware `organizational` sub-view depends on the (non-serializable)
 * resolver too. A split-API caller that extracted metrics with a resolver but
 * did not re-supply deps to runRules would otherwise have its resolver-derived
 * organizational block silently recomputed with the exact-domain fallback,
 * downgrading subdomain/organizational matches to false. So the extracted
 * organizational projection is preserved instead of recomputed when no rule-time
 * resolver is available AND the extracted block was itself resolver-derived
 * (organizational.resolverAvailable) AND rule-time trust still selects the same
 * trusted+passing domain set the extracted block was built from.
 *
 * That last condition is the security boundary: the organizational view is a
 * function of the From domain and the trusted, passing SPF/DKIM/DMARC domains, so
 * it only stays valid while that domain set is unchanged. When a trust override
 * changes which headers are trusted, the recomputed exact-domain `authentication`
 * already reflects the new trust; preserving a stale organizational block there
 * would let organizational.anyAuthAligned stay true from a header that is no
 * longer trusted, suppressing composites such as
 * composite.unauthenticatedFromSpoof. trustedPassingDomainSignature compares the
 * rule-time set against the baked one (computable without the resolver, since the
 * filter is exact-domain), so preservation is gated on the two matching.
 *
 * The block is recomputed (exact-domain, applying rule-time trust) whenever a
 * rule-time resolver is present, the extracted block was not resolver-derived, or
 * the trusted+passing domain set changed — accepting the PSL downgrade only when
 * the alternative would be a trust-stale verdict.
 */
/**
 * Stable signature of the trusted, passing domain set an organizational view is
 * built from: the trusted+passing SPF MAIL FROM, DKIM d=, and DMARC header.from
 * domains. Two AuthenticationAlignment values share a signature exactly when they
 * would yield the same organizational alignment for a fixed From domain, so it is
 * used to decide whether a resolver-derived organizational block stays valid
 * under rule-time trust. The filter is exact-domain (trusted && pass && domain),
 * so the signature is computable without the PSL resolver.
 */
function trustedPassingDomainSignature(auth: AuthenticationAlignment): string {
  const sorted = (domains: (string | null)[]): string[] =>
    [...new Set(domains.filter((d): d is string => d !== null))].sort();
  const spf = sorted(
    auth.spfResults.filter((r) => r.trusted && r.result === "pass").map((r) => r.smtpMailfrom),
  );
  const dkim = sorted(
    auth.dkimResults.filter((r) => r.trusted && r.result === "pass").map((r) => r.headerD),
  );
  const dmarc = sorted(
    auth.dmarcResults.filter((r) => r.trusted && r.result === "pass").map((r) => r.headerFrom),
  );
  return JSON.stringify({ spf, dkim, dmarc });
}

export function messageScopedMetrics(
  metrics: MessageMetrics,
  options: AnalyzeOptions,
  deps?: MetricsDependencies,
): MessageMetrics {
  const authentication = collectAuthenticationAlignment(
    metrics.authenticationResults,
    metrics.fromDomain,
    (h) => resolveHeaderTrust(h, options),
    deps?.getRegistrableDomain,
  );
  const preserveOrganizational =
    deps?.getRegistrableDomain === undefined &&
    metrics.authentication.organizational.resolverAvailable &&
    trustedPassingDomainSignature(authentication) ===
      trustedPassingDomainSignature(metrics.authentication);
  return {
    ...metrics,
    authentication: preserveOrganizational
      ? { ...authentication, organizational: metrics.authentication.organizational }
      : authentication,
  };
}

/**
 * Narrow metrics to a single Authentication-Results header for header-scoped
 * rule evaluation. All other facts are preserved so header-scoped rules can
 * still read message-level metrics (e.g. fromDomain) if they need to.
 *
 * The cached `authentication` projection is recomputed from just this header so
 * a header-scoped rule reading authentication.anyAuthAligned, the per-method
 * result lists, or the trusted/untrusted counts sees only the current header's
 * SPF/DKIM/DMARC results — not another header's. Trust is resolved through
 * resolveHeaderTrust (mirroring the other Authentication-Results rules) so a
 * caller declaring trustedAuthservIds to runRules after extracting metrics
 * without it gets the same projection analyzeMessage would, rather than the
 * extraction-time trust baked into metrics.authentication.
 */
function headerScopedMetrics(
  metrics: MessageMetrics,
  header: AuthenticationResultsHeader,
  options: AnalyzeOptions,
  deps?: MetricsDependencies,
): MessageMetrics {
  const authentication = collectAuthenticationAlignment(
    [header],
    metrics.fromDomain,
    (h) => resolveHeaderTrust(h, options),
    deps?.getRegistrableDomain,
  );
  return { ...metrics, authentication, authenticationResults: [header] };
}
