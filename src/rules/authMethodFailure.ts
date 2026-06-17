import { resolveHeaderTrust } from "./trust.js";
import type { Rule, Signal, SignalSeverity } from "../types.js";

/**
 * Authentication-Results method results that count as a failure or error.
 *
 *   - fail:      the method's check did not pass (SPF/DKIM/DMARC).
 *   - softfail:  SPF "soft" failure — the domain marks the source as probably
 *                unauthorized (`~all`) without asserting a hard fail.
 *   - temperror: a transient error (e.g. a DNS timeout) prevented evaluation.
 *   - permerror: a permanent error — usually a broken or malformed published
 *                policy (e.g. an unparseable SPF record).
 *
 * `pass`, `none`, `neutral`, and `policy` are intentionally excluded: they are
 * not failures, and `none`/`neutral` in particular are extremely common for
 * legitimate mail (no published policy) and would be high-volume false signals.
 */
const FAILURE_RESULTS = new Set(["fail", "softfail", "temperror", "permerror"]);

/**
 * Pick a severity for one failing method result.
 *
 * Trust gates everything: an Authentication-Results header is only authoritative
 * when stamped by an authserv-id the caller declared trusted. Anyone upstream
 * can forge an Authentication-Results header, so a failure claimed by an
 * untrusted authserv-id proves nothing on its own and is reported at low
 * confidence. (untrustedAuthservIdRule separately flags the untrusted source so
 * the caller can correlate the two.)
 *
 * Among trusted, authoritative failures:
 *
 *   - DMARC fail is the strongest single spoofing indicator available here: it
 *     means the message is unaligned with its own From domain under the
 *     domain's published policy (neither SPF nor DKIM aligned). Reported high.
 *   - Any other hard `fail` is medium. SPF fail can be a legitimate forward and
 *     DKIM fail can be a mailing list that altered the body, so it is a strong
 *     hint rather than a verdict.
 *   - softfail / temperror / permerror are low: a soft fail is deliberately
 *     non-committal, and the *error results are frequently benign transient DNS
 *     issues or a sender's own broken policy publication, not abuse.
 */
function severityFor(method: string, result: string, trusted: boolean): SignalSeverity {
  if (!trusted) return "low";
  if (method === "dmarc" && result === "fail") return "high";
  if (result === "fail") return "medium";
  return "low";
}

/**
 * Flags individual authentication methods (SPF/DKIM/DMARC/…) that returned a
 * failing or error result in a (trusted) Authentication-Results header.
 *
 * Attacker pattern: a spoofed sender whose mail fails the From domain's
 * published SPF/DKIM/DMARC policy. DMARC fail in particular is the canonical
 * direct-domain spoofing signal.
 *
 * False-positive pattern, deliberately mitigated by severity:
 *   - Forwarders break SPF and mailing lists break DKIM for legitimate mail, so
 *     a single SPF/DKIM fail is medium, not high.
 *   - temperror/permerror are transient or sender-side configuration problems,
 *     so they stay low.
 *   - A failure stamped by an untrusted authserv-id could itself be forged, so
 *     it is never escalated above low regardless of method.
 *
 * The rule reports observations only; it never weighs methods against each other
 * or returns a verdict. The caller combines these signals with its own policy.
 */
export const authMethodFailureRule: Rule = {
  key: "auth.methodFailure",
  scope: "header",
  description:
    "An authentication method (SPF/DKIM/DMARC/…) returned a failing or error result.",
  evaluate({ metrics, options }) {
    const signals: Signal[] = [];
    for (const header of metrics.authenticationResults) {
      const trusted = resolveHeaderTrust(header, options);
      for (const method of header.methods) {
        if (!FAILURE_RESULTS.has(method.result)) continue;
        signals.push({
          // One stable key for the whole family; the failing method and result
          // travel in `data` rather than being overloaded into the key string,
          // so callers enumerate a fixed key and filter on data.method/result.
          key: "auth.method.failure",
          category: "auth-failure",
          severity: severityFor(method.method, method.result, trusted),
          message: `${method.method.toUpperCase()} returned ${method.result}.`,
          data: {
            method: method.method,
            result: method.result,
            authservId: header.authservId,
            trusted,
            properties: method.properties,
          },
        });
      }
    }
    return signals;
  },
};
