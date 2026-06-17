import type { Rule, Signal } from "../types.js";

const FAILURE_RESULTS = ["fail", "softfail", "temperror", "permerror"];

/**
 * Flags individual authentication methods (SPF/DKIM/DMARC/…) that did not pass.
 *
 * Severity note: a hard `fail` is reported as medium while soft/transient
 * results (softfail, temperror, permerror) are low, because the latter can be
 * caused by benign misconfiguration or transient DNS issues rather than abuse.
 * The rule does not weigh methods against each other or decide a verdict; the
 * caller combines these signals with its own policy.
 */
export const authMethodFailureRule: Rule = {
  key: "auth.methodFailure",
  description: "An authentication method returned a failing or error result.",
  evaluate({ metrics }) {
    const signals: Signal[] = [];
    for (const header of metrics.authenticationResults) {
      for (const method of header.methods) {
        if (!FAILURE_RESULTS.includes(method.result)) continue;
        signals.push({
          key: `auth.${method.method}.${method.result}`,
          severity: method.result === "fail" ? "medium" : "low",
          message: `${method.method.toUpperCase()} returned ${method.result}.`,
          data: { authservId: header.authservId, properties: method.properties },
        });
      }
    }
    return signals;
  },
};
