import { extractDomainFromMailbox, extractDomainFromMessageId, domainsExactlyMatch } from "./domains.js";
import { getFirstHeaderValue, getHeaderValues, normalizeHeaders } from "./normalizeHeaders.js";
import { parseAuthenticationResults } from "./parseAuthenticationResults.js";
import type { AnalyzeInput, AnalyzeResult, Signal } from "./types.js";

export function analyzeMessage(input: AnalyzeInput): AnalyzeResult {
  const headers = normalizeHeaders(input.headers);
  const trustedAuthservIds = input.options?.trustedAuthservIds ?? [];
  const fromDomain = extractDomainFromMailbox(getFirstHeaderValue(headers, "from"));
  const messageIdDomain = extractDomainFromMessageId(getFirstHeaderValue(headers, "message-id"));
  const messageIdDomainMatchesFromDomain = domainsExactlyMatch(fromDomain, messageIdDomain);
  const authenticationResults = getHeaderValues(headers, "authentication-results").map((raw) =>
    parseAuthenticationResults(raw, trustedAuthservIds),
  );

  const signals: Signal[] = [];

  if (authenticationResults.length === 0) {
    signals.push({
      key: "authResults.missing",
      severity: "medium",
      message: "No Authentication-Results header was found.",
    });
  }

  for (const header of authenticationResults) {
    if (!header.trusted) {
      signals.push({
        key: "authResults.untrustedAuthservId",
        severity: "low",
        message: "Authentication-Results header was produced by an untrusted authserv-id.",
        data: { authservId: header.authservId },
      });
    }

    for (const method of header.methods) {
      if (["fail", "softfail", "temperror", "permerror"].includes(method.result)) {
        signals.push({
          key: `auth.${method.method}.${method.result}`,
          severity: method.result === "fail" ? "medium" : "low",
          message: `${method.method.toUpperCase()} returned ${method.result}.`,
          data: { authservId: header.authservId, properties: method.properties },
        });
      }
    }
  }

  if (messageIdDomainMatchesFromDomain === false) {
    signals.push({
      key: "messageId.domainMismatch",
      severity: "low",
      message: "Message-ID domain differs from the From domain.",
      data: { fromDomain, messageIdDomain },
    });
  }

  return {
    metrics: {
      fromDomain,
      messageIdDomain,
      messageIdDomainMatchesFromDomain,
      authenticationResults,
    },
    signals,
  };
}
