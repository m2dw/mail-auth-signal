import { describe, expect, it } from "vitest";
import {
  analyzeMessage,
  defaultCompositeRules,
  defaultRules,
  extractMetrics,
  runCompositeRules,
  runRules,
} from "../src/index.js";
import type {
  AnalyzeInput,
  CompositeRule,
  MetricsDependencies,
} from "../src/index.js";

const TRUSTED_ID = "mx.example.net";

/**
 * A minimal Public Suffix List resolver covering the compound `.co.jp` suffix and
 * a plain `.com`, so a subdomain of an organizational domain resolves to that
 * registrable domain. The core bundles no PSL data (license boundary), so the
 * resolver is supplied here exactly as a real caller (e.g. a tldts-backed one)
 * would. Returns null for anything it does not recognize.
 */
const PSL: Record<string, string> = {
  "example.co.jp": "example.co.jp",
  "news.example.co.jp": "example.co.jp",
  "bounce.example.co.jp": "example.co.jp",
  "mail.example.co.jp": "example.co.jp",
  "evil.co.jp": "evil.co.jp",
  "attacker.co.jp": "evil.co.jp",
  "example.com": "example.com",
  "mail.example.com": "example.com",
};
const deps: MetricsDependencies = { getRegistrableDomain: (domain) => PSL[domain] ?? null };

/** A message with the given From and a single trusted Authentication-Results header. */
function trustedMessage(from: string, authResults: string): AnalyzeInput {
  return {
    headers: {
      from,
      "message-id": "<id@example.co.jp>",
      "authentication-results": authResults,
    },
    options: { trustedAuthservIds: [TRUSTED_ID] },
  };
}

describe("organizational (PSL-aware) alignment — compound suffixes such as .co.jp", () => {
  // From is a subdomain of the organizational domain its authenticated identifiers
  // sit under: header.d / smtp.mailfrom are example.co.jp, From is news.example.co.jp.
  const SUBDOMAIN_FROM = trustedMessage(
    "Example <a@news.example.co.jp>",
    `${TRUSTED_ID}; spf=pass smtp.mailfrom=bounce.example.co.jp; dkim=pass header.d=example.co.jp`,
  );

  it("treats a From subdomain as aligned with its registrable domain when a resolver is supplied", () => {
    const { authentication } = extractMetrics(SUBDOMAIN_FROM, deps);

    // Exact-domain comparison still reads the subdomain difference as unaligned…
    expect(authentication.spfAlignedWithFrom).toBe(false);
    expect(authentication.dkimAlignedWithFrom).toBe(false);
    expect(authentication.anyAuthAligned).toBe(false);

    // …while the PSL-aware view recognizes the shared organizational domain.
    expect(authentication.organizational.resolverAvailable).toBe(true);
    expect(authentication.organizational.spfAligned).toBe(true);
    expect(authentication.organizational.dkimAligned).toBe(true);
    expect(authentication.organizational.anySpfAligned).toBe(true);
    expect(authentication.organizational.anyDkimAligned).toBe(true);
    expect(authentication.organizational.anyAuthAligned).toBe(true);
    expect(authentication.organizational.unalignedPassingSpfDomains).toEqual([]);
    expect(authentication.organizational.unalignedPassingDkimDomains).toEqual([]);
  });

  it("falls back to exact comparison and records resolverAvailable:false when no resolver is supplied", () => {
    const { authentication } = extractMetrics(SUBDOMAIN_FROM);

    expect(authentication.organizational.resolverAvailable).toBe(false);
    // Without PSL data, a subdomain only aligns if it is byte-for-byte equal, so
    // the organizational view degrades to the exact-domain result.
    expect(authentication.organizational.spfAligned).toBe(false);
    expect(authentication.organizational.dkimAligned).toBe(false);
    expect(authentication.organizational.anyAuthAligned).toBe(false);
    expect(authentication.organizational.unalignedPassingSpfDomains).toEqual(["bounce.example.co.jp"]);
    expect(authentication.organizational.unalignedPassingDkimDomains).toEqual(["example.co.jp"]);
  });

  it("does not treat a different organization on the same suffix as aligned", () => {
    // From example.co.jp, but the passing DKIM signs for evil.co.jp — same .co.jp
    // suffix, different registrable domain, so it must read as unaligned.
    const { authentication } = extractMetrics(
      trustedMessage(
        "Example <a@example.co.jp>",
        `${TRUSTED_ID}; dkim=pass header.d=attacker.co.jp`,
      ),
      deps,
    );

    expect(authentication.organizational.resolverAvailable).toBe(true);
    expect(authentication.organizational.dkimAligned).toBe(false);
    expect(authentication.organizational.anyDkimAligned).toBe(false);
    expect(authentication.organizational.anyAuthAligned).toBe(false);
    expect(authentication.organizational.unalignedPassingDkimDomains).toEqual(["attacker.co.jp"]);
  });

  it("distinguishes an aligned signature from a co-occurring cross-org one (any vs all)", () => {
    // The author-domain signature aligns organizationally; a third-party signer does
    // not. DMARC's DKIM leg passes on the aligned one (any), but not every signature
    // aligns (all), and the cross-org domain is surfaced as unaligned-but-passing.
    const { authentication } = extractMetrics(
      trustedMessage(
        "Example <a@news.example.co.jp>",
        `${TRUSTED_ID}; dkim=pass header.d=example.co.jp; dkim=pass header.d=mailer.test`,
      ),
      deps,
    );

    expect(authentication.organizational.anyDkimAligned).toBe(true);
    expect(authentication.organizational.dkimAligned).toBe(false);
    expect(authentication.organizational.anyAuthAligned).toBe(true);
    expect(authentication.organizational.unalignedPassingDkimDomains).toEqual(["mailer.test"]);
  });

  it("excludes untrusted and non-passing results from the organizational view too", () => {
    // A forged untrusted header and a failing signature must not make the
    // organizational view read as aligned, mirroring the exact-domain gating.
    const { authentication } = extractMetrics(
      {
        headers: {
          from: "Example <a@news.example.co.jp>",
          "authentication-results": [
            "relay.evil.test; dkim=pass header.d=example.co.jp",
            `${TRUSTED_ID}; dkim=fail header.d=example.co.jp`,
          ],
        },
        options: { trustedAuthservIds: [TRUSTED_ID] },
      },
      deps,
    );

    expect(authentication.organizational.dkimAligned).toBeNull();
    expect(authentication.organizational.anyDkimAligned).toBe(false);
    expect(authentication.organizational.anyAuthAligned).toBe(false);
    expect(authentication.organizational.unalignedPassingDkimDomains).toEqual([]);
  });
});

describe("organizational alignment — resolver threads through the full pipeline", () => {
  const SUBDOMAIN_FROM = trustedMessage(
    "Example <a@news.example.co.jp>",
    `${TRUSTED_ID}; spf=pass smtp.mailfrom=bounce.example.co.jp; dkim=pass header.d=example.co.jp`,
  );

  it("analyzeMessage surfaces the organizational view computed with the resolver", () => {
    const aligned = analyzeMessage(SUBDOMAIN_FROM, undefined, deps);
    expect(aligned.metrics.authentication.organizational.anyAuthAligned).toBe(true);
    expect(aligned.metrics.authentication.organizational.resolverAvailable).toBe(true);

    const noResolver = analyzeMessage(SUBDOMAIN_FROM);
    expect(noResolver.metrics.authentication.organizational.anyAuthAligned).toBe(false);
    expect(noResolver.metrics.authentication.organizational.resolverAvailable).toBe(false);
  });

  it("runRules recomputes the organizational view with the same resolver and rule-time trust", () => {
    // Split API: extract without trust (everything untrusted, so unaligned), then
    // declare trust and the resolver at rule time. The recomputed projection a
    // message-scoped rule sees must match analyzeMessage for the same inputs.
    const metricsNoTrust = extractMetrics({ headers: SUBDOMAIN_FROM.headers });
    expect(metricsNoTrust.authentication.organizational.anyAuthAligned).toBe(false);

    let seen: boolean | undefined;
    runRules(
      metricsNoTrust,
      { trustedAuthservIds: [TRUSTED_ID] },
      [
        {
          key: "test.captureOrg",
          evaluate({ metrics }) {
            seen = metrics.authentication.organizational.anyAuthAligned;
            return [];
          },
        },
      ],
      deps,
    );
    expect(seen).toBe(true);
  });

  it("preserves the resolver-derived organizational view when runRules gets no resolver", () => {
    // Split API: extract WITH the resolver (so the organizational block is
    // resolver-derived and aligned), then run rules WITHOUT re-supplying deps and
    // with no trust override. The resolver is non-serializable, so a caller often
    // cannot re-pass it; the recomputed exact-domain fallback must not silently
    // downgrade the already-extracted organizational projection.
    const metrics = extractMetrics(SUBDOMAIN_FROM, deps);
    expect(metrics.authentication.organizational.anyAuthAligned).toBe(true);
    expect(metrics.authentication.organizational.resolverAvailable).toBe(true);

    let seen: boolean | undefined;
    let seenResolverAvailable: boolean | undefined;
    runRules(metrics, undefined, [
      {
        key: "test.captureOrg",
        evaluate({ metrics }) {
          seen = metrics.authentication.organizational.anyAuthAligned;
          seenResolverAvailable = metrics.authentication.organizational.resolverAvailable;
          return [];
        },
      },
    ]);
    expect(seen).toBe(true);
    expect(seenResolverAvailable).toBe(true);
  });

  it("preserves the resolver-derived organizational view when runRules re-passes trust options without the resolver", () => {
    // The documented split-API flow: extract WITH the resolver and trust, then
    // re-pass input.options (which carries trustedAuthservIds) to runRules but
    // WITHOUT re-supplying the non-serializable resolver. A present trust override
    // must not flip preservation off and recompute the resolver-derived block with
    // the exact-domain fallback, downgrading anyAuthAligned from true to false.
    const metrics = extractMetrics(SUBDOMAIN_FROM, deps);
    expect(metrics.authentication.organizational.anyAuthAligned).toBe(true);
    expect(metrics.authentication.organizational.resolverAvailable).toBe(true);

    let seen: boolean | undefined;
    let seenResolverAvailable: boolean | undefined;
    runRules(metrics, SUBDOMAIN_FROM.options, [
      {
        key: "test.captureOrg",
        evaluate({ metrics }) {
          seen = metrics.authentication.organizational.anyAuthAligned;
          seenResolverAvailable = metrics.authentication.organizational.resolverAvailable;
          return [];
        },
      },
    ]);
    expect(seen).toBe(true);
    expect(seenResolverAvailable).toBe(true);
  });

  it("recomputes (does not preserve) when a trust override untrusts the header the resolver-derived block was built from", () => {
    // Security boundary: extract WITH the resolver and trust, so the resolver-derived
    // organizational block is aligned from a now-trusted header. Then call runRules
    // with a DIFFERENT trustedAuthservIds (the original authserv-id is no longer
    // trusted) and WITHOUT re-supplying the resolver. The rest of `authentication`
    // is recomputed with the new trust, so preserving the stale organizational block
    // solely because it was resolver-derived would keep anyAuthAligned true from a
    // header that is no longer trusted — suppressing composites like
    // unauthenticatedFromSpoof. The rule-time trusted+passing domain set is now
    // empty, so the block must be recomputed instead of preserved.
    const metrics = extractMetrics(SUBDOMAIN_FROM, deps);
    expect(metrics.authentication.organizational.anyAuthAligned).toBe(true);
    expect(metrics.authentication.organizational.resolverAvailable).toBe(true);

    let seen: boolean | undefined;
    let seenResolverAvailable: boolean | undefined;
    runRules(metrics, { trustedAuthservIds: ["other.untrusted"] }, [
      {
        key: "test.captureOrg",
        evaluate({ metrics }) {
          seen = metrics.authentication.organizational.anyAuthAligned;
          seenResolverAvailable = metrics.authentication.organizational.resolverAvailable;
          return [];
        },
      },
    ]);
    expect(seen).toBe(false);
    expect(seenResolverAvailable).toBe(false);
  });

  it("preserves the resolver-derived organizational view when runCompositeRules re-passes trust options without the resolver", () => {
    // Same trust-options-without-resolver hazard on the documented composite path.
    const metrics = extractMetrics(SUBDOMAIN_FROM, deps);
    expect(metrics.authentication.organizational.anyAuthAligned).toBe(true);
    expect(metrics.authentication.organizational.resolverAvailable).toBe(true);

    let seen: boolean | undefined;
    let seenResolverAvailable: boolean | undefined;
    const captureOrg: CompositeRule = {
      key: "test.captureOrgComposite",
      evaluate({ metrics }) {
        seen = metrics.authentication.organizational.anyAuthAligned;
        seenResolverAvailable = metrics.authentication.organizational.resolverAvailable;
        return [];
      },
    };
    runCompositeRules(metrics, [], SUBDOMAIN_FROM.options, [captureOrg]);
    expect(seen).toBe(true);
    expect(seenResolverAvailable).toBe(true);
  });

  it("recomputes with a trust override when the extracted block was not resolver-derived", () => {
    // No resolver at extraction (resolverAvailable:false) and none at rule time,
    // but trust changes from none to TRUSTED_ID. There is no PSL verdict to lose,
    // so the block is recomputed to apply the new trust: exact-domain alignment
    // stays false here (From subdomain vs registrable-domain identifiers), and the
    // preservation branch must not pin a stale extraction-time projection.
    const metricsNoTrust = extractMetrics({ headers: SUBDOMAIN_FROM.headers });
    expect(metricsNoTrust.authentication.organizational.resolverAvailable).toBe(false);

    let seenResolverAvailable: boolean | undefined;
    runRules(metricsNoTrust, { trustedAuthservIds: [TRUSTED_ID] }, [
      {
        key: "test.captureOrg",
        evaluate({ metrics }) {
          seenResolverAvailable = metrics.authentication.organizational.resolverAvailable;
          return [];
        },
      },
    ]);
    expect(seenResolverAvailable).toBe(false);
  });

  it("preserves the resolver-derived organizational view when runCompositeRules gets no resolver", () => {
    // Same split-API hazard as the runRules case above, on the documented
    // composite path: extract WITH the resolver, then run composites WITHOUT
    // re-supplying deps and with no trust override. A composite rule reading
    // authentication.organizational.anyAuthAligned must still see the
    // resolver-derived true, not the downgraded exact-domain fallback.
    const metrics = extractMetrics(SUBDOMAIN_FROM, deps);
    expect(metrics.authentication.organizational.anyAuthAligned).toBe(true);
    expect(metrics.authentication.organizational.resolverAvailable).toBe(true);

    let seen: boolean | undefined;
    let seenResolverAvailable: boolean | undefined;
    const captureOrg: CompositeRule = {
      key: "test.captureOrgComposite",
      evaluate({ metrics }) {
        seen = metrics.authentication.organizational.anyAuthAligned;
        seenResolverAvailable = metrics.authentication.organizational.resolverAvailable;
        return [];
      },
    };
    runCompositeRules(metrics, [], undefined, [captureOrg]);
    expect(seen).toBe(true);
    expect(seenResolverAvailable).toBe(true);
  });
});

describe("organizational alignment honored in composites — relaxed subdomain mail", () => {
  // Legitimate relaxed-aligned subdomain mail: From is a subdomain of the
  // organizational domain its trusted, passing DKIM/SPF identifiers sit under.
  // The exact-domain check reads the subdomain difference as unaligned, so the
  // exact dkim/smtp.mailfrom mismatch consistency signals are present — the shape
  // that previously tripped composite.unauthenticatedFromSpoof.
  const SUBDOMAIN_FROM = trustedMessage(
    "Example <a@news.example.co.jp>",
    `${TRUSTED_ID}; spf=pass smtp.mailfrom=bounce.example.co.jp; dkim=pass header.d=example.co.jp`,
  );

  it("does not emit unauthenticatedFromSpoof for relaxed-aligned subdomain mail when a resolver is supplied", () => {
    const result = analyzeMessage(SUBDOMAIN_FROM, defaultRules, deps, defaultCompositeRules);

    // PSL-aware view recognizes the shared organizational domain even though the
    // exact-domain view still reads it as unaligned.
    expect(result.metrics.authentication.anyAuthAligned).toBe(false);
    expect(result.metrics.authentication.organizational.anyAuthAligned).toBe(true);
    // The exact-domain mismatch consistency signals are present...
    expect(result.signals.map((s) => s.key)).toContain("dkim.domainMismatch");
    // ...but organizational alignment suppresses the false spoof verdict.
    expect(result.signals.map((s) => s.key)).not.toContain(
      "composite.unauthenticatedFromSpoof",
    );
  });

  it("still fires unauthenticatedFromSpoof for the same mail when no resolver is supplied (override)", () => {
    // Without a resolver the organizational view degrades to exact comparison, so
    // the From subdomain is genuinely unaligned and the trusted DKIM/SPF mismatch
    // is divergent-identity evidence: the spoof composite must still fire. This is
    // the resolver-override contrast — the only thing that changed is the resolver.
    const result = analyzeMessage(SUBDOMAIN_FROM, defaultRules, undefined, defaultCompositeRules);

    expect(result.metrics.authentication.anyAuthAligned).toBe(false);
    expect(result.metrics.authentication.organizational.anyAuthAligned).toBe(false);
    expect(result.signals.map((s) => s.key)).toContain("composite.unauthenticatedFromSpoof");
  });

  it("still emits unauthenticatedFromSpoof for a cross-organization spoof under a resolver", () => {
    // From news.example.co.jp but the only trusted passing identifier is on a
    // different organization (evil.co.jp). Organizational alignment is false, so the
    // PSL-aware path must not suppress the genuine spoof.
    const spoof = trustedMessage(
      "Example <a@news.example.co.jp>",
      `${TRUSTED_ID}; spf=fail smtp.mailfrom=attacker.co.jp; dkim=pass header.d=evil.co.jp`,
    );
    const result = analyzeMessage(spoof, defaultRules, deps, defaultCompositeRules);

    expect(result.metrics.authentication.organizational.anyAuthAligned).toBe(false);
    expect(result.signals.map((s) => s.key)).toContain("composite.unauthenticatedFromSpoof");
  });
});
