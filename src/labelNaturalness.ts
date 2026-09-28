import { registrableLabelOf } from "./domainShape.js";
import {
  getPrivateAwareRegistrableDomain,
  getRegistrableDomain as builtinGetRegistrableDomain,
} from "./psl.js";
import type {
  MetricsDependencies,
  RegistrableLabelNaturalness,
  RegistrableLabelNaturalnessStatus,
} from "./types.js";

function round4(value: number): number {
  // `+ 0` folds -0 to 0 so a JSON round-trip compares equal.
  return Math.round(value * 1e4) / 1e4 + 0;
}

/**
 * Labels the model may see: ASCII letters/digits/hyphens that are not punycode.
 * A letter-bigram model over an ACE (`xn--`) encoding or over non-ASCII
 * codepoints measures the encoding, not the name, so those are left unscored.
 */
function isScorableLabel(label: string): boolean {
  return /^[a-z0-9-]+$/.test(label) && !label.startsWith("xn--");
}

/**
 * Identify the *registrable-domain label* of `domain` and, only when the caller
 * supplies a naturalness model, record the model's score for it (see
 * RegistrableLabelNaturalness).
 *
 * The label is the leftmost label of the registrable domain from the built-in
 * PSL resolver (or `options.getRegistrableDomain` when supplied), so compound
 * suffixes resolve correctly (`mail.dcm-hldgs.co.jp` -> `dcm-hldgs`) and the
 * label a random subdomain hides behind is still found (`dessert.axgporj.com`
 * -> `axgporj`). Beneath a PSL private suffix the tenant label is measured
 * instead of the shared provider label (`acme.github.io` -> `acme`), since the
 * tenant is the registrant-chosen part.
 *
 * Normalization: the input is trimmed, lower-cased, and stripped of one trailing
 * dot; the label is passed to the model lower-cased. Short labels are measured
 * (see labelLength); punycode and non-ASCII labels are not (status
 * "unsupported-label"). The model's value is rounded to 4 decimals; a
 * non-finite or non-number value, a throwing model, or a non-function model
 * yields a null score with an explanatory status instead of an exception.
 *
 * The core bundles no frequency table or corpus and applies no threshold: this
 * is an observation for the caller's own policy, never a verdict or a score.
 */
export function computeRegistrableLabelNaturalness(
  domain: string | null | undefined,
  options?: Pick<MetricsDependencies, "getRegistrableDomain" | "scoreLabelNaturalness">,
): RegistrableLabelNaturalness {
  const result = (
    status: RegistrableLabelNaturalnessStatus,
    fields: Partial<RegistrableLabelNaturalness> = {},
  ): RegistrableLabelNaturalness => ({
    domain: null,
    registrableDomain: null,
    underPrivateSuffix: false,
    measuredDomain: null,
    label: null,
    labelLength: 0,
    score: null,
    status,
    ...fields,
  });

  const normalized =
    typeof domain === "string" ? domain.trim().toLowerCase().replace(/\.$/, "") : "";
  if (normalized === "") return result("no-domain");

  const resolver = options?.getRegistrableDomain ?? builtinGetRegistrableDomain;
  const resolved = resolver(normalized);
  if (!resolved) return result("no-registrable-domain", { domain: normalized });
  const registrableDomain = resolved.toLowerCase();

  // The private-suffix tenant refines the resolver's answer only when it sits
  // at or beneath it; a caller resolver that disagrees with the built-in PSL
  // keeps its own registrable domain rather than a label it never produced.
  const builtinPrivate = getPrivateAwareRegistrableDomain(normalized);
  const privateRegistrable =
    builtinPrivate !== null &&
    (builtinPrivate === registrableDomain || builtinPrivate.endsWith(`.${registrableDomain}`))
      ? builtinPrivate
      : null;
  const measuredDomain = privateRegistrable ?? registrableDomain;
  const label = registrableLabelOf(measuredDomain);
  const identified = {
    domain: normalized,
    registrableDomain,
    underPrivateSuffix: privateRegistrable !== null,
    measuredDomain,
    label,
    labelLength: [...label].length,
  };

  if (label === "" || !isScorableLabel(label)) return result("unsupported-label", identified);

  const model: unknown = options?.scoreLabelNaturalness;
  if (model === undefined || model === null) return result("no-model", identified);
  if (typeof model !== "function") return result("invalid-model", identified);

  let value: unknown;
  try {
    value = model(label);
  } catch {
    return result("model-error", identified);
  }
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return result("invalid-model-output", identified);
  }
  return result("measured", { ...identified, score: round4(value) });
}
