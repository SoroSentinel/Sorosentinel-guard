import type { Severity } from "../rules/types.ts";
import type { PublicSignal, Registry } from "./registry.ts";
import { walkText } from "./registry.ts";
import type { Result, WordingError, WordingErrorCode } from "./slots.ts";
import { SlotValue, hasUnsafeChar, isZeroTime, rfc3339, timestampValue } from "./slots.ts";

/**
 * The fail-closed public-text renderer, a second implementation of
 * sorosentinel-intel internal/wording/render.go (docs/project_structure.md §5).
 * Both must pass Intel's wording/vectors/render.json (`make test-contract`).
 * This is the only code path that may produce user-visible prose. On any
 * error it returns the error and the structured facts, never text.
 */

export interface RenderConfig {
  readonly methodologyUrl: string;
  readonly reviewUrl: string;
}

/** as_of is supplied by the caller (never read from the wall clock here) so output is reproducible. */
export interface RenderRequest {
  readonly templateId: string;
  /** Used by entity-signal templates. */
  readonly signalLevel?: PublicSignal;
  /** Used by Guard finding templates. */
  readonly severity?: Severity;
  readonly asOf: Date | null;
  readonly method: string;
  readonly rulesetVersion: string;
  readonly slots: Readonly<Record<string, SlotValue>>;
}

export interface Statement {
  readonly templateId: string;
  readonly signalLevel: PublicSignal | undefined;
  readonly severity: Severity | undefined;
  readonly text: string;
  readonly attribution: string;
  readonly facts: Readonly<Record<string, string>>;
  readonly asOf: Date;
  readonly method: string;
  readonly rulesetVersion: string;
  readonly methodologyUrl: string;
  readonly reviewUrl: string;
}

/** On failure, show `facts` with no prose. */
export type RenderResult =
  | { readonly ok: true; readonly statement: Statement }
  | { readonly ok: false; readonly error: WordingError; readonly facts: Readonly<Record<string, string>> };

const METHOD = /^[A-Z][A-Z0-9-]{1,63}$/;
const RULESET = /^[0-9]{4}\.[0-9]{2}\.[0-9]+$/;

export class Renderer {
  readonly #reg: Registry;
  readonly #cfg: RenderConfig;

  private constructor(reg: Registry, cfg: RenderConfig) {
    this.#reg = reg;
    this.#cfg = cfg;
  }

  /** Config URLs must be plain https URLs (code invalid_slot_value otherwise). */
  static create(reg: Registry, cfg: RenderConfig): Result<Renderer> {
    for (const u of [cfg.methodologyUrl, cfg.reviewUrl]) {
      if (!isPlainHttpsUrl(u)) {
        return { ok: false, error: { code: "invalid_slot_value", detail: "config URLs must be plain https URLs" } };
      }
    }
    return { ok: true, value: new Renderer(reg, { methodologyUrl: cfg.methodologyUrl, reviewUrl: cfg.reviewUrl }) };
  }

  render(req: RenderRequest): RenderResult {
    const r = this.#render(req);
    return "code" in r ? { ok: false, error: r, facts: facts(req) } : { ok: true, statement: r };
  }

  #render(req: RenderRequest): Statement | WordingError {
    const err = (code: WordingErrorCode, detail: string): WordingError => ({ code, detail });
    const t = this.#reg.template(req.templateId);
    if (t === undefined) return err("unknown_template", req.templateId);
    if (t.status !== "counsel_approved") return err("not_approved", `template ${t.id} is ${t.status}`);
    const tp = this.#reg.lintTemplate(t);
    if (tp.length > 0) return err("invalid_template", tp.join("; "));
    // lintTemplate has confirmed the attribution exists.
    const a = this.#reg.attribution(t.attribution) ?? { id: "", text: "", status: "" };
    if (a.status !== "counsel_approved") return err("not_approved", `attribution ${a.id} is ${a.status}`);
    const ap = this.#reg.lintAttribution(a);
    if (ap.length > 0) return err("invalid_template", ap.join("; "));
    if (t.signalLevels.length > 0) {
      if (req.signalLevel === undefined || !t.signalLevels.includes(req.signalLevel)) {
        return err("level_not_allowed", req.signalLevel ?? "");
      }
    } else if (req.severity === undefined || !t.severities.includes(req.severity)) {
      return err("level_not_allowed", req.severity ?? "");
    }

    const when = req.asOf;
    const asOf = when === null ? null : timestampValue(when);
    if (when === null || asOf === null || !asOf.ok) return err("missing_slot", "as_of");
    if (!METHOD.test(req.method)) return err("invalid_slot_value", "method");
    if (!RULESET.test(req.rulesetVersion)) return err("invalid_slot_value", "ruleset_version");

    const given = new Map(Object.entries(req.slots));
    for (const name of [...t.slots.keys()].sort()) {
      const v = given.get(name);
      if (v === undefined) return err("missing_slot", name);
      if (!(v instanceof SlotValue) || v.type !== t.slots.get(name)) return err("slot_type_mismatch", name);
    }
    for (const name of [...given.keys()].sort()) {
      if (!t.slots.has(name)) return err("unexpected_slot", name);
    }

    const display = new Map<string, string>([
      ["as_of", asOf.value.display],
      ["method", req.method],
      ["ruleset_version", req.rulesetVersion],
      ["methodology_url", this.#cfg.methodologyUrl],
      ["review_url", this.#cfg.reviewUrl],
    ]);
    for (const [name, v] of given) display.set(name, v.display);
    const text = fill(t.text, display);
    if (typeof text !== "string") return text;
    const attr = fill(a.text, display);
    if (typeof attr !== "string") return attr;
    // Second layer: slot values (e.g. attacker-chosen domains) can carry blocked terms.
    const terms = this.#reg.blockedTerms(`${text}\n${attr}`);
    if (terms.length > 0) return err("blocked_term", terms.join(", "));

    return {
      templateId: t.id,
      signalLevel: req.signalLevel,
      severity: req.severity,
      text,
      attribution: attr,
      facts: facts(req),
      asOf: new Date(when.getTime()),
      method: req.method,
      rulesetVersion: req.rulesetVersion,
      methodologyUrl: this.#cfg.methodologyUrl,
      reviewUrl: this.#cfg.reviewUrl,
    };
  }
}

/** The structured slot values of req: the fail-closed output when rendering fails. */
export function facts(req: RenderRequest): Record<string, string> {
  const out: [string, string][] = Object.entries(req.slots).map(([name, v]) => [name, v instanceof SlotValue ? v.fact : ""]);
  if (req.asOf !== null && !isZeroTime(req.asOf)) out.push(["as_of", rfc3339(req.asOf)]);
  // fromEntries defines own properties, so a "__proto__" slot name stays data.
  return Object.fromEntries(out);
}

function fill(text: string, values: ReadonlyMap<string, string>): string | WordingError {
  let out = "";
  let missing: string | null = null;
  const bad = walkText(
    text,
    (lit) => {
      out += lit;
    },
    (name) => {
      const v = values.get(name);
      if (v === undefined && missing === null) missing = name;
      out += v ?? "";
    },
  );
  if (bad !== null) return { code: "invalid_template", detail: bad };
  if (missing !== null) return { code: "missing_slot", detail: missing };
  return out;
}

/**
 * Go accepts a URL when url.Parse succeeds with scheme https, a non-empty
 * host, no userinfo, and no control or bidi characters. This check is
 * stricter (an ASCII host name or bracketed IPv6 literal, an optional numeric
 * port, no spaces or backslashes), so anything it accepts Go accepts too.
 */
export function isPlainHttpsUrl(u: string): boolean {
  if (hasUnsafeChar(u) || /[^\x21-\x7e]/.test(u) || u.includes("\\")) return false;
  const m = /^https:\/\/([^/?#]*)([/?#].*)?$/i.exec(u);
  if (m === null || m[1] === undefined) return false;
  const authority = m[1];
  if (authority.includes("@")) return false;
  if (!/^(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:.]+\])(?::[0-9]*)?$/.test(authority)) return false;
  // Go rejects malformed percent-escapes in the path and fragment; this also covers the query.
  return !/%(?![0-9A-Fa-f]{2})/.test(m[2] ?? "");
}
