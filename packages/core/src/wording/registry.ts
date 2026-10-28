import { compileBlocklist, findBlockedTerms, goFields } from "./blocklist.ts";
import { isSlotType } from "./slots.ts";

/**
 * Template registry and lint, ported from sorosentinel-intel
 * internal/wording (registry.go, lint.go). Templates are data compiled in
 * from Intel's pinned wording files; fields are plain strings so that lint,
 * not the type system, decides what is acceptable (as in Go).
 */

export type TemplateStatus = "draft" | "counsel_approved" | "retired";
export type PublicSignal = "consistent" | "no_signals" | "caution" | "high_caution";

export interface TemplateDef {
  readonly id: string;
  readonly applies_to?: { readonly entity_type?: string; readonly detector?: string; readonly finding?: string };
  readonly signal_levels?: readonly string[] | null;
  /** Set instead of signal_levels for Guard finding templates. */
  readonly severities?: readonly string[] | null;
  readonly text: string;
  readonly slots?: Readonly<Record<string, string>> | null;
  readonly attribution: string;
  readonly status: string;
}

export interface AttributionDef {
  readonly id: string;
  readonly text: string;
  readonly status: string;
}

export interface RegistryInput {
  readonly templates: readonly TemplateDef[];
  readonly attributions: readonly AttributionDef[];
  readonly blocklist: readonly string[];
}

/** Internal, normalized template: slot names in a Map so no key can reach Object.prototype. */
export interface Template {
  readonly id: string;
  readonly signalLevels: readonly string[];
  readonly severities: readonly string[];
  readonly text: string;
  readonly slots: ReadonlyMap<string, string>;
  readonly attribution: string;
  readonly status: string;
}

export interface Problem {
  readonly where: string;
  readonly msg: string;
}

// Filled by the renderer from the request and config; templates may use them but must not declare them.
export const RESERVED_SLOTS: ReadonlySet<string> = new Set(["as_of", "method", "ruleset_version", "methodology_url", "review_url"]);

// Every attribution must carry these (PRD §5.1 L4).
const REQUIRED_ATTRIBUTION_SLOTS = ["as_of", "method", "methodology_url", "review_url"] as const;

const TEMPLATE_ID = /^[a-z0-9_]+(\.[a-z0-9_]+)*\.v[0-9]+$/;
export const SLOT_NAME = /^[a-z][a-z0-9_]*$/;
const SIGNAL_LEVELS: ReadonlySet<string> = new Set(["consistent", "no_signals", "caution", "high_caution"]);
const SEVERITIES: ReadonlySet<string> = new Set(["critical", "high", "medium", "low", "info"]);
const STATUSES: ReadonlySet<string> = new Set(["draft", "counsel_approved", "retired"]);

const q = (s: string): string => JSON.stringify(s);

/** An immutable set of templates, attributions and the blocklist. */
export class Registry {
  readonly #templates = new Map<string, Template>();
  readonly #attributions = new Map<string, AttributionDef>();
  readonly #blocked: RegExp;

  /** Rejects duplicates and a bad blocklist (throws). Content problems are reported by lint and enforced again at render time. */
  constructor(input: RegistryInput) {
    this.#blocked = compileBlocklist(input.blocklist);
    for (const t of input.templates) {
      if (this.#templates.has(t.id)) throw new Error(`duplicate template id ${q(t.id)}`);
      this.#templates.set(t.id, {
        id: t.id,
        signalLevels: [...(t.signal_levels ?? [])],
        severities: [...(t.severities ?? [])],
        text: t.text,
        slots: new Map(Object.entries(t.slots ?? {})),
        attribution: t.attribution,
        status: t.status,
      });
    }
    for (const a of input.attributions) {
      if (this.#attributions.has(a.id)) throw new Error(`duplicate attribution id ${q(a.id)}`);
      this.#attributions.set(a.id, { id: a.id, text: a.text, status: a.status });
    }
  }

  template(id: string): Template | undefined {
    return this.#templates.get(id);
  }

  attribution(id: string): AttributionDef | undefined {
    return this.#attributions.get(id);
  }

  /** Distinct blocklisted terms found in text, lowercased and sorted. */
  blockedTerms(text: string): string[] {
    return findBlockedTerms(this.#blocked, text);
  }

  /** Checks every template and attribution. Empty means fit to render (approval is checked at render time). */
  lint(): Problem[] {
    const out: Problem[] = [];
    for (const id of [...this.#templates.keys()].sort()) {
      const t = this.#templates.get(id);
      if (t !== undefined) for (const msg of this.lintTemplate(t)) out.push({ where: `template ${id}`, msg });
    }
    for (const id of [...this.#attributions.keys()].sort()) {
      const a = this.#attributions.get(id);
      if (a !== undefined) for (const msg of this.lintAttribution(a)) out.push({ where: `attribution ${id}`, msg });
    }
    return out;
  }

  lintTemplate(t: Template): string[] {
    const p: string[] = [];
    if (!TEMPLATE_ID.test(t.id)) p.push("id must look like name.part.vN");
    p.push(...lintStatus(t.status));
    if (t.signalLevels.length > 0 && t.severities.length > 0) {
      p.push("set either signal_levels (entity signals) or severities (findings), not both");
    } else if (t.signalLevels.length === 0 && t.severities.length === 0) {
      p.push("signal_levels is empty and no severities are set");
    }
    for (const l of t.signalLevels) if (!SIGNAL_LEVELS.has(l)) p.push(`unknown signal level ${q(l)}`);
    for (const s of t.severities) if (!SEVERITIES.has(s)) p.push(`unknown severity ${q(s)}`);
    if (!this.#attributions.has(t.attribution)) p.push(`attribution ${q(t.attribution)} not found`);
    for (const [name, typ] of t.slots) {
      if (RESERVED_SLOTS.has(name)) p.push(`slot ${q(name)} is reserved and must not be declared`);
      if (!SLOT_NAME.test(name)) p.push(`bad slot name ${q(name)}`);
      if (!isSlotType(typ)) p.push(`slot ${q(name)} has unknown type ${q(typ)}`);
    }
    const [used, textProblems] = this.lintText(t.text);
    p.push(...textProblems);
    for (const name of used) {
      if (!t.slots.has(name) && !RESERVED_SLOTS.has(name)) p.push(`placeholder {${name}} is not declared in slots`);
    }
    for (const name of t.slots.keys()) if (!used.has(name)) p.push(`slot ${q(name)} is declared but unused`);
    return p.sort();
  }

  lintAttribution(a: AttributionDef): string[] {
    const p = lintStatus(a.status);
    const [used, textProblems] = this.lintText(a.text);
    p.push(...textProblems);
    for (const name of used) if (!RESERVED_SLOTS.has(name)) p.push(`placeholder {${name}} is not a reserved slot`);
    for (const name of REQUIRED_ATTRIBUTION_SLOTS) if (!used.has(name)) p.push(`missing required placeholder {${name}}`);
    if (!a.text.includes("not a determination of intent or wrongdoing")) {
      p.push('missing "not a determination of intent or wrongdoing"');
    }
    return p.sort();
  }

  /**
   * Shared text rules: non-empty, printable ASCII only (blocks homoglyph
   * evasion of the blocklist), well-formed placeholders, no blocked terms.
   */
  lintText(text: string): [Set<string>, string[]] {
    const p: string[] = [];
    if (goFields(text).length === 0) p.push("text is empty");
    for (let i = 0; i < text.length; i++) {
      const c = text.charCodeAt(i);
      if ((c < 0x20 && c !== 0x0a) || c >= 0x7f) {
        p.push("text must be printable ASCII");
        break;
      }
    }
    const used = new Set<string>();
    const err = walkText(text, () => {}, (name) => used.add(name));
    if (err !== null) p.push(err);
    const terms = this.blockedTerms(text);
    if (terms.length > 0) p.push(`blocked terms: ${terms.join(", ")}`);
    return [used, p];
  }

  /** Checks free-standing public prose for blocked terms, reporting each hit by line. */
  lintDocument(name: string, text: string): Problem[] {
    const out: Problem[] = [];
    for (const [i, line] of text.split("\n").entries()) {
      const terms = this.blockedTerms(line);
      if (terms.length > 0) out.push({ where: `${name}:${i + 1}`, msg: `blocked terms: ${terms.join(", ")}` });
    }
    return out;
  }
}

function lintStatus(s: string): string[] {
  return STATUSES.has(s) ? [] : [`unknown status ${q(s)}`];
}

/** Splits text into literal runs and placeholder names. Returns an error message or null. */
export function walkText(text: string, lit: (s: string) => void, slot: (name: string) => void): string | null {
  let rest = text;
  while (rest.length > 0) {
    const open = rest.search(/[{}]/);
    if (open < 0) {
      lit(rest);
      return null;
    }
    if (rest[open] === "}") return "unmatched '}'";
    lit(rest.slice(0, open));
    const end = rest.slice(open + 1).search(/[{}]/);
    if (end < 0 || rest[open + 1 + end] !== "}") return "unmatched '{'";
    const name = rest.slice(open + 1, open + 1 + end);
    if (!SLOT_NAME.test(name)) return `bad placeholder {${name}}`;
    slot(name);
    rest = rest.slice(open + end + 2);
  }
  return null;
}
