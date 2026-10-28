import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import type { Severity } from "../../src/rules/types.ts";
import { parseBlocklistYaml } from "../../src/wording/blocklist.ts";
import type { AttributionDef, PublicSignal, TemplateDef } from "../../src/wording/registry.ts";
import { Registry } from "../../src/wording/registry.ts";
import type { RenderResult } from "../../src/wording/render.ts";
import { Renderer } from "../../src/wording/render.ts";
import type { SlotType, SlotValue, WordingErrorCode } from "../../src/wording/slots.ts";
import { parseRfc3339, slotValue } from "../../src/wording/slots.ts";

// Pinned from sorosentinel-intel (intel-schemas/PINNED); never edited here.
const pinned = (name: string) => readFileSync(new URL(`../../../../intel-schemas/${name}`, import.meta.url), "utf8");

interface Case {
  name: string;
  request: {
    template_id: string;
    signal_level?: PublicSignal;
    severity?: Severity;
    as_of: string;
    method: string;
    ruleset_version: string;
    slots: Record<string, { type: SlotType; value: string }>;
  };
  expect: { text?: string; attribution?: string; facts?: Record<string, string>; error?: WordingErrorCode };
}

const vectors = JSON.parse(pinned("render.json")) as {
  config: { methodology_url: string; review_url: string };
  attributions: AttributionDef[];
  templates: TemplateDef[];
  cases: Case[];
};

const registry = new Registry({
  templates: vectors.templates,
  attributions: vectors.attributions,
  blocklist: parseBlocklistYaml(pinned("blocklist.yaml")),
});

const created = Renderer.create(registry, { methodologyUrl: vectors.config.methodology_url, reviewUrl: vectors.config.review_url });
if (!created.ok) throw new Error(created.error.detail);
const renderer = created.value;

// Mirrors Intel's renderCase: slot validation errors surface before Render.
function renderCase(c: Case): RenderResult | { ok: false; error: { code: WordingErrorCode } } {
  let asOf: Date | null = null;
  if (c.request.as_of !== "") {
    asOf = parseRfc3339(c.request.as_of);
    if (asOf === null) throw new Error(`bad as_of in vector ${c.name}`);
  }
  const slots: Record<string, SlotValue> = {};
  for (const [name, s] of Object.entries(c.request.slots)) {
    const v = slotValue(s.type, s.value);
    if (!v.ok) return v;
    slots[name] = v.value;
  }
  return renderer.render({
    templateId: c.request.template_id,
    ...(c.request.signal_level !== undefined && { signalLevel: c.request.signal_level }),
    ...(c.request.severity !== undefined && { severity: c.request.severity }),
    asOf,
    method: c.request.method,
    rulesetVersion: c.request.ruleset_version,
    slots,
  });
}

describe("renderer matches Intel's render vectors", () => {
  it("has cases and a lint-clean registry", () => {
    expect(vectors.cases.length).toBeGreaterThan(0);
    expect(registry.lint()).toEqual([]);
  });

  it.each(vectors.cases.map((c) => [c.name, c] as const))("%s", (_name, c) => {
    const got = renderCase(c);
    if (c.expect.error !== undefined) {
      expect(got.ok).toBe(false);
      if (!got.ok) expect(got.error.code).toBe(c.expect.error);
      // Fail closed: no prose on any error path.
      expect(got).not.toHaveProperty("statement");
      return;
    }
    if (!got.ok) throw new Error(`unexpected error ${got.error.code}`);
    if (!("statement" in got)) throw new Error("no statement");
    expect(got.statement.text).toBe(c.expect.text);
    expect(got.statement.attribution).toBe(c.expect.attribution);
    expect(got.statement.facts).toEqual(c.expect.facts);
  });
});

describe("pinned blocklist", () => {
  it("is read in full", () => {
    const terms = parseBlocklistYaml(pinned("blocklist.yaml"));
    expect(terms).toContain("rug pull");
    expect(terms).toContain("tries to");
    expect(terms.length).toBeGreaterThanOrEqual(17);
  });
});
