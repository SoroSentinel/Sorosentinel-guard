import { describe, expect, it } from "vitest";

import { compileBlocklist, findBlockedTerms, parseBlocklistYaml } from "../src/wording/blocklist.ts";
import type { AttributionDef, TemplateDef } from "../src/wording/registry.ts";
import { Registry } from "../src/wording/registry.ts";
import type { RenderRequest } from "../src/wording/render.ts";
import { Renderer, isPlainHttpsUrl } from "../src/wording/render.ts";
import type { SlotType } from "../src/wording/slots.ts";
import { SLOT_TYPES, SlotValue, parseRfc3339, rfc3339, slotValue, timestampValue } from "../src/wording/slots.ts";

const TERMS = ["scam", "scammer", "fraud", "fraudulent", "fake", "stolen", "theft", "thief", "hack", "hacker", "criminal", "illegal", "malicious", "rug pull", "ponzi", "designed to", "tries to"];
const ACCOUNT = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
const CONFIG = { methodologyUrl: "https://sorosentinel.invalid/methodology", reviewUrl: "https://sorosentinel.invalid/review" };

const ATTR: AttributionDef = {
  id: "attr_v1",
  status: "counsel_approved",
  text: "Method: {method}, ruleset {ruleset_version}. Observed {as_of}. This is an indicator, not a determination of intent or wrongdoing. Methodology: {methodology_url}. Review: {review_url}.",
};
const DOMAIN_TEMPLATE: TemplateDef = {
  id: "test.domain.v1",
  signal_levels: ["caution"],
  text: "TEST ONLY. Domain {domain} at ledger {ledger}.",
  slots: { domain: "domain", ledger: "ledger" },
  attribution: "attr_v1",
  status: "counsel_approved",
};

function renderer(templates: TemplateDef[], attributions: AttributionDef[] = [ATTR]): Renderer {
  const r = Renderer.create(new Registry({ templates, attributions, blocklist: TERMS }), CONFIG);
  if (!r.ok) throw new Error(r.error.detail);
  return r.value;
}

function val(type: SlotType, raw: string): SlotValue {
  const v = slotValue(type, raw);
  if (!v.ok) throw new Error(`${type} ${raw}: ${v.error.code}`);
  return v.value;
}

function domainRequest(overrides: Partial<RenderRequest> = {}): RenderRequest {
  return {
    templateId: "test.domain.v1",
    signalLevel: "caution",
    asOf: new Date("2026-10-26T14:02:00Z"),
    method: "D-HOMEDOMAIN-MISMATCH",
    rulesetVersion: "2026.10.1",
    slots: { domain: val("domain", "example.com"), ledger: val("ledger", "1") },
    ...overrides,
  };
}

describe("blocklist", () => {
  const re = compileBlocklist(TERMS);

  // Expected values were checked against Go's compileBlocklist.
  it.each([
    ["Scammed", ["scammed"]],
    ["SCAMMERS", ["scammers"]],
    ["hacked", ["hacked"]],
    ["fraudulently", ["fraudulently"]],
    ["fakes", ["fakes"]],
    ["Ponzis", ["ponzis"]],
    ["the fake.", ["fake"]],
    ["rug-pull", ["rug-pull"]],
    ["rug_pull", ["rug_pull"]],
    ["Rug \t Pull", ["rug \t pull"]],
    ["Designed-To", ["designed-to"]],
    ["tries  to", ["tries  to"]],
    ["malicious-looking", ["malicious"]],
    ["pseudo-hack", ["hack"]],
    ["caf\u00e9 scam", ["scam"]],
    // Go's \b is ASCII-only, so a non-ASCII letter next to a term is a boundary.
    ["scam\u00e9", ["scam"]],
    ["\u00e9scam", ["scam"]],
    // Go's (?i) folds U+212A KELVIN SIGN to k and U+017F LONG S to s; ToLower maps the Kelvin sign to k.
    ["hac\u212aed", ["hacked"]],
    ["a\u017fcam", ["\u017fcam"]],
  ])("blocks %j", (text, want) => {
    expect(findBlockedTerms(re, text)).toEqual(want);
  });

  it.each(["scampi", "hackathon", "rugpull", "designedto", "fakery", "x_fake", "fake_x", "9fake", "fake9", "trying to", "\u017fcam", "hac\u212a"])(
    "does not block %j (same as Go)",
    (text) => {
      expect(findBlockedTerms(re, text)).toEqual([]);
    },
  );

  it("reports distinct terms, sorted", () => {
    expect(findBlockedTerms(re, "Fake scam, FAKE hack")).toEqual(["fake", "hack", "scam"]);
  });

  it("refuses an empty list, an empty term, or a non-ASCII term", () => {
    expect(() => compileBlocklist([])).toThrow();
    expect(() => compileBlocklist([" "])).toThrow();
    expect(() => compileBlocklist(["caf\u00e9"])).toThrow();
  });

  it("escapes regex metacharacters in terms", () => {
    const dot = compileBlocklist(["a.b"]);
    expect(findBlockedTerms(dot, "a.b")).toEqual(["a.b"]);
    expect(findBlockedTerms(dot, "axb")).toEqual([]);
  });
});

describe("parseBlocklistYaml", () => {
  it("reads the published shape", () => {
    expect(parseBlocklistYaml("# note\nterms:\n  - scam\n  - rug pull\n")).toEqual(["scam", "rug pull"]);
    expect(parseBlocklistYaml("terms:\r\n  - scam\r\n")).toEqual(["scam"]);
  });

  it.each([
    ["no terms key", "  - scam\n"],
    ["flow list", "terms: [scam]\n"],
    ["quoted item", 'terms:\n  - "scam"\n'],
    ["tab indent", "terms:\n\t- scam\n"],
    ["other key", "terms:\n  - scam\nextra: 1\n"],
    ["nested value", "terms:\n  - scam:\n      x\n"],
    ["anchor", "terms:\n  - &a scam\n"],
    ["empty", ""],
  ])("rejects %s", (_n, src) => {
    expect(() => parseBlocklistYaml(src)).toThrow();
  });

  it("rejects oversized input", () => {
    expect(() => parseBlocklistYaml(`terms:\n${"  - scam\n".repeat(10_000)}`)).toThrow();
  });
});

describe("slot values", () => {
  it.each(SLOT_TYPES.map((t) => [t] as const))("%s rejects control and bidi characters", (t) => {
    for (const bad of ["a\u202eb", "a\u2066b", "a\u200eb", "a\u061cb", "a\nb", "a\u0000b", "a\u007fb", "a\u0085b", "a\ud800b"]) {
      const v = slotValue(t, bad);
      expect(v.ok).toBe(false);
      if (!v.ok) expect(v.error.code).toBe("invalid_slot_value");
    }
  });

  it.each([
    ["weight", "0", "0"],
    ["weight", "255", "255"],
    ["weight", "007", "7"],
    ["ledger", "4294967295", "4294967295"],
    ["ledger", "0001", "1"],
    ["domain", "Example.COM.", "example.com"],
    ["wasm_hash", "AB".repeat(32), "ab".repeat(32)],
    ["asset_key", "native", "native"],
    ["signer_key", `P${"A".repeat(60)}`, `P${"A".repeat(60)}`],
    ["signer_key", `T${"A".repeat(55)}`, `T${"A".repeat(55)}`],
    ["timestamp", "2026-10-26T14:02:31.9+02:00", "2026-10-26T12:02:31Z"],
  ] as const)("%s accepts %j", (t, raw, fact) => {
    expect(val(t, raw).fact).toBe(fact);
  });

  it.each([
    ["weight", "256"],
    ["weight", "-1"],
    ["weight", "+1"],
    ["weight", " 1"],
    ["weight", ""],
    ["weight", "1e2"],
    ["ledger", "0"],
    ["ledger", "4294967296"],
    ["ledger", "99999999999999999999999"],
    ["ledger", "visit example.org"],
    ["account", `M${"A".repeat(68)}`],
    ["account", "native"],
    ["contract", ACCOUNT],
    ["domain", "ex\u0430mple.com"], // Cyrillic a (U+0430)
    ["domain", "localhost"],
    ["signer_key", `C${"A".repeat(55)}`],
    ["signer_key", `P${"A".repeat(59)}`],
    ["timestamp", "2026-10-26"],
    ["timestamp", "2026-02-29T00:00:00Z"],
    ["timestamp", "0001-01-01T00:00:00Z"],
    ["timestamp", "2026-10-26t14:02:31Z"],
  ] as const)("%s rejects %j", (t, raw) => {
    const v = slotValue(t, raw);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.error.code).toBe("invalid_slot_value");
  });

  it("parses RFC 3339 the way Go does, including its lenient fallback", () => {
    const p = (s: string) => {
      const d = parseRfc3339(s);
      return d === null ? null : rfc3339(d);
    };
    expect(p("2026-10-26T4:02:31Z")).toBe("2026-10-26T04:02:31Z");
    expect(p("2026-10-26T00:00:00+24:00")).toBe("2026-10-25T00:00:00Z");
    expect(p("2026-10-26T14:02:31,123Z")).toBe("2026-10-26T14:02:31Z");
    expect(p("2026-10-26T14:02:31+25:00")).toBeNull();
    expect(p("2026-10-26T24:00:00Z")).toBeNull();
    expect(p("2026-10-26T14:02:60Z")).toBeNull();
    expect(p("2026-04-31T00:00:00Z")).toBeNull();
  });

  it("rejects an invalid or zero date", () => {
    expect(timestampValue(new Date(Number.NaN)).ok).toBe(false);
    expect(timestampValue(new Date("0001-01-01T00:00:00Z")).ok).toBe(false);
  });

  it("cannot be constructed outside the validators", () => {
    expect(() => new SlotValue(Symbol("SlotValue"), "domain", "anything", "anything")).toThrow(TypeError);
  });
});

describe("renderer config", () => {
  it.each([
    "https://sorosentinel.invalid/methodology",
    "HTTPS://sorosentinel.invalid",
    "https://sorosentinel.invalid:8443/a?b=c#d",
    "https://[::1]/review",
  ])("accepts %j", (u) => {
    expect(isPlainHttpsUrl(u)).toBe(true);
  });

  it.each([
    "http://sorosentinel.invalid",
    "https://",
    "https:sorosentinel.invalid",
    "//sorosentinel.invalid",
    "https://user@sorosentinel.invalid",
    "https://@sorosentinel.invalid",
    "https://sorosentinel.invalid:abc",
    "https://soro sentinel.invalid",
    "https://sorosentinel.invalid/%zz",
    "https://sorosentinel.invalid/\u202e",
    "https://sorosentinel.invalid/\n",
    "https://sorosentinel.invalid\\@evil.example",
    "javascript:alert(1)",
    "",
  ])("rejects %j", (u) => {
    expect(isPlainHttpsUrl(u)).toBe(false);
    const r = Renderer.create(new Registry({ templates: [], attributions: [], blocklist: TERMS }), { ...CONFIG, reviewUrl: u });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("invalid_slot_value");
  });
});

describe("render", () => {
  it("renders an approved template", () => {
    const r = renderer([DOMAIN_TEMPLATE]).render(domainRequest());
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.statement.text).toBe("TEST ONLY. Domain example.com at ledger 1.");
  });

  it.each<[string, Partial<TemplateDef>]>([
    ["declares a reserved slot", { text: "TEST ONLY. {domain} {ledger} {as_of}.", slots: { domain: "domain", ledger: "ledger", as_of: "timestamp" } }],
    ["carries a blocked term", { text: "TEST ONLY. Fake {domain} at {ledger}." }],
    ["has non-ASCII text", { text: "TEST ONLY. Domain {domain} at ledger {ledger}\u2026" }],
    ["has an undeclared placeholder", { text: "TEST ONLY. {domain} {ledger} {other}." }],
    ["has an unused slot", { text: "TEST ONLY. {domain}." }],
    ["has an unmatched brace", { text: "TEST ONLY. {domain} {ledger" }],
    ["has an unknown slot type", { slots: { domain: "free_text", ledger: "ledger" } }],
    ["sets both levels and severities", { severities: ["high"] }],
    ["sets neither levels nor severities", { signal_levels: [] }],
    ["has an unknown signal level", { signal_levels: ["caution", "malicious"] }],
    ["has a bad id", { id: "Test.Domain" }],
    ["names a missing attribution", { attribution: "nope_v1" }],
  ])("refuses an approved template that %s", (_n, change) => {
    const t = { ...DOMAIN_TEMPLATE, ...change };
    const r = renderer([t]).render(domainRequest({ templateId: t.id }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("invalid_template");
  });

  it("refuses an approved attribution without the standard disclaimer", () => {
    const attr = { ...ATTR, text: "Method: {method}. Observed {as_of}. {methodology_url} {review_url}." };
    const r = renderer([DOMAIN_TEMPLATE], [attr]).render(domainRequest());
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("invalid_template");
  });

  it("checks approval before lint", () => {
    const r = renderer([{ ...DOMAIN_TEMPLATE, status: "retired", text: "fake" }]).render(domainRequest());
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("not_approved");
  });

  it("uses severities for finding templates", () => {
    const t: TemplateDef = { ...DOMAIN_TEMPLATE, signal_levels: null, severities: ["high"] };
    const rnd = renderer([t]);
    const { signalLevel: _drop, ...base } = domainRequest();
    expect(rnd.render({ ...base, severity: "high" }).ok).toBe(true);
    const low = rnd.render({ ...base, severity: "low" });
    expect(low.ok).toBe(false);
    if (!low.ok) expect(low.error.code).toBe("level_not_allowed");
    // A signal level does not satisfy a finding template.
    const lvl = rnd.render(domainRequest());
    expect(lvl.ok).toBe(false);
    if (!lvl.ok) expect(lvl.error.code).toBe("level_not_allowed");
  });

  it.each<[string, Partial<RenderRequest>, string]>([
    ["null as_of", { asOf: null }, "missing_slot"],
    ["invalid as_of", { asOf: new Date(Number.NaN) }, "missing_slot"],
    ["zero as_of", { asOf: new Date("0001-01-01T00:00:00Z") }, "missing_slot"],
    ["bad ruleset version", { rulesetVersion: "latest" }, "invalid_slot_value"],
    ["lowercase method", { method: "d-x" }, "invalid_slot_value"],
  ])("fails closed on %s", (_n, change, code) => {
    const r = renderer([DOMAIN_TEMPLATE]).render(domainRequest(change));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe(code);
  });

  it("rejects a forged slot value as a type mismatch", () => {
    const forged = { type: "domain", display: "anything", fact: "anything" } as unknown as SlotValue;
    const r = renderer([DOMAIN_TEMPLATE]).render(domainRequest({ slots: { domain: forged, ledger: val("ledger", "1") } }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("slot_type_mismatch");
  });

  it("returns facts, never prose, on failure; hostile slot names stay data", () => {
    const slots = JSON.parse('{"__proto__": 1}') as Record<string, SlotValue>;
    slots["__proto__"] = val("ledger", "2");
    const r = renderer([DOMAIN_TEMPLATE]).render(
      domainRequest({ slots: { ...slots, domain: val("domain", "example.com"), ledger: val("ledger", "1") } }),
    );
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.error.code).toBe("unexpected_slot");
    expect(r).not.toHaveProperty("statement");
    expect(Object.getPrototypeOf(r.facts)).toBe(Object.prototype);
    expect(Object.hasOwn(r.facts, "__proto__")).toBe(true);
    expect(r.facts).toMatchObject({ domain: "example.com", ledger: "1", as_of: "2026-10-26T14:02:00Z" });
  });

  it("blocks terms that arrive through slot values", () => {
    const r = renderer([DOMAIN_TEMPLATE]).render(domainRequest({ slots: { domain: val("domain", "scammers.example"), ledger: val("ledger", "1") } }));
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe("blocked_term");
      expect(r.facts["domain"]).toBe("scammers.example");
    }
  });

  it("does not share the caller's Date", () => {
    const asOf = new Date("2026-10-26T14:02:00Z");
    const r = renderer([DOMAIN_TEMPLATE]).render(domainRequest({ asOf }));
    asOf.setUTCFullYear(2000);
    if (r.ok) expect(r.statement.asOf.toISOString()).toBe("2026-10-26T14:02:00.000Z");
  });

  it("rejects duplicate ids", () => {
    expect(() => new Registry({ templates: [DOMAIN_TEMPLATE, DOMAIN_TEMPLATE], attributions: [ATTR], blocklist: TERMS })).toThrow();
    expect(() => new Registry({ templates: [], attributions: [ATTR, ATTR], blocklist: TERMS })).toThrow();
  });
});
