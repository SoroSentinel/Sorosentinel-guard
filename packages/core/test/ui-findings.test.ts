import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import type { AnalysisResult, AnalyzeContext } from "../src/analyze.ts";
import { analyze } from "../src/index.ts";
import type { AccountEffect, BalanceEffect } from "../src/effects/types.ts";
import type { Finding, Severity } from "../src/rules/types.ts";
import type { SimulationOutcome } from "../src/simulate/simulate.ts";
import { compileBlocklist, findBlockedTerms, parseBlocklistYaml } from "../src/wording/blocklist.ts";
import type { RenderResult, Statement } from "../src/wording/render.ts";
import { Renderer } from "../src/wording/render.ts";
import type { AttributionDef, TemplateDef } from "../src/wording/registry.ts";
import { Registry } from "../src/wording/registry.ts";
import type { SlotType, SlotValue } from "../src/wording/slots.ts";
import { slotValue } from "../src/wording/slots.ts";
import type { FindingsOptions } from "../src/ui/findings.ts";
import { DEFAULT_LABELS, renderFindings } from "../src/ui/findings.ts";
import type { StubElement, StubNode } from "./ui/dom-stub.ts";
import { createDomStub } from "./ui/dom-stub.ts";

/**
 * The reference findings view (Guard #46). Prose comes only from the renderer,
 * untrusted strings are stripped and never linkified, and the tree is asserted
 * as what a screen reader sees: names, roles, heading outline, reading order.
 */

const TERMS = parseBlocklistYaml(readFileSync(new URL("../../../intel-schemas/blocklist.yaml", import.meta.url), "utf8"));

const ACCOUNT = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
const OTHER = "GB7BDSZU2AY27NMOTFE5GVNYYJPCHR5BF74JEX6J6VVB4S3PGM2VUZDQ";
const AS_OF = new Date("2026-10-27T00:01:00Z");
// Bidirectional and invisible characters, written as escapes so this file holds none.
const RLO = "\u202e";
const ZWJ = "\u200d";

const stub = createDomStub();
const view = (result: AnalysisResult, extra: Omit<FindingsOptions, "doc"> = {}): StubElement =>
  renderFindings(result, { doc: stub.doc, ...extra }) as unknown as StubElement;

const result = (over: Partial<AnalysisResult> = {}): AnalysisResult => ({
  status: "findings_present",
  txHash: "a".repeat(64),
  network: "public",
  operationCount: 1,
  effects: [],
  accountEffects: [],
  findings: [],
  notChecked: ["NC-SIMULATION"],
  snapshotStatus: "verified",
  ...over,
});

const balance = (over: Partial<BalanceEffect> = {}): BalanceEffect => ({
  account: ACCOUNT,
  asset: "native",
  deltaMin: -10_000_000n,
  deltaMax: -10_000_000n,
  assurance: "ledger",
  ...over,
});

const finding = (over: Partial<Finding> = {}): Finding => ({
  code: "G-SIGNER-ADDED",
  severity: "high",
  operationIndex: 0,
  facts: { account: ACCOUNT, signer: OTHER, signer_type: "ed25519", weight: "10" },
  statement: null,
  ...over,
});

const CONFIG = { methodologyUrl: "https://sorosentinel.invalid/methodology", reviewUrl: "https://sorosentinel.invalid/review" };
const ATTRIBUTION: AttributionDef = {
  id: "attr_v1",
  status: "counsel_approved",
  // The standard attribution Intel's lint requires, including "or wrongdoing".
  text: "Method: {method}, ruleset {ruleset_version}. Observed {as_of}. This is an indicator, not a determination of intent or wrongdoing. Methodology: {methodology_url}. Review: {review_url}.",
};
const APPROVED: TemplateDef = {
  id: "test.signer_added.v1",
  severities: ["high"],
  text: "TEST ONLY. Signer {signer} added to {account} with weight {weight}.",
  slots: { signer: "signer_key", account: "account", weight: "weight" },
  attribution: "attr_v1",
  status: "counsel_approved",
};
const DRAFT: TemplateDef = { ...APPROVED, id: "test.draft.v1", status: "draft" };

const rendererFor = (template: TemplateDef): Renderer => {
  const r = Renderer.create(new Registry({ templates: [template], attributions: [ATTRIBUTION], blocklist: TERMS }), CONFIG);
  if (!r.ok) throw new Error(`renderer setup failed: ${r.error.code} ${r.error.detail}`);
  return r.value;
};

const SLOT_BY_FACT: Record<string, SlotType> = { signer: "signer_key", account: "account", weight: "weight" };

/** Fills a template's slots from a finding's facts, the way an integrator's mapping does. */
const statementFor = (renderer: Renderer, templateId: string) => (f: Finding): RenderResult => {
  const slots: Record<string, SlotValue> = {};
  for (const [name, value] of Object.entries(f.facts)) {
    const type = SLOT_BY_FACT[name];
    if (type === undefined) continue; // this template has no signer_type slot
    const v = slotValue(type, value);
    if (!v.ok) throw new Error(`slot ${name} rejected: ${v.error.code} ${v.error.detail}`);
    slots[name] = v.value;
  }
  return renderer.render({
    templateId,
    severity: f.severity,
    asOf: AS_OF,
    method: "GUARD-RULE",
    rulesetVersion: "2026.10.1",
    slots,
  });
};

/** First element with `tag` in document order. */
const first = (node: StubNode, tag: string): StubElement | undefined => {
  if (node.kind === "text") return undefined;
  if (node.tag === tag) return node;
  for (const child of node.children) {
    const found = first(child, tag);
    if (found !== undefined) return found;
  }
  return undefined;
};

const hex = (s: string): string => Array.from(new TextEncoder().encode(s), (b) => b.toString(16).padStart(2, "0")).join("");

describe("what the issue asks the component to show", () => {
  it("shows the status, the operation count and the transaction hash", () => {
    const text = stub.textOf(view(result({ operationCount: 3, txHash: "b".repeat(64) })));
    expect(text).toContain("Findings present");
    expect(text).toContain("Operations 3");
    expect(text).toContain("b".repeat(64));
  });

  it("shows every finding, in the order analyze returned them, without truncation", () => {
    const severities: Severity[] = ["critical", "high", "medium", "low", "info"];
    const wanted = [...severities, severities[0] as Severity, severities[1] as Severity];
    const findings = wanted.map((severity, i): Finding => finding({ code: "G-ACCOUNT-CONTROL", severity, operationIndex: i }));
    const list = first(view(result({ findings })), "ol");
    if (list === undefined) throw new Error("no findings list");
    expect(list.children).toHaveLength(7);
    const data = (child: StubNode, attr: string) =>
      child.kind === "element" ? child.attrs.find(([k]) => k === attr)?.[1] : undefined;
    expect(list.children.map((c) => data(c, "data-code"))).toEqual(findings.map(() => "G-ACCOUNT-CONTROL"));
    expect(list.children.map((c) => data(c, "data-severity"))).toEqual(wanted);
  });

  it("puts the worst case of each balance effect first", () => {
    const el = view(result({ effects: [balance({ deltaMin: -500n, deltaMax: -500n }), balance({ deltaMin: 1n, deltaMax: null })] }));
    const tbody = first(el, "tbody");
    if (tbody === undefined) throw new Error("no effects table body");
    const rows = tbody.children.map((row) =>
      row.kind === "element" ? row.children.map((cell) => stub.textOf(cell)) : [],
    );
    expect(rows.map((r) => r[2])).toEqual(["-500", "1"]);
    expect(rows[0]?.[3]).toBe("-500");
    // A missing upper bound is stated, and never shown as zero (§3.9).
    expect(rows[1]?.[3]).toBe("no upper bound");
  });

  it("keeps a findings-free result readable and never says safe", () => {
    const text = stub.textOf(view(result({ status: "no_issues_found", findings: [] })));
    expect(text).toContain("No issues found");
    expect(text.toLowerCase()).not.toMatch(/\b(safe|clean|trusted|secure)\b/);
    expect(text).toContain("Findings (0)");
  });
});

describe("prose comes only from the renderer", () => {
  it("with no renderer injected, each finding degrades to its facts", () => {
    const el = view(result({ findings: [finding()] }));
    expect(stub.serialize(el)).toContain('data-wording="no_renderer"');
    expect(stub.textOf(el)).toContain(OTHER);
  });

  it("with an approved template, the sentence and its attribution are shown", () => {
    const text = stub.textOf(
      view(result({ findings: [finding()] }), { statementFor: statementFor(rendererFor(APPROVED), "test.signer_added.v1") }),
    );
    expect(text).toContain("TEST ONLY. Signer");
    expect(text).toContain("not a determination of intent or wrongdoing");
  });

  it("with a draft template the renderer refuses and only facts are shown", () => {
    // Today's real state: every Guard template in Intel is draft (Intel #32).
    const el = view(result({ findings: [finding()] }), {
      statementFor: statementFor(rendererFor(DRAFT), "test.draft.v1"),
    });
    expect(stub.serialize(el)).toContain('data-wording="not_approved"');
    expect(stub.textOf(el)).not.toContain("TEST ONLY");
    expect(stub.textOf(el)).toContain(OTHER);
  });

  it("never shows a wording error detail, which is for logs", () => {
    const detail = "template test.draft.v1 is draft";
    const el = view(result({ findings: [finding()] }), {
      statementFor: () => ({ ok: false, error: { code: "missing_slot", detail }, facts: {} }),
    });
    expect(stub.textOf(el)).not.toContain(detail);
    expect(stub.serialize(el)).toContain('data-wording="missing_slot"');
  });

  it("renders a successful statement verbatim and adds no sentences around it", () => {
    const statement: Statement = {
      templateId: "test.signer_added.v1",
      signalLevel: undefined,
      severity: "high",
      text: "RENDERED SENTENCE",
      attribution: "RENDERED ATTRIBUTION",
      facts: { account: ACCOUNT },
      asOf: AS_OF,
      method: "GUARD-RULE",
      rulesetVersion: "2026.10.1",
      methodologyUrl: CONFIG.methodologyUrl,
      reviewUrl: CONFIG.reviewUrl,
    };
    const html = stub.serialize(view(result({ findings: [finding()] }), { statementFor: () => ({ ok: true, statement }) }));
    expect(html).toContain("<p>RENDERED SENTENCE</p>");
    expect(html).toContain('<p data-role="attribution">RENDERED ATTRIBUTION</p>');
    expect(html).toContain("<details><summary>Facts</summary>");
  });

  it("its own field labels carry no blocklisted term and are not sentences", () => {
    const blocked = compileBlocklist(TERMS);
    for (const [name, label] of Object.entries(DEFAULT_LABELS)) {
      expect(findBlockedTerms(blocked, label), `${name} is blocklisted`).toEqual([]);
      expect(label, `${name} looks like a sentence`).not.toMatch(/[.!?]/);
      expect(label.split(" ").length, `${name} is too long`).toBeLessThanOrEqual(4);
    }
  });
});

describe("untrusted strings cannot become markup, control characters or links", () => {
  it("strips bidi overrides, zero-width characters, NUL and newlines", () => {
    const el = view(
      result({
        effects: [balance({ asset: `USD${RLO}C:issuer` })],
        accountEffects: [{ kind: "home_domain", operationIndex: 0, account: ACCOUNT, bytesHex: hex(`pay${RLO}pal.exe`) }],
        findings: [finding({ facts: { note: `pay${ZWJ}pal\u0000invoice\nnumber` } })],
      }),
    );
    const text = stub.textOf(el);
    expect(text).not.toContain(RLO);
    expect(text).not.toContain(ZWJ);
    expect(text).not.toContain("\u0000");
    expect(text).not.toContain("\n");
    expect(text).toContain("USDC:issuer");
    expect(text).toContain("paypal.exe");
    expect(text).toContain("paypalinvoicenumber");
  });

  it("writes values as text nodes, so markup in a value is inert", () => {
    const el = view(
      result({
        effects: [balance({ asset: '<img src=x onerror="alert(1)">' })],
        findings: [finding({ facts: { memo: '<a href="https://evil.invalid">Sign here</a>' } })],
      }),
    );
    const html = stub.serialize(el);
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img");
    // The hostile value is inert escaped text; it stays a value and never a tag.
    expect(html).toContain("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;");
    // The hostile memo is inert text, never an anchor: nothing is linkified.
    expect(html).toContain("&lt;a href=&quot;https://evil.invalid");
    expect(stub.tags(el)).not.toContain("a");
  });

  it("links only the renderer's own config URLs", () => {
    const el = view(result({ findings: [finding()] }), {
      statementFor: statementFor(rendererFor(APPROVED), "test.signer_added.v1"),
    });
    expect(stub.attributes(el, "href")).toEqual([CONFIG.methodologyUrl, CONFIG.reviewUrl]);
    expect(stub.attributes(el, "rel")).toEqual(["noreferrer", "noreferrer"]);
  });

  it("refuses to link a config URL that is not plain https", () => {
    const statement: Statement = {
      templateId: "t.v1",
      signalLevel: undefined,
      severity: "high",
      text: "RENDERED",
      attribution: "ATTRIBUTION",
      facts: {},
      asOf: AS_OF,
      method: "GUARD-RULE",
      rulesetVersion: "2026.10.1",
      methodologyUrl: "javascript:alert(1)",
      reviewUrl: "https://evil.invalid\u202e/methodology",
    };
    const html = stub.serialize(view(result({ findings: [finding()] }), { statementFor: () => ({ ok: true, statement }) }));
    expect(html).not.toContain("<a ");
    expect(html).not.toContain("javascript:");
  });

  it("caps a long hostile value instead of rendering it whole", () => {
    const html = stub.serialize(view(result({ findings: [finding({ facts: { note: "x".repeat(10_000) } })] })));
    expect(html).toContain("…");
    expect(html.length).toBeLessThan(2_000);
  });

  it("treats an overridden label as untrusted too", () => {
    const el = view(result(), { labels: { region: `Review ${RLO}<b>now</b>` } });
    expect(stub.textOf(el)).toContain("Review <b>now</b>");
    expect(stub.serialize(el)).not.toContain("<b>");
  });

  it("reads hostile input from a real analysis without emitting markup", () => {
    const { xdr, network_passphrase } = JSON.parse(
      readFileSync(new URL("../../../fixtures/tx/hostile/hashx_signer.json", import.meta.url), "utf8"),
    ) as { xdr: string; network_passphrase: string };
    const ctx: AnalyzeContext = { networkPassphrase: network_passphrase, asOf: AS_OF };
    const html = stub.serialize(view(analyze(xdr, ctx)));
    expect(html).toMatch(/^<section /);
    expect(html).not.toMatch(/<script|onerror=|javascript:/);
    expect(html).toContain("G-SIGNER-ADDED");
    expect(html).toContain('data-severity="critical"');
  });
});

describe("keyboard and screen-reader accessible structure", () => {
  it("is one named region whose heading is its name", () => {
    const el = view(result());
    expect(el.attrs).toContainEqual(["role", "region"]);
    expect(el.attrs).toContainEqual(["aria-label", "Transaction review"]);
    const heading = el.children[0];
    expect(heading !== undefined && heading.kind === "element" && heading.tag).toBe("h2");
  });

  it("announces the status through exactly one live region", () => {
    const el = view(result({ status: "partial" }));
    expect(stub.attributes(el, "role").filter((r) => r === "status")).toEqual(["status"]);
    expect(stub.textOf(el)).toContain("Status: Partial");
  });

  it("names every section and keeps the heading outline unbroken", () => {
    const el = view(
      result({
        findings: [finding()],
        effects: [balance()],
        accountEffects: [{ kind: "merge", operationIndex: 1, account: ACCOUNT, destination: OTHER }],
        notChecked: ["NC-SIMULATION", "NC-MEMO-REQUIRED"],
        simulation: { status: "skipped", reason: "no_rpc" },
      }),
    );
    expect(stub.attributes(el, "aria-label")).toEqual([
      "Transaction review",
      "Balance effects",
      "Account changes",
      "Findings",
      "Not checked",
      "Simulation",
    ]);
    expect(stub.tags(el).filter((t) => /^h[1-6]$/.test(t))).toEqual(["h2", "h3", "h3", "h3", "h4", "h3", "h3"]);
  });

  it("moves the whole outline when the host page already uses h2", () => {
    const el = view(result({ findings: [finding()] }), { headingLevel: 3 });
    expect(stub.tags(el).filter((t) => /^h[1-6]$/.test(t))).toEqual(["h3", "h4", "h5", "h4"]);
  });

  it("caps heading levels at h6 whatever the host asks for", () => {
    const el = view(result({ findings: [finding()] }), { headingLevel: 99 });
    expect(stub.tags(el).filter((t) => /^h[1-6]$/.test(t))).toEqual(["h4", "h5", "h6", "h5"]);
  });

  it("states severity as text, never color alone", () => {
    const text = stub.textOf(view(result({ findings: [finding({ severity: "critical" }), finding({ severity: "low" })] })));
    expect(text).toContain("Critical G-SIGNER-ADDED");
    expect(text).toContain("Low G-SIGNER-ADDED");
  });

  it("gives the balance table a caption and column headers", () => {
    const html = stub.serialize(view(result({ effects: [balance({ assurance: "contract_reported" })] })));
    expect(html).toContain("<caption>Balance effects</caption>");
    expect(html.match(/<th scope="col">/g)).toHaveLength(5);
    expect(html).toContain("contract_reported");
  });

  it("keeps facts keyboard-reachable with a native disclosure and no script", () => {
    const el = view(result({ findings: [finding()] }), {
      statementFor: statementFor(rendererFor(APPROVED), "test.signer_added.v1"),
    });
    expect(stub.tags(el)).toContain("details");
    expect(stub.tags(el)).toContain("summary");
    expect(stub.serialize(el)).not.toMatch(/onclick|onfocus|javascript:/);
  });

  it("shows the not-checked codes rather than implying completeness", () => {
    const text = stub.textOf(view(result({ notChecked: ["NC-DECODE", "NC-SIMULATION", "NC-NETWORK-COVERAGE"] })));
    expect(text).toContain("Not checked NC-DECODE NC-SIMULATION NC-NETWORK-COVERAGE");
  });

  it("shows operation_index even when the rule did not repeat it", () => {
    expect(stub.serialize(view(result({ findings: [finding({ operationIndex: 4, facts: {} })] })))).toContain(
      "<dt>operation_index</dt><dd>4</dd>",
    );
    // A transaction-level finding says "none", not the word "null".
    expect(stub.serialize(view(result({ findings: [finding({ operationIndex: null, facts: {} })] })))).toContain(
      "<dt>operation_index</dt><dd>none</dd>",
    );
  });

  it("marks an unanalyzable result with its reason and no hash", () => {
    const text = stub.textOf(
      view(result({ status: "unanalyzable", txHash: null, unanalyzableReason: "decode_failed", notChecked: ["NC-DECODE"] })),
    );
    expect(text).toContain("Unanalyzable");
    expect(text).toContain("decode_failed");
    expect(text).toContain("Transaction hash none");
  });
});

describe("every result variant renders", () => {
  const accountEffects: AccountEffect[] = [
    { kind: "trustline", operationIndex: 0, account: ACCOUNT, asset: `USDC:${OTHER}`, limit: 1_000n },
    { kind: "signer", operationIndex: 1, account: ACCOUNT, signer: OTHER, signerType: "hash_x", weight: 0 },
    { kind: "thresholds", operationIndex: 2, account: ACCOUNT, masterWeight: 0, low: null, medium: 3, high: null },
    { kind: "flags", operationIndex: 3, account: ACCOUNT, set: 1, clear: null },
    { kind: "home_domain", operationIndex: 4, account: ACCOUNT, bytesHex: hex("example.com") },
    { kind: "inflation_destination", operationIndex: 5, account: ACCOUNT, destination: OTHER },
    { kind: "merge", operationIndex: 6, account: ACCOUNT, destination: OTHER },
  ];

  it("handles all seven account effect kinds", () => {
    const text = stub.textOf(view(result({ accountEffects })));
    for (const expected of ["trustline", "hash_x", "master_weight", "flags_set", "example.com", "inflation_destination", "merge"]) {
      expect(text, expected).toContain(expected);
    }
    // Only the fields the operation actually sets are shown (§7c).
    expect(text).not.toContain("low_threshold");
    expect(text).not.toContain("flags_clear");
  });

  it("handles all four statuses and all five severities", () => {
    for (const [status, words] of [
      ["findings_present", "Findings present"],
      ["no_issues_found", "No issues found"],
      ["partial", "Status: Partial"],
      ["unanalyzable", "Unanalyzable"],
    ] as const) {
      expect(stub.textOf(view(result({ status, findings: [] }))), status).toContain(words);
    }
    const text = stub.textOf(view(result({ findings: (["critical", "high", "medium", "low", "info"] as const).map((s) => finding({ severity: s })) })));
    for (const word of ["Critical", "High", "Medium", "Low", "Info"]) expect(text, word).toContain(word);
  });

  it("handles every simulation outcome variant", () => {
    const outcomes: SimulationOutcome[] = [
      {
        status: "ok",
        latestLedger: 123,
        minResourceFee: "100",
        resourceFee: "200",
        footprint: { readOnly: 3, readWrite: 4 },
        authRequired: [{ credential: "sorobanCredentialsAddress", signatureExpirationLedger: 0 }, { credential: "sorobanCredentialsSourceAccount" }],
        restore: { minResourceFee: "50" },
      },
      { status: "skipped", reason: "no_invoke_host_function" },
      { status: "timeout", timeoutMs: 1000 },
      { status: "error", reason: "network" },
      { status: "malformed", reason: "too_large" },
    ];
    for (const sim of outcomes) {
      const text = stub.textOf(view(result({ simulation: sim })));
      expect(text).toContain("Simulation");
      expect(text).toContain(sim.status);
    }
    const ok = stub.textOf(view(result({ simulation: outcomes[0] as SimulationOutcome })));
    expect(ok).toContain("123");
    expect(ok).toContain("sorobanCredentialsAddress");
    expect(ok).toContain("restore_min_resource_fee_stroops 50");
  });
});

describe("renders a real analyze() result", () => {
  it("keeps all 50 operations and every finding of the padding fixture", () => {
    const { xdr, network_passphrase } = JSON.parse(
      readFileSync(new URL("../../../fixtures/tx/hostile/padding_buried_set_options.json", import.meta.url), "utf8"),
    ) as { xdr: string; network_passphrase: string };
    const r = analyze(xdr, { networkPassphrase: network_passphrase, asOf: AS_OF });
    expect(r.operationCount).toBe(50);
    expect(r.findings.length).toBeGreaterThan(1);
    const html = stub.serialize(view(r));
    for (const f of r.findings) {
      expect(html, `${f.code} missing`).toContain(`data-code="${f.code}"`);
      for (const name of Object.keys(f.facts)) expect(html, `${f.code}.${name} missing`).toContain(`<dt>${name}</dt>`);
    }
    expect(html).toContain('data-status="partial"');
    expect(html).toContain(r.txHash ?? "");
    expect(html).toContain("<dd>50</dd>");
  });
});
