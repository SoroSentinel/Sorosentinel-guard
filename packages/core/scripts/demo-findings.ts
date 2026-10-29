// Writes a static page holding the reference findings view (src/ui/findings.ts)
// for committed fixtures, so its markup can be checked in a real browser:
// accessibility tree, landmarks, heading outline and keyboard focus.
//
//   node packages/core/scripts/demo-findings.ts [--with-wording] [out.html]
//
// The component builds DOM nodes, and a browser is needed to observe them, but
// this repo has no DOM dependency (AGENTS.md §6: adding one needs approval). The
// page is therefore produced with the same stub the component's tests use,
// serialized the way a browser serializes. Nothing here ships: stdout carries no
// fixture name, address or hash beyond the case labels below, and the page is
// written under $TMPDIR, never into the repo.
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";

import { analyze } from "../src/index.ts";
import { renderFindings } from "../src/ui/findings.ts";
import type { StubElement } from "../test/ui/dom-stub.ts";
import { createDomStub } from "../test/ui/dom-stub.ts";
import { Registry } from "../src/wording/registry.ts";
import type { AttributionDef, TemplateDef } from "../src/wording/registry.ts";
import { Renderer } from "../src/wording/render.ts";
import type { RenderResult } from "../src/wording/render.ts";
import { parseBlocklistYaml } from "../src/wording/blocklist.ts";
import { slotValue } from "../src/wording/slots.ts";
import type { SlotType, SlotValue } from "../src/wording/slots.ts";
import type { Finding } from "../src/rules/types.ts";

/** Chosen to cover the display states: many operations, a critical finding, an unbounded delta, a merge. */
const CASES = [
  "hostile/padding_buried_set_options",
  "hostile/hashx_signer",
  "hostile/no_time_bounds",
  "benign/path_payment_strict_receive",
  "benign/account_merge",
] as const;

// `--with-wording` renders the prose path as well. The component's interactive
// parts (a native facts disclosure and the methodology and review links) only
// exist when a statement was rendered, so a keyboard check needs this branch.
//
// The templates below are synthetic and labeled "TEST ONLY". Guard pins Intel's
// blocklist but not its wording files, and every real template is still draft
// (Intel #32), so nothing here is approved text and this file is not the place
// where approved prose lives.
const withWording = process.argv.includes("--with-wording");

const ATTRIBUTION: AttributionDef = {
  id: "test.guard_attribution.v1",
  status: "counsel_approved",
  text: "Method: {method}, ruleset {ruleset_version}. Observed {as_of}. This is an indicator, not a determination of intent or wrongdoing. Methodology: {methodology_url}. Review: {review_url}.",
};

// Slot names are fact keys the rules actually emit, and each template declares
// only the facts its finding always carries, so the render succeeds instead of
// failing closed on a missing slot. `{as_of}` below is filled by the renderer.
const TEMPLATES: TemplateDef[] = [
  {
    id: "test.guard_signer_added.v1",
    severities: ["critical", "high"],
    text: "TEST ONLY. Signer {signer} was given weight {weight} on {account}. A signer can approve transactions for that account.",
    slots: { signer: "signer_key", weight: "weight", account: "account" },
    attribution: "test.guard_attribution.v1",
    status: "counsel_approved",
  },
  {
    id: "test.guard_account_control.v1",
    severities: ["critical"],
    text: "TEST ONLY. The set of keys that can authorize {account} was changed.",
    slots: { account: "account" },
    attribution: "test.guard_attribution.v1",
    status: "counsel_approved",
  },
  {
    id: "test.guard_no_expiry.v1",
    severities: ["medium"],
    text: "TEST ONLY. This transaction has no upper time bound, so it stays valid until its sequence number is used.",
    attribution: "test.guard_attribution.v1",
    status: "counsel_approved",
  },
];

/** Finding codes with a template here. Every other code fails closed to facts. */
const TEMPLATE_BY_CODE: Record<string, string> = {
  "G-SIGNER-ADDED": "test.guard_signer_added.v1",
  "G-ACCOUNT-CONTROL": "test.guard_account_control.v1",
  "G-NO-EXPIRY": "test.guard_no_expiry.v1",
};

/** as_of is passed in, never read from the wall clock (AGENTS.md §3.7). */
const AS_OF = new Date("2026-10-27T00:01:00Z");

const BLOCKLIST = new URL("../../../intel-schemas/blocklist.yaml", import.meta.url);

/** Builds the injected hook the component reads prose through, over the test registry. */
function makeStatementSource(): (finding: Finding) => RenderResult {
  const registry = new Registry({
    templates: TEMPLATES,
    attributions: [ATTRIBUTION],
    blocklist: parseBlocklistYaml(readFileSync(BLOCKLIST, "utf8")),
  });
  const created = Renderer.create(registry, {
    methodologyUrl: "https://sorosentinel.invalid/methodology",
    reviewUrl: "https://sorosentinel.invalid/review",
  });
  if (!created.ok) throw new Error(`renderer setup failed: ${created.error.code} ${created.error.detail}`);
  const renderer = created.value;

  return (finding) => {
    const templateId = TEMPLATE_BY_CODE[finding.code];
    if (templateId === undefined) {
      return { ok: false, error: { code: "unknown_template", detail: finding.code }, facts: finding.facts };
    }
    const template = registry.template(templateId);
    if (template === undefined) {
      return { ok: false, error: { code: "unknown_template", detail: templateId }, facts: finding.facts };
    }
    const slots: Record<string, SlotValue> = {};
    for (const [name, type] of template.slots) {
      const raw = finding.facts[name];
      if (raw === undefined) return { ok: false, error: { code: "missing_slot", detail: name }, facts: finding.facts };
      const value = slotValue(type as SlotType, raw);
      if (!value.ok) return { ok: false, error: value.error, facts: finding.facts };
      slots[name] = value.value;
    }
    return renderer.render({
      templateId,
      severity: finding.severity,
      asOf: AS_OF,
      method: "GUARD-RULE",
      rulesetVersion: "2026.10.1",
      slots,
    });
  };
}

const scratch = mkdtempSync(`${tmpdir()}/guard-findings-`);
const out = process.argv.slice(2).find((a) => !a.startsWith("--")) ?? `${scratch}/findings.html`;
const stub = createDomStub();
const statementFor = withWording ? makeStatementSource() : undefined;
const sections: string[] = [];

for (const name of CASES) {
  const file = new URL(`../../../fixtures/tx/${name}.json`, import.meta.url);
  const fixture = JSON.parse(readFileSync(file, "utf8")) as { xdr?: unknown; network_passphrase?: unknown };
  if (typeof fixture.xdr !== "string" || typeof fixture.network_passphrase !== "string") {
    throw new Error(`fixture ${name} is missing xdr or network_passphrase`);
  }
  const result = analyze(fixture.xdr, { networkPassphrase: fixture.network_passphrase, asOf: AS_OF });
  // Without a hook every finding shows in its fail-closed state: codes and
  // facts, no prose. That is the state integrators see until wording is approved.
  const tree = renderFindings(result, {
    doc: stub.doc,
    ...(statementFor === undefined ? {} : { statementFor }),
  });
  sections.push(`<h2>${name}</h2>${stub.serialize(tree as unknown as StubElement)}`);
}

const wordingNote = statementFor === undefined
  ? "Wording is not approved yet, so each finding is shown as codes and facts. That is the fail-closed state, not a missing feature."
  : "Synthetic TEST ONLY templates were rendered for some codes, so those findings show prose, a facts disclosure and links. Codes without a template still fail closed."
;

const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Guard findings view</title>
<style>
  /* Page chrome only. The component sets no styles and its markup is unchanged. */
  body { font: 15px/1.5 system-ui, sans-serif; margin: 2rem auto; max-width: 62rem; }
  table { border-collapse: collapse; }
  th, td { border: 1px solid #bbb; padding: 0.3rem 0.5rem; text-align: left; }
  dt { font-weight: 600; }
  dd { margin: 0 0 0.4rem 1rem; }
  section[aria-label] { border-left: 3px solid #ddd; margin: 0.5rem 0; padding-left: 0.8rem; }
  h2 { margin-top: 3rem; border-bottom: 1px solid #eee; }
</style>
</head>
<body>
<h1>Guard findings view: component output for committed fixtures</h1>
<p>Produced by <code>packages/core/scripts/demo-findings.ts</code>. ${wordingNote}</p>
${sections.join("\n")}
</body>
</html>
`;

writeFileSync(out, page);
console.log(`wrote ${out}: ${String(CASES.length)} fixtures, ${String(page.length)} bytes, wording=${String(statementFor !== undefined)}`);
