import { readdirSync, readFileSync } from "node:fs";

import { Networks } from "@stellar/stellar-sdk/base";
import { describe, expect, it } from "vitest";

import { analyze } from "../src/index.ts";
import type { AnalysisResult } from "../src/index.ts";
import { orderFindings, type Finding } from "../src/rules/types.ts";

const FIXTURES = new URL("../../../fixtures/tx/", import.meta.url);

function run(fixture: string): AnalysisResult {
  const f = JSON.parse(readFileSync(new URL(fixture, FIXTURES), "utf8")) as { xdr: string; network_passphrase: string };
  return analyze(f.xdr, { networkPassphrase: f.network_passphrase });
}

describe("analyze status", () => {
  it("garbage is unanalyzable, never clean", () => {
    for (const input of ["", "AAAA", "not base64!"]) {
      const r = analyze(input, { networkPassphrase: Networks.PUBLIC });
      expect(r.status).toBe("unanalyzable");
      expect(r.unanalyzableReason).toBe("decode_failed");
      expect(r.txHash).toBeNull();
      expect(r.notChecked).toEqual(["NC-DECODE"]);
    }
  });

  it("an empty passphrase is unanalyzable", () => {
    expect(run("benign/payment_native.json").status).not.toBe("unanalyzable");
    const f = JSON.parse(readFileSync(new URL("benign/payment_native.json", FIXTURES), "utf8")) as { xdr: string };
    expect(analyze(f.xdr, { networkPassphrase: "" }).unanalyzableReason).toBe("invalid_network_passphrase");
  });

  it("without a counterparty lookup, a plain payment is partial, not clean", () => {
    const r = run("benign/payment_native.json");
    expect(r.status).toBe("partial");
    // No memo and no ledger data: the destination's SEP-29 requirement is unchecked too.
    expect(r.notChecked).toEqual(["NC-COUNTERPARTY-SIGNALS", "NC-EXECUTION-TIME", "NC-MEMO-REQUIRED"]);
    expect(r.findings).toEqual([]);
    expect(r.operationCount).toBe(1);
    expect(r.txHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("an unknown network adds G-NETWORK-UNKNOWN and NC-NETWORK-COVERAGE", () => {
    const r = run("hostile/unknown_network.json");
    expect(r.status).toBe("partial");
    expect(r.network).toBe("unknown");
    expect(r.findings).toEqual([
      { code: "G-NETWORK-UNKNOWN", severity: "info", operationIndex: null, facts: {}, statement: null },
    ]);
    expect(r.notChecked).toContain("NC-NETWORK-COVERAGE");
  });

  it("covered networks never get G-NETWORK-UNKNOWN", () => {
    for (const f of ["benign/payment_native.json", "benign/change_trust.json"]) {
      expect(run(f).findings.map((x) => x.code)).not.toContain("G-NETWORK-UNKNOWN");
    }
  });

  it("contract calls note that simulation was not run, and uncovered effects", () => {
    const r = run("benign/invoke_contract.json");
    expect(r.notChecked).toEqual(expect.arrayContaining(["NC-SIMULATION", "NC-OPERATION-EFFECTS"]));
    expect(r.status).toBe("partial");
  });

  it("every fixture yields a status and at least one not_checked code; none is clean today", () => {
    for (const dir of ["benign", "hostile"] as const) {
      for (const name of readdirSync(new URL(`${dir}/`, FIXTURES)).filter((n) => n.endsWith(".json"))) {
        const r = run(`${dir}/${name}`);
        expect(r.notChecked.length, name).toBeGreaterThan(0);
        expect(["partial", "unanalyzable"], name).toContain(r.status);
      }
    }
  });

  it("reports the full operation count for padded transactions", () => {
    expect(run("hostile/padding_buried_set_options.json").operationCount).toBe(50);
  });

  it("is deterministic", () => {
    expect(run("hostile/fee_bump.json")).toEqual(run("hostile/fee_bump.json"));
  });
});

describe("finding order", () => {
  const f = (severity: Finding["severity"], operationIndex: number | null): Finding => ({
    code: "G-NETWORK-UNKNOWN",
    severity,
    operationIndex,
    facts: {},
    statement: null,
  });

  it("orders by severity, then operation, and never drops any", () => {
    const many = Array.from({ length: 200 }, (_, i) => f(i % 2 ? "info" : "critical", 199 - i));
    const ordered = orderFindings(many);
    expect(ordered).toHaveLength(200);
    expect(ordered.slice(0, 100).every((x) => x.severity === "critical")).toBe(true);
    expect(ordered[0]?.operationIndex).toBe(1);
    expect(orderFindings([f("low", 3), f("high", 9), f("critical", null)]).map((x) => x.severity)).toEqual([
      "critical",
      "high",
      "low",
    ]);
  });
});
