import { readFileSync } from "node:fs";

import { Keypair } from "@stellar/stellar-sdk/base";
import { describe, expect, it } from "vitest";

import { analyze, canonicalKey, snapshotHash, snapshotPayload } from "../src/index.ts";
import type { AnalysisResult, AnalyzeContext, Snapshot } from "../src/index.ts";

const FIXTURES = new URL("../../../fixtures/tx/", import.meta.url);

// Fixture accounts (scripts/gen-fixtures.ts) and Intel's test snapshot key (seed 0x07 x32).
const key = (b: number) => Keypair.fromRawEd25519Seed(new Uint8Array(32).fill(b));
const S = key(1).publicKey();
const OTHER = key(2).publicKey();
const ISSUER = key(3).publicKey();
const USDC = `USDC:${ISSUER}`;
const SNAPSHOT_KEY = key(7);
const PINNED = { "test-key-1": SNAPSHOT_KEY.rawPublicKey() };

const MIN_TIME = 1_793_059_200; // fixture time bounds start here
const GENERATED = new Date(MIN_TIME * 1000);
const AS_OF = new Date(MIN_TIME * 1000 + 60_000);

function snapshot(network: "public" | "testnet", flagged: [string, string][], overrides: Partial<Snapshot> = {}): Snapshot {
  const entries = [...new Set(flagged.map(([t, k]) => snapshotHash(canonicalKey(network, t, k))))].sort();
  const s: Snapshot = {
    format_version: 1,
    network,
    version: 1,
    generated_at: GENERATED.toISOString().replace(".000Z", "Z"),
    ruleset_version: "2026.10.1",
    key_id: "test-key-1",
    entries,
    signature: "",
    ...overrides,
  };
  s.signature = btoa(String.fromCharCode(...SNAPSHOT_KEY.sign(snapshotPayload(s))));
  return s;
}

function run(fixture: string, ctx: Partial<AnalyzeContext> = {}): AnalysisResult {
  const f = JSON.parse(readFileSync(new URL(fixture, FIXTURES), "utf8")) as { xdr: string; network_passphrase: string };
  return analyze(f.xdr, { networkPassphrase: f.network_passphrase, ...ctx });
}

const withSnapshot = (data: unknown, extra: Partial<AnalyzeContext> = {}): Partial<AnalyzeContext> => ({
  asOf: AS_OF,
  snapshot: { data, pinnedKeys: PINNED },
  ...extra,
});

describe("counterparty lookup", () => {
  // A payment with a memo needs no SEP-29 lookup, so `analyze` can check it completely.
  it("a verified snapshot with no hits gives the first clean result", () => {
    const r = run("benign/memo_id.json", withSnapshot(snapshot("public", [])));
    expect(r.snapshotStatus).toBe("verified");
    expect(r.notChecked).toEqual(["NC-EXECUTION-TIME"]);
    expect(r.status).toBe("no_issues_found");
    expect(r.findings).toEqual([]);
  });

  it("a flagged destination account raises G-DEST-FLAGGED", () => {
    const r = run("benign/memo_id.json", withSnapshot(snapshot("public", [["account", OTHER]])));
    expect(r.status).toBe("findings_present");
    expect(r.findings).toEqual([
      {
        code: "G-DEST-FLAGGED",
        severity: "high",
        operationIndex: null,
        facts: { entity_type: "account", key: OTHER, roles: "balance" },
        statement: null,
      },
    ]);
  });

  it("a trustline to a flagged asset raises G-TRUST-FLAGGED", () => {
    const r = run("benign/change_trust.json", withSnapshot(snapshot("testnet", [["asset", USDC]])));
    expect(r.findings).toEqual([
      {
        code: "G-TRUST-FLAGGED",
        severity: "high",
        operationIndex: null,
        facts: { entity_type: "asset", key: USDC, roles: "trustline" },
        statement: null,
      },
    ]);
  });

  it("a flagged asset received in a payment is G-TRUST-FLAGGED with the balance role", () => {
    const r = run("benign/path_payment_strict_receive.json", withSnapshot(snapshot("public", [["asset", USDC]])));
    expect(r.findings.map((f) => [f.code, f.facts["roles"]])).toEqual([["G-TRUST-FLAGGED", "balance"]]);
  });

  it("a flagged account added as a signer reports both roles and the signer finding", () => {
    const r = run("benign/set_options_add_signer.json", withSnapshot(snapshot("public", [["account", OTHER]])));
    expect(r.findings.map((f) => f.code).sort()).toEqual(["G-DEST-FLAGGED", "G-SIGNER-ADDED"]);
    expect(r.findings.find((f) => f.code === "G-DEST-FLAGGED")?.facts["roles"]).toBe("signer");
  });

  it("the transaction source itself can be flagged", () => {
    const r = run("benign/payment_native.json", withSnapshot(snapshot("public", [["account", S]])));
    expect(r.findings[0]?.facts["roles"]).toBe("balance,source");
  });

  it("an invoked contract is looked up; the call stays partial without simulated effects", () => {
    const r = run("benign/invoke_contract.json", withSnapshot(snapshot("testnet", [])));
    expect(r.snapshotStatus).toBe("verified");
    expect(r.status).toBe("partial");
    expect(r.notChecked).not.toContain("NC-COUNTERPARTY-SIGNALS");
    expect(r.notChecked).toEqual(["NC-EXECUTION-TIME", "NC-OPERATION-EFFECTS", "NC-SIMULATION"]);
  });
});

describe("snapshot states", () => {
  it("no snapshot: not_provided, partial", () => {
    const r = run("benign/payment_native.json");
    expect(r.snapshotStatus).toBe("not_provided");
    expect(r.status).toBe("partial");
    expect(r.notChecked).toContain("NC-COUNTERPARTY-SIGNALS");
  });

  it("no asOf: the snapshot is not used", () => {
    const r = run("benign/payment_native.json", { snapshot: { data: snapshot("public", [["account", OTHER]]), pinnedKeys: PINNED } });
    expect(r.snapshotStatus).toBe("no_as_of");
    expect(r.status).toBe("partial");
    expect(r.findings).toEqual([]);
  });

  it.each([
    ["stale", { asOf: new Date(AS_OF.getTime() + 2 * 3600_000) }, () => snapshot("public", [])],
    ["bad_signature", {}, () => ({ ...snapshot("public", []), version: 2 })],
    ["network_mismatch", {}, () => snapshot("testnet", [])],
    ["unknown_key", {}, () => snapshot("public", [], { key_id: "other-key" })],
    ["malformed", {}, () => ({ hello: "world" })],
  ] as const)("%s: partial, and a hit is never reported from an unusable snapshot", (reason, extra, make) => {
    const r = run("benign/payment_native.json", withSnapshot(make(), extra));
    expect(r.snapshotStatus).toBe(reason);
    expect(r.status).toBe("partial");
    expect(r.notChecked).toContain("NC-COUNTERPARTY-SIGNALS");
  });

  it("unknown network: not_applicable", () => {
    const r = run("hostile/unknown_network.json", withSnapshot(snapshot("public", [])));
    expect(r.snapshotStatus).toBe("not_applicable");
    expect(r.status).toBe("partial");
  });

  it("a tampered snapshot with a matching hit is rejected before lookup", () => {
    const s = snapshot("public", []);
    const forged = { ...s, entries: [snapshotHash(canonicalKey("public", "account", OTHER))] };
    const r = run("benign/payment_native.json", withSnapshot(forged));
    expect(r.snapshotStatus).toBe("bad_signature");
    expect(r.findings).toEqual([]);
  });
});
