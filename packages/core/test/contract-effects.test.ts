import { readFileSync } from "node:fs";

import { Address, Asset, Keypair, SorobanDataBuilder, StrKey, nativeToScVal, xdr } from "@stellar/stellar-sdk/base";
import { describe, expect, it } from "vitest";

import { analyze, analyzeAsync, canonicalKey, snapshotHash, snapshotPayload } from "../src/index.ts";
import type { AnalysisResult, AnalyzeContext, BalanceEffect, Snapshot } from "../src/index.ts";

const FIXTURES = new URL("../../../fixtures/tx/", import.meta.url);
const invoke = JSON.parse(readFileSync(new URL("benign/invoke_contract.json", FIXTURES), "utf8")) as { xdr: string; network_passphrase: string };
const PASSPHRASE = invoke.network_passphrase;

// Fixture accounts (scripts/gen-fixtures.ts) and Intel's test snapshot key (seed 0x07 x32).
const key = (b: number) => Keypair.fromRawEd25519Seed(new Uint8Array(32).fill(b));
const S = key(1).publicKey();
const OTHER = key(2).publicKey();
const ISSUER = key(3).publicKey();
const SNAPSHOT_KEY = key(7);
const INVOKED = StrKey.encodeContract(new Uint8Array(32).fill(7));
const TOKEN = StrKey.encodeContract(new Uint8Array(32).fill(9));
const VAULT = StrKey.encodeContract(new Uint8Array(32).fill(11));
const USDC = new Asset("USDC", ISSUER);
const USDC_KEY = `USDC:${ISSUER}`;
const USDC_SAC = USDC.contractId(PASSPHRASE);

const MIN_TIME = 1_793_059_200;
const AS_OF = new Date(MIN_TIME * 1000 + 60_000);

// ---- XDR builders ----

const sym = (s: string) => xdr.ScVal.scvSymbol(s);
const addr = (a: string) => new Address(a).toScVal();
const str = (s: string) => xdr.ScVal.scvString(s);
const i128 = (n: bigint) => nativeToScVal(n, { type: "i128" });

function event(contract: string, topics: xdr.ScVal[], data: xdr.ScVal, inSuccessfulContractCall = true): string {
  const contractId = new Address(contract).toScAddress();
  if (contractId.type !== "scAddressTypeContract") throw new Error("not a contract");
  return new xdr.DiagnosticEvent({
    inSuccessfulContractCall,
    event: new xdr.ContractEvent({
      ext: xdr.ExtensionPoint.v0(),
      contractId: contractId.contractId,
      type: xdr.ContractEventType.contract,
      body: xdr.ContractEventBody.v0(new xdr.ContractEventV0({ topics, data })),
    }),
  }).toXdr("base64");
}

const sacTransfer = (from: string, to: string, amount: bigint, data: xdr.ScVal = i128(amount)) =>
  event(USDC_SAC, [sym("transfer"), addr(from), addr(to), str(USDC_KEY)], data);

function trustline(account: string, balance: bigint): xdr.LedgerEntry {
  return new xdr.LedgerEntry({
    lastModifiedLedgerSeq: 999,
    data: xdr.LedgerEntryData.trustline(
      new xdr.TrustLineEntry({
        accountId: Keypair.fromPublicKey(account).xdrAccountId(),
        asset: USDC.toTrustLineXDRObject(),
        balance,
        limit: 10n ** 15n,
        flags: 1,
        ext: xdr.TrustLineEntryExt.v0(),
      }),
    ),
    ext: xdr.LedgerEntryExt.v0(),
  });
}

function trustlineChange(account: string, before: bigint | null, after: bigint | null) {
  const k = xdr.LedgerKey.trustline(
    new xdr.LedgerKeyTrustLine({ accountId: Keypair.fromPublicKey(account).xdrAccountId(), asset: USDC.toTrustLineXDRObject() }),
  );
  return {
    type: 1,
    key: k.toXdr("base64"),
    before: before === null ? null : trustline(account, before).toXdr("base64"),
    after: after === null ? null : trustline(account, after).toXdr("base64"),
  };
}

function contractDataChange(contract: string) {
  const owner = new Address(contract).toScAddress();
  const k = xdr.ScVal.scvVec([sym("Balance"), addr(S)]);
  const entry = new xdr.LedgerEntry({
    lastModifiedLedgerSeq: 999,
    data: xdr.LedgerEntryData.contractData(
      new xdr.ContractDataEntry({ ext: xdr.ExtensionPoint.v0(), contract: owner, key: k, durability: xdr.ContractDataDurability.persistent, val: i128(1n) }),
    ),
    ext: xdr.LedgerEntryExt.v0(),
  });
  const ledgerKey = xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({ contract: owner, key: k, durability: xdr.ContractDataDurability.persistent }));
  return { type: 1, key: ledgerKey.toXdr("base64"), before: entry.toXdr("base64"), after: entry.toXdr("base64") };
}

// ---- fake RPC ----

const txData = new SorobanDataBuilder().setResourceFee("12345").build().toXdr("base64");

function success(result: Record<string, unknown>): Response {
  const body = {
    jsonrpc: "2.0",
    id: 1,
    result: { latestLedger: 1000, minResourceFee: "54321", transactionData: txData, results: [{ xdr: xdr.ScVal.scvVoid().toXdr("base64") }], ...result },
  };
  return new Response(JSON.stringify(body), { status: 200 });
}

function snapshot(flagged: [string, string][]): Snapshot {
  const s: Snapshot = {
    format_version: 1,
    network: "testnet",
    version: 1,
    generated_at: new Date(MIN_TIME * 1000).toISOString().replace(".000Z", "Z"),
    ruleset_version: "2026.10.1",
    key_id: "test-key-1",
    entries: [...new Set(flagged.map(([t, k]) => snapshotHash(canonicalKey("testnet", t, k))))].sort(),
    signature: "",
  };
  s.signature = btoa(String.fromCharCode(...SNAPSHOT_KEY.sign(snapshotPayload(s))));
  return s;
}

function ctx(result: Record<string, unknown>, extra: Partial<AnalyzeContext> = {}): AnalyzeContext {
  const f = (() => Promise.resolve(success(result))) as unknown as typeof fetch;
  return { networkPassphrase: PASSPHRASE, rpc: { url: "https://rpc.example.test/", fetch: f }, ...extra };
}

const withSnapshot = (flagged: [string, string][]): Partial<AnalyzeContext> => ({
  asOf: AS_OF,
  snapshot: { data: snapshot(flagged), pinnedKeys: { "test-key-1": SNAPSHOT_KEY.rawPublicKey() } },
});

const contractEffects = (r: AnalysisResult): BalanceEffect[] => r.effects.filter((e) => !(e.account === S && e.asset === "native"));

// ---- tests ----

describe("contract effects from simulation", () => {
  it("a SAC transfer confirmed by trustline diffs is ledger and completes the invocation", async () => {
    const r = await analyzeAsync(
      invoke.xdr,
      ctx(
        { events: [sacTransfer(S, OTHER, 100n)], stateChanges: [trustlineChange(S, 500n, 400n), trustlineChange(OTHER, null, 100n)] },
        withSnapshot([]),
      ),
    );
    expect(contractEffects(r)).toEqual([
      { account: S, asset: USDC_KEY, deltaMin: -100n, deltaMax: -100n, assurance: "ledger" },
      { account: OTHER, asset: USDC_KEY, deltaMin: 100n, deltaMax: 100n, assurance: "ledger" },
    ]);
    expect(r.notChecked).toEqual(["NC-EXECUTION-TIME"]);
    expect(r.status).toBe("no_issues_found");
  });

  it("reads the CAP-67 map form of transfer data", async () => {
    const data = xdr.ScVal.scvMap([
      new xdr.ScMapEntry({ key: sym("amount"), val: i128(100n) }),
      new xdr.ScMapEntry({ key: sym("to_muxed_id"), val: xdr.ScVal.scvU64(7n) }),
    ]);
    const r = await analyzeAsync(
      invoke.xdr,
      ctx({ events: [sacTransfer(S, OTHER, 100n, data)], stateChanges: [trustlineChange(S, 500n, 400n), trustlineChange(OTHER, 0n, 100n)] }),
    );
    expect(contractEffects(r).map((e) => [e.account, e.deltaMin, e.assurance])).toEqual([
      [S, -100n, "ledger"],
      [OTHER, 100n, "ledger"],
    ]);
    expect(r.notChecked).not.toContain("NC-OPERATION-EFFECTS");
  });

  it("reads SAC mint and clawback, with and without the pre-CAP-67 admin topic", async () => {
    const r = await analyzeAsync(
      invoke.xdr,
      ctx({
        events: [
          event(USDC_SAC, [sym("mint"), addr(OTHER), str(USDC_KEY)], i128(10n)),
          event(USDC_SAC, [sym("clawback"), addr(ISSUER), addr(S), str(USDC_KEY)], i128(5n)),
        ],
        stateChanges: [trustlineChange(S, 500n, 495n), trustlineChange(OTHER, 0n, 10n)],
      }),
    );
    expect(contractEffects(r).map((e) => [e.account, e.deltaMin, e.assurance])).toEqual([
      [S, -5n, "ledger"],
      [OTHER, 10n, "ledger"],
    ]);
    expect(r.notChecked).not.toContain("NC-OPERATION-EFFECTS");
  });

  it("a SAC transfer to a contract holder stays contract_reported for the contract's balance", async () => {
    const r = await analyzeAsync(
      invoke.xdr,
      ctx({ events: [sacTransfer(S, VAULT, 100n)], stateChanges: [trustlineChange(S, 500n, 400n), contractDataChange(USDC_SAC)] }),
    );
    expect(contractEffects(r)).toEqual([
      { account: S, asset: USDC_KEY, deltaMin: -100n, deltaMax: -100n, assurance: "ledger" },
      { account: VAULT, asset: USDC_KEY, deltaMin: 100n, deltaMax: 100n, assurance: "contract_reported" },
    ]);
    expect(r.notChecked).not.toContain("NC-OPERATION-EFFECTS");
  });

  it("a custom-token transfer is contract_reported, keyed by the token contract, and stays uncovered", async () => {
    const r = await analyzeAsync(
      invoke.xdr,
      ctx({ events: [event(TOKEN, [sym("transfer"), addr(S), addr(OTHER)], i128(50n))], stateChanges: [contractDataChange(TOKEN)] }),
    );
    expect(contractEffects(r)).toEqual([
      { account: S, asset: TOKEN, deltaMin: -50n, deltaMax: -50n, assurance: "contract_reported" },
      { account: OTHER, asset: TOKEN, deltaMin: 50n, deltaMax: 50n, assurance: "contract_reported" },
    ]);
    expect(r.notChecked).toContain("NC-OPERATION-EFFECTS");
    expect(r.notChecked).not.toContain("NC-SIMULATION");
    expect(r.status).toBe("partial");
  });

  it("a contract claiming a SAC asset in its event is never ledger", async () => {
    // TOKEN says it moved USDC, and the state changes even agree; the emitter is not the USDC SAC.
    const r = await analyzeAsync(
      invoke.xdr,
      ctx({
        events: [event(TOKEN, [sym("transfer"), addr(S), addr(OTHER), str(USDC_KEY)], i128(100n))],
        stateChanges: [trustlineChange(S, 500n, 400n), trustlineChange(OTHER, 0n, 100n)],
      }),
    );
    expect(contractEffects(r)).toEqual([
      { account: S, asset: TOKEN, deltaMin: -100n, deltaMax: -100n, assurance: "contract_reported" },
      { account: OTHER, asset: TOKEN, deltaMin: 100n, deltaMax: 100n, assurance: "contract_reported" },
    ]);
    expect(r.notChecked).toContain("NC-OPERATION-EFFECTS");
  });

  it("SAC events that the ledger diffs do not match are not ledger", async () => {
    // The endpoint reports a 1000 transfer, but balances moved by 100.
    const r = await analyzeAsync(
      invoke.xdr,
      ctx({ events: [sacTransfer(S, OTHER, 1000n)], stateChanges: [trustlineChange(S, 500n, 400n), trustlineChange(OTHER, 0n, 100n)] }),
    );
    expect(contractEffects(r).map((e) => [e.deltaMin, e.assurance])).toEqual([
      [-1000n, "contract_reported"],
      [1000n, "contract_reported"],
    ]);
    expect(r.notChecked).toContain("NC-OPERATION-EFFECTS");
  });

  it("without state changes, SAC events are contract_reported and the invocation stays uncovered", async () => {
    const r = await analyzeAsync(invoke.xdr, ctx({ events: [sacTransfer(S, OTHER, 100n)] }));
    expect(contractEffects(r).every((e) => e.assurance === "contract_reported")).toBe(true);
    expect(r.notChecked).toContain("NC-OPERATION-EFFECTS");
  });

  it("ignores events from failed calls", async () => {
    const r = await analyzeAsync(invoke.xdr, ctx({ events: [event(USDC_SAC, [sym("transfer"), addr(S), addr(OTHER), str(USDC_KEY)], i128(9n), false)], stateChanges: [] }));
    expect(contractEffects(r)).toEqual([]);
    expect(r.notChecked).not.toContain("NC-OPERATION-EFFECTS");
  });

  it("an event Guard does not read (an allowance) keeps the invocation uncovered", async () => {
    const r = await analyzeAsync(
      invoke.xdr,
      ctx({ events: [event(USDC_SAC, [sym("approve"), addr(S), addr(OTHER), str(USDC_KEY)], i128(1n))], stateChanges: [] }),
    );
    expect(r.notChecked).toContain("NC-OPERATION-EFFECTS");
  });

  it("other ledger changes (here: the invoked contract's own storage) keep it uncovered", async () => {
    const r = await analyzeAsync(
      invoke.xdr,
      ctx({ events: [sacTransfer(S, OTHER, 100n)], stateChanges: [trustlineChange(S, 500n, 400n), trustlineChange(OTHER, 0n, 100n), contractDataChange(INVOKED)] }),
    );
    // The SAC balances are still confirmed; the rest is not derived.
    expect(contractEffects(r).every((e) => e.assurance === "ledger")).toBe(true);
    expect(r.notChecked).toContain("NC-OPERATION-EFFECTS");
  });

  describe("malformed events", () => {
    const cases: [string, Record<string, unknown>][] = [
      ["undecodable event XDR", { events: ["AAAA"], stateChanges: [] }],
      ["events not an array", { events: "x", stateChanges: [] }],
      ["undecodable state change", { events: [], stateChanges: [{ type: 1, key: "AAAA", before: null, after: null }] }],
      ["negative amount", { events: [sacTransfer(S, OTHER, -5n)], stateChanges: [] }],
      ["amount not an i128", { events: [event(USDC_SAC, [sym("transfer"), addr(S), addr(OTHER), str(USDC_KEY)], xdr.ScVal.scvU32(5))], stateChanges: [] }],
      ["missing address topic", { events: [event(USDC_SAC, [sym("transfer"), addr(S), str(USDC_KEY)], i128(5n))], stateChanges: [] }],
      ["unknown key in data map", { events: [sacTransfer(S, OTHER, 1n, xdr.ScVal.scvMap([new xdr.ScMapEntry({ key: sym("amount"), val: i128(1n) }), new xdr.ScMapEntry({ key: sym("memo"), val: i128(1n) })]))], stateChanges: [] }],
    ];
    for (const [name, result] of cases) {
      it(`${name}: simulation counts, the invocation stays uncovered with no contract effects`, async () => {
        const r = await analyzeAsync(invoke.xdr, ctx(result));
        expect(r.simulation?.status).toBe("ok");
        expect(r.notChecked).not.toContain("NC-SIMULATION");
        expect(r.notChecked).toContain("NC-OPERATION-EFFECTS");
        expect(contractEffects(r)).toEqual([]);
        expect(r.status).toBe("partial");
      });
    }
  });
});

describe("contract counterparties", () => {
  it("a flagged invoked contract raises G-CONTRACT-FLAGGED without simulation", () => {
    const r = analyze(invoke.xdr, { networkPassphrase: PASSPHRASE, ...withSnapshot([["contract", INVOKED]]) });
    expect(r.findings).toEqual([
      { code: "G-CONTRACT-FLAGGED", severity: "high", operationIndex: null, facts: { entity_type: "contract", key: INVOKED, roles: "invoked" }, statement: null },
    ]);
    expect(r.notChecked).not.toContain("NC-COUNTERPARTY-SIGNALS");
  });

  it("a flagged token contract and a flagged contract holder are found through simulated effects", async () => {
    const r = await analyzeAsync(
      invoke.xdr,
      ctx(
        { events: [event(TOKEN, [sym("transfer"), addr(S), addr(VAULT)], i128(5n))], stateChanges: [] },
        withSnapshot([
          ["contract", TOKEN],
          ["contract", VAULT],
        ]),
      ),
    );
    expect(r.findings.map((f) => [f.code, f.facts["key"], f.facts["roles"]])).toEqual([
      ["G-CONTRACT-FLAGGED", TOKEN, "token"],
      ["G-DEST-FLAGGED", VAULT, "balance"],
    ]);
    expect(r.status).toBe("partial");
  });
});
