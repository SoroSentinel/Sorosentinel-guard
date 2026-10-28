import { readFileSync } from "node:fs";

import { Keypair, Networks, StrKey, xdr } from "@stellar/stellar-sdk/base";
import { describe, expect, it } from "vitest";

import { analyze, analyzeAsync, snapshotPayload } from "../src/index.ts";
import type { AnalysisResult, AnalyzeContext, Snapshot } from "../src/index.ts";
import { MEMO_REQUIRED_DATA_NAME } from "../src/memo/memo-required.ts";

const FIXTURES = new URL("../../../fixtures/tx/", import.meta.url);
const URL_ = "https://rpc.example.test/";

function fixture(name: string): { xdr: string; network_passphrase: string } {
  return JSON.parse(readFileSync(new URL(name, FIXTURES), "utf8")) as { xdr: string; network_passphrase: string };
}

// Fixture accounts (scripts/gen-fixtures.ts).
const key = (b: number) => Keypair.fromRawEd25519Seed(new Uint8Array(32).fill(b)).publicKey();
const OTHER = key(2);
const CUSTODIAN = key(5);

// A verified, empty snapshot (as in lookup.test.ts), so counterparties are checked.
const SNAPSHOT_KEY = Keypair.fromRawEd25519Seed(new Uint8Array(32).fill(7));
const MIN_TIME = 1_793_059_200; // fixture time bounds start here
function emptySnapshot(): Pick<AnalyzeContext, "asOf" | "snapshot"> {
  const s: Snapshot = {
    format_version: 1,
    network: "public",
    version: 1,
    generated_at: new Date(MIN_TIME * 1000).toISOString().replace(".000Z", "Z"),
    ruleset_version: "2026.10.1",
    key_id: "test-key-1",
    entries: [],
    signature: "",
  };
  s.signature = btoa(String.fromCharCode(...SNAPSHOT_KEY.sign(snapshotPayload(s))));
  return { asOf: new Date(MIN_TIME * 1000 + 60_000), snapshot: { data: s, pinnedKeys: { "test-key-1": SNAPSHOT_KEY.rawPublicKey() } } };
}

const single = fixture("hostile/memo_required_destination.json");
const muxed = fixture("hostile/muxed_destination.json");
const mixed = fixture("hostile/memo_required_operations.json");
const withMemo = fixture("benign/memo_id.json");

// ---- fake RPC ----

interface Call {
  method: string;
  params: Record<string, unknown>;
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

const ok = (result: unknown) => json({ jsonrpc: "2.0", id: 1, result });

function dataKey(account: string, name = MEMO_REQUIRED_DATA_NAME): string {
  return xdr.LedgerKey.data(
    new xdr.LedgerKeyData({ accountId: xdr.PublicKey.publicKeyTypeEd25519(StrKey.decodeEd25519PublicKey(account)), dataName: name }),
  ).toXdr("base64");
}

function dataEntry(account: string, value: string, name = MEMO_REQUIRED_DATA_NAME): string {
  return xdr.LedgerEntryData.data(
    new xdr.DataEntry({
      accountId: xdr.PublicKey.publicKeyTypeEd25519(StrKey.decodeEd25519PublicKey(account)),
      dataName: name,
      dataValue: new TextEncoder().encode(value),
      ext: xdr.DataEntryExt.v0(),
    }),
  ).toXdr("base64");
}

type Handler = (method: string, params: Record<string, unknown>) => Response | Promise<Response>;

/** Ledger state: account -> its `config.memo_required` value. Answers like Stellar RPC. */
function ledger(state: Record<string, string>, passphrase: string = Networks.PUBLIC): Handler {
  return (method, params) => {
    if (method === "getNetwork") return ok({ passphrase, protocolVersion: 23 });
    if (method === "getLedgerEntries") {
      const keys = params["keys"] as string[];
      const entries = Object.entries(state)
        .filter(([account]) => keys.includes(dataKey(account)))
        .map(([account, value]) => ({ key: dataKey(account), xdr: dataEntry(account, value), lastModifiedLedgerSeq: 900 }));
      return ok(entries.length === 0 ? { latestLedger: 1000 } : { entries, latestLedger: 1000 });
    }
    return json({ jsonrpc: "2.0", id: 1, error: { code: -32601, message: "method not found" } });
  };
}

function fakeFetch(handler: Handler): { fetch: typeof fetch; calls: Call[] } {
  const calls: Call[] = [];
  const f = (_input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const body = JSON.parse(String(init?.body)) as { method: string; params: Record<string, unknown> };
    calls.push({ method: body.method, params: body.params });
    return Promise.resolve(handler(body.method, body.params));
  };
  return { fetch: f as typeof fetch, calls };
}

function ctx(f: typeof fetch, passphrase: string, timeoutMs?: number): AnalyzeContext {
  return { networkPassphrase: passphrase, rpc: { url: URL_, fetch: f, ...(timeoutMs === undefined ? {} : { timeoutMs }) } };
}

async function run(tx: { xdr: string; network_passphrase: string }, handler: Handler, timeoutMs?: number): Promise<{ r: AnalysisResult; calls: Call[] }> {
  const { fetch: f, calls } = fakeFetch(handler);
  return { r: await analyzeAsync(tx.xdr, ctx(f, tx.network_passphrase, timeoutMs)), calls };
}

const memoFinding = (destination: string, operationIndex: number) => ({
  code: "G-MEMO-REQUIRED",
  severity: "high",
  operationIndex,
  facts: { destination, operation_index: String(operationIndex) },
  statement: null,
});

function expectUnchecked(r: AnalysisResult): void {
  expect(r.notChecked).toContain("NC-MEMO-REQUIRED");
  expect(r.status).toBe("partial");
  expect(r.findings.filter((f) => f.code === "G-MEMO-REQUIRED")).toEqual([]);
}

// ---- tests ----

describe("G-MEMO-REQUIRED (SEP-29)", () => {
  it("a payment without a memo to a memo-required account is a high finding", async () => {
    const { r, calls } = await run(single, ledger({ [CUSTODIAN]: "1" }));
    expect(r.findings).toEqual([memoFinding(CUSTODIAN, 0)]);
    expect(r.notChecked).not.toContain("NC-MEMO-REQUIRED");
    // Counterparties are still unchecked without a snapshot.
    expect(r.status).toBe("partial");
    // Only the data entry's ledger key is sent; no envelope, no simulation.
    expect(calls.map((c) => c.method).sort()).toEqual(["getLedgerEntries", "getNetwork"]);
    expect(calls.find((c) => c.method === "getLedgerEntries")?.params).toEqual({ keys: [dataKey(CUSTODIAN)] });
  });

  it("a transaction with a memo needs no lookup and has no finding", async () => {
    const { r, calls } = await run(withMemo, ledger({ [OTHER]: "1" }));
    expect(calls).toHaveLength(0);
    expect(r.findings).toEqual([]);
    expect(r.notChecked).not.toContain("NC-MEMO-REQUIRED");
  });

  it("a muxed destination is exempt (SEP-29) and is not looked up", async () => {
    const { r, calls } = await run(muxed, ledger({ [CUSTODIAN]: "1" }));
    expect(calls).toHaveLength(0);
    expect(r.findings).toEqual([]);
    expect(r.notChecked).not.toContain("NC-MEMO-REQUIRED");
    // The synchronous analysis needs no ledger data for it either.
    expect(analyze(muxed.xdr, { networkPassphrase: muxed.network_passphrase }).notChecked).not.toContain("NC-MEMO-REQUIRED");
  });

  it("a destination without the data entry has no finding and is checked", async () => {
    const { r } = await run(single, ledger({}));
    expect(r.findings).toEqual([]);
    expect(r.notChecked).not.toContain("NC-MEMO-REQUIRED");
  });

  it("only the value \"1\" requires a memo", async () => {
    for (const value of ["0", "true", "11", " 1", ""]) {
      const { r } = await run(single, ledger({ [CUSTODIAN]: value }));
      expect(r.findings, value).toEqual([]);
      expect(r.notChecked, value).not.toContain("NC-MEMO-REQUIRED");
    }
  });

  it("batches every SEP-29 destination into one lookup and reports each operation", async () => {
    const { r, calls } = await run(mixed, ledger({ [CUSTODIAN]: "1", [OTHER]: "1" }));
    const lookups = calls.filter((c) => c.method === "getLedgerEntries");
    expect(lookups).toHaveLength(1);
    // Deduplicated; the created account (op 4) and the muxed destination (op 5) are not looked up.
    expect(lookups[0]?.params).toEqual({ keys: [dataKey(CUSTODIAN), dataKey(OTHER)].sort() });
    expect(r.findings.filter((f) => f.code === "G-MEMO-REQUIRED")).toEqual([
      memoFinding(CUSTODIAN, 0),
      memoFinding(OTHER, 1),
      memoFinding(CUSTODIAN, 2),
      memoFinding(OTHER, 6),
    ]);
    expect(r.notChecked).not.toContain("NC-MEMO-REQUIRED");
  });

  it("non-payment operations are ignored", async () => {
    const { r } = await run(mixed, ledger({ [CUSTODIAN]: "1" }));
    const indexes = r.findings.filter((f) => f.code === "G-MEMO-REQUIRED").map((f) => f.operationIndex);
    expect(indexes).toEqual([0, 2]);
    for (const f of ["benign/change_trust.json", "benign/set_options_add_signer.json", "benign/manage_data_decode_only.json", "benign/create_account.json"]) {
      const { r: other, calls } = await run(fixture(f), ledger({ [CUSTODIAN]: "1", [OTHER]: "1" }));
      expect(calls.filter((c) => c.method === "getLedgerEntries"), f).toEqual([]);
      expect(other.notChecked, f).not.toContain("NC-MEMO-REQUIRED");
    }
  });

  it("a fee bump uses the inner transaction's memo and destinations", async () => {
    const { r } = await run(fixture("hostile/fee_bump.json"), ledger({ [OTHER]: "1" }));
    expect(r.findings).toEqual([memoFinding(OTHER, 0)]);
  });
});

describe("NC-MEMO-REQUIRED: the lookup fails loud", () => {
  it("the synchronous analyze() reads no ledger data, so payments without a memo stay unchecked", () => {
    for (const tx of [single, mixed, fixture("benign/payment_native.json"), fixture("benign/account_merge.json"), fixture("benign/path_payment_strict_send.json")]) {
      expectUnchecked(analyze(tx.xdr, { networkPassphrase: tx.network_passphrase }));
    }
  });

  it("analyzeAsync without an RPC endpoint leaves it unchecked", async () => {
    expectUnchecked(await analyzeAsync(single.xdr, { networkPassphrase: single.network_passphrase }));
  });

  it("a timeout leaves it unchecked", async () => {
    const { r } = await run(single, () => new Promise<Response>(() => undefined), 20);
    expectUnchecked(r);
  });

  it("transport and RPC errors leave it unchecked", async () => {
    const handlers: Handler[] = [
      () => {
        throw new TypeError("network down");
      },
      () => new Response("busy", { status: 503 }),
      () => json({ jsonrpc: "2.0", id: 1, error: { code: -32603, message: "internal" } }),
      (method, params) => (method === "getNetwork" ? new Response("busy", { status: 500 }) : ledger({})(method, params)),
    ];
    for (const h of handlers) expectUnchecked((await run(single, h)).r);
  });

  it("an endpoint for another network leaves it unchecked", async () => {
    expectUnchecked((await run(single, ledger({ [CUSTODIAN]: "1" }, Networks.TESTNET))).r);
  });

  it("malformed responses leave it unchecked", async () => {
    const entries = (result: unknown): Handler => (method, params) => (method === "getLedgerEntries" ? ok(result) : ledger({})(method, params));
    const good = { key: dataKey(CUSTODIAN), xdr: dataEntry(CUSTODIAN, "1") };
    const bodies: Handler[] = [
      () => new Response("not json", { status: 200 }),
      () => json({ jsonrpc: "2.0", id: 2, result: { latestLedger: 1 } }),
      () => new Response(new Uint8Array([0xff, 0xfe]), { status: 200 }),
      () => new Response("x".repeat(1024 * 1024 + 1), { status: 200 }),
      entries({}),
      entries({ latestLedger: -1 }),
      entries({ latestLedger: 1000, entries: "none" }),
      entries({ latestLedger: 1000, entries: [good, good] }),
      entries({ latestLedger: 1000, entries: [{ key: dataKey(CUSTODIAN) }] }),
      entries({ latestLedger: 1000, entries: [{ ...good, xdr: "AAAA%%%" }] }),
      // An entry for a key that was not asked for.
      entries({ latestLedger: 1000, entries: [{ key: dataKey(OTHER), xdr: dataEntry(OTHER, "1") }] }),
      // The entry does not match its key: another account, another name, another entry type.
      entries({ latestLedger: 1000, entries: [{ key: dataKey(CUSTODIAN), xdr: dataEntry(OTHER, "1") }] }),
      entries({ latestLedger: 1000, entries: [{ key: dataKey(CUSTODIAN), xdr: dataEntry(CUSTODIAN, "1", "config.memo_requirex") }] }),
      entries({ latestLedger: 1000, entries: [{ key: dataKey(CUSTODIAN), xdr: xdr.ScVal.scvVoid().toXdr("base64") }] }),
      (method, params) => (method === "getNetwork" ? ok({ protocolVersion: 23 }) : ledger({})(method, params)),
    ];
    for (const [i, h] of bodies.entries()) {
      const { r } = await run(single, h);
      expect(r.notChecked, `case ${i}`).toContain("NC-MEMO-REQUIRED");
      expect(r.status, `case ${i}`).toBe("partial");
    }
    // Two keys asked for, one answered twice.
    const { r } = await run(mixed, entries({ latestLedger: 1000, entries: [good, good] }));
    expectUnchecked(r);
  });

  it("with counterparties checked, the memo lookup alone decides between clean and partial", async () => {
    const analyzed = async (handler: Handler) => {
      const { fetch: f } = fakeFetch(handler);
      return analyzeAsync(single.xdr, { ...ctx(f, single.network_passphrase), ...emptySnapshot() });
    };
    const checked = await analyzed(ledger({}));
    expect(checked.snapshotStatus).toBe("verified");
    expect(checked.notChecked).toEqual(["NC-EXECUTION-TIME"]);
    expect(checked.status).toBe("no_issues_found");

    const required = await analyzed(ledger({ [CUSTODIAN]: "1" }));
    expect(required.status).toBe("findings_present");
    expect(required.findings).toEqual([memoFinding(CUSTODIAN, 0)]);

    const failed = await analyzed(() => new Response("busy", { status: 503 }));
    expect(failed.notChecked).toEqual(["NC-EXECUTION-TIME", "NC-MEMO-REQUIRED"]);
    expect(failed.status).toBe("partial");
  });
});
