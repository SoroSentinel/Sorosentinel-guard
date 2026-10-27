import { readFileSync } from "node:fs";

import { Address, Contract, Keypair, SorobanDataBuilder, StrKey, xdr } from "@stellar/stellar-sdk/base";
import { describe, expect, it } from "vitest";

import { MAX_SIMULATION_RESPONSE_BYTES, analyze, analyzeAsync, simulateTransaction } from "../src/index.ts";
import type { AnalysisResult, AnalyzeContext, SimulationOutcome } from "../src/index.ts";

const FIXTURES = new URL("../../../fixtures/tx/", import.meta.url);
const URL_ = "https://rpc.example.test/";

function fixture(name: string): { xdr: string; network_passphrase: string } {
  return JSON.parse(readFileSync(new URL(name, FIXTURES), "utf8")) as { xdr: string; network_passphrase: string };
}

const invoke = fixture("benign/invoke_contract.json");

// ---- fake RPC ----

interface Call {
  url: string;
  init: RequestInit | undefined;
}

function fakeFetch(respond: () => Response | Promise<Response>): { fetch: typeof fetch; calls: Call[] } {
  const calls: Call[] = [];
  const f = (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    calls.push({ url: String(input), init });
    return Promise.resolve(respond());
  };
  return { fetch: f as typeof fetch, calls };
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

const contract = new Contract(StrKey.encodeContract(new Uint8Array(32).fill(7)));
const other = Keypair.fromRawEd25519Seed(new Uint8Array(32).fill(2));

function authEntry(): string {
  const call = contract.call("hello");
  if (call.body.type !== "invokeHostFunction" || call.body.invokeHostFunctionOp.hostFunction.type !== "hostFunctionTypeInvokeContract") {
    throw new Error("unexpected contract call shape");
  }
  const invocation = new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(call.body.invokeHostFunctionOp.hostFunction.invokeContract),
    subInvocations: [],
  });
  const creds = new xdr.SorobanAddressCredentials({
    address: new Address(other.publicKey()).toScAddress(),
    nonce: 1n,
    signatureExpirationLedger: 0,
    signature: xdr.ScVal.scvVoid(),
  });
  return new xdr.SorobanAuthorizationEntry({ credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(creds), rootInvocation: invocation }).toXdr("base64");
}

const txData = new SorobanDataBuilder().setFootprint([contract.getFootprint()], []).setResourceFee("12345").build().toXdr("base64");

function success(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    jsonrpc: "2.0",
    id: 1,
    result: {
      latestLedger: 1000,
      minResourceFee: "54321",
      transactionData: txData,
      results: [{ xdr: xdr.ScVal.scvVoid().toXdr("base64"), auth: [authEntry()] }],
      ...overrides,
    },
  };
}

function ctx(f: typeof fetch, timeoutMs?: number): AnalyzeContext {
  return {
    networkPassphrase: invoke.network_passphrase,
    rpc: { url: URL_, fetch: f, ...(timeoutMs === undefined ? {} : { timeoutMs }) },
  };
}

async function runInvoke(respond: () => Response | Promise<Response>, timeoutMs?: number): Promise<AnalysisResult> {
  return analyzeAsync(invoke.xdr, ctx(fakeFetch(respond).fetch, timeoutMs));
}

function expectFailed(r: AnalysisResult, simulation: SimulationOutcome): void {
  expect(r.simulation).toEqual(simulation);
  expect(r.status).toBe("partial");
  expect(r.notChecked).toContain("NC-SIMULATION");
}

// ---- tests ----

describe("analyzeAsync simulation", () => {
  it("records simulation data and clears NC-SIMULATION on success, but stays partial", async () => {
    const { fetch: f, calls } = fakeFetch(() => json(success()));
    const r = await analyzeAsync(invoke.xdr, ctx(f));
    expect(r.simulation).toEqual({
      status: "ok",
      latestLedger: 1000,
      minResourceFee: "54321",
      resourceFee: "12345",
      footprint: { readOnly: 1, readWrite: 0 },
      authRequired: [{ credential: "sorobanCredentialsAddress", signatureExpirationLedger: 0 }],
      restore: null,
    });
    expect(r.notChecked).not.toContain("NC-SIMULATION");
    // Contract balance effects are not derived yet.
    expect(r.notChecked).toContain("NC-OPERATION-EFFECTS");
    expect(r.status).toBe("partial");

    // Everything else matches the synchronous analysis.
    const { simulation: _s, notChecked: _n, ...rest } = r;
    const { notChecked: _m, ...sync } = analyze(invoke.xdr, { networkPassphrase: invoke.network_passphrase });
    expect(rest).toEqual(sync);

    // Only the envelope goes to the configured endpoint.
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe(URL_);
    expect(calls[0]?.init?.method).toBe("POST");
    expect(JSON.parse(String(calls[0]?.init?.body))).toEqual({
      jsonrpc: "2.0",
      id: 1,
      method: "simulateTransaction",
      params: { transaction: invoke.xdr },
    });
  });

  it("records a restore preamble", async () => {
    const r = await runInvoke(() => json(success({ restorePreamble: { minResourceFee: "77", transactionData: txData } })));
    expect(r.simulation).toMatchObject({ status: "ok", restore: { minResourceFee: "77" } });
  });

  it("times out when fetch never resolves", async () => {
    const r = await runInvoke(() => new Promise<Response>(() => undefined), 20);
    expectFailed(r, { status: "timeout", timeoutMs: 20 });
  });

  it("times out when the body never finishes", async () => {
    const stalled = new ReadableStream<Uint8Array>({ start: (c) => c.enqueue(new TextEncoder().encode("{")) });
    const r = await runInvoke(() => new Response(stalled, { status: 200 }), 20);
    expectFailed(r, { status: "timeout", timeoutMs: 20 });
  });

  it("HTTP 500 is an error", async () => {
    const r = await runInvoke(() => json(success(), 500));
    expectFailed(r, { status: "error", reason: "http", httpStatus: 500 });
  });

  it("a rejected fetch is a network error", async () => {
    const r = await runInvoke(() => Promise.reject(new TypeError("connection refused")));
    expectFailed(r, { status: "error", reason: "network" });
  });

  it("invalid JSON is malformed", async () => {
    const r = await runInvoke(() => new Response("{not json", { status: 200 }));
    expectFailed(r, { status: "malformed", reason: "invalid_json" });
  });

  it("non-UTF-8 bodies are malformed", async () => {
    const r = await runInvoke(() => new Response(new Uint8Array([0x7b, 0xff, 0x7d]), { status: 200 }));
    expectFailed(r, { status: "malformed", reason: "invalid_json" });
  });

  it("a JSON-RPC error is an error, keeping only its code", async () => {
    const r = await runInvoke(() => json({ jsonrpc: "2.0", id: 1, error: { code: -32602, message: "<script>" } }));
    expectFailed(r, { status: "error", reason: "rpc", rpcCode: -32602 });
  });

  it("a simulation error is an error, without its message", async () => {
    const r = await runInvoke(() => json({ jsonrpc: "2.0", id: 1, result: { latestLedger: 1000, error: "HostError: ..." } }));
    expectFailed(r, { status: "error", reason: "simulation" });
  });

  it.each([
    ["missing minResourceFee", success({ minResourceFee: undefined })],
    ["non-integer minResourceFee", success({ minResourceFee: "1.5" })],
    ["negative minResourceFee", success({ minResourceFee: "-1" })],
    ["minResourceFee above int64", success({ minResourceFee: "9223372036854775808" })],
    ["numeric minResourceFee", success({ minResourceFee: 54321 })],
    ["missing transactionData", success({ transactionData: undefined })],
    ["undecodable transactionData", success({ transactionData: "AAAA" })],
    ["missing results", success({ results: undefined })],
    ["two results", success({ results: [{ xdr: "AAAAAQ==" }, { xdr: "AAAAAQ==" }] })],
    ["result without xdr", success({ results: [{ auth: [] }] })],
    ["undecodable auth entry", success({ results: [{ xdr: "AAAAAQ==", auth: ["AAAA"] }] })],
    ["non-string auth entry", success({ results: [{ xdr: "AAAAAQ==", auth: [1] }] })],
    ["bad latestLedger", success({ latestLedger: -1 })],
    ["bad restorePreamble", success({ restorePreamble: { minResourceFee: "1" } })],
    ["non-string simulation error", success({ error: { code: 1 } })],
    ["wrong id", { ...success(), id: 2 }],
    ["missing jsonrpc", { ...success(), jsonrpc: undefined }],
    ["no result", { jsonrpc: "2.0", id: 1 }],
    ["array result", { jsonrpc: "2.0", id: 1, result: [] }],
    ["error without code", { jsonrpc: "2.0", id: 1, error: { message: "x" } }],
    ["top-level array", []],
    ["null", null],
  ])("%s is malformed", async (_name, body) => {
    const r = await runInvoke(() => json(body));
    expectFailed(r, { status: "malformed", reason: "invalid_shape" });
  });

  it("an oversized body is malformed and not read past the cap", async () => {
    let pulled = 0;
    const chunk = new Uint8Array(64 * 1024).fill(0x20);
    const endless = new ReadableStream<Uint8Array>({
      pull: (c) => {
        pulled += chunk.byteLength;
        c.enqueue(chunk);
      },
    });
    const r = await runInvoke(() => new Response(endless, { status: 200 }));
    expectFailed(r, { status: "malformed", reason: "too_large" });
    expect(pulled).toBeLessThanOrEqual(MAX_SIMULATION_RESPONSE_BYTES + 2 * chunk.byteLength);
  });

  it("a declared oversized body is rejected up front", async () => {
    const r = await runInvoke(() => new Response("{}", { status: 200, headers: { "content-length": String(MAX_SIMULATION_RESPONSE_BYTES + 1) } }));
    expectFailed(r, { status: "malformed", reason: "too_large" });
  });

  it("non-Soroban transactions are skipped without calling the endpoint", async () => {
    const payment = fixture("benign/payment_native.json");
    const { fetch: f, calls } = fakeFetch(() => json(success()));
    const r = await analyzeAsync(payment.xdr, { networkPassphrase: payment.network_passphrase, rpc: { url: URL_, fetch: f } });
    expect(r.simulation).toEqual({ status: "skipped", reason: "no_invoke_host_function" });
    expect(r.notChecked).not.toContain("NC-SIMULATION");
    expect(calls).toHaveLength(0);
    const { simulation: _s, ...rest } = r;
    expect(rest).toEqual(analyze(payment.xdr, { networkPassphrase: payment.network_passphrase }));
  });

  it("without an RPC endpoint, contract calls are skipped and keep NC-SIMULATION", async () => {
    const r = await analyzeAsync(invoke.xdr, { networkPassphrase: invoke.network_passphrase });
    expectFailed(r, { status: "skipped", reason: "no_rpc" });
  });

  it("undecodable input is skipped and unanalyzable", async () => {
    const { fetch: f, calls } = fakeFetch(() => json(success()));
    const r = await analyzeAsync("AAAA", ctx(f));
    expect(r.status).toBe("unanalyzable");
    expect(r.simulation).toEqual({ status: "skipped", reason: "not_decoded" });
    expect(calls).toHaveLength(0);
  });
});

describe("simulateTransaction config", () => {
  const ok = () => fakeFetch(() => json(success())).fetch;

  it.each([
    ["non-http URL", { url: "file:///etc/passwd", fetch: ok() }],
    ["unparseable URL", { url: "not a url", fetch: ok() }],
    ["zero timeout", { url: URL_, timeoutMs: 0, fetch: ok() }],
    ["NaN timeout", { url: URL_, timeoutMs: Number.NaN, fetch: ok() }],
    ["timeout above the maximum", { url: URL_, timeoutMs: 10 * 60_000, fetch: ok() }],
  ])("%s is invalid_config", async (_name, rpc) => {
    expect(await simulateTransaction(invoke.xdr, rpc)).toEqual({ status: "error", reason: "invalid_config" });
  });
});
