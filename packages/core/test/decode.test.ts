import { readdirSync, readFileSync } from "node:fs";

import { hash, xdr } from "@stellar/stellar-sdk/base";
import { describe, expect, it } from "vitest";

import { decodeEnvelope, MAX_ENVELOPE_BASE64_LENGTH, operationSupport } from "../src/index.ts";
import type { DecodedTransaction, OperationType } from "../src/index.ts";

interface Fixture {
  name: string;
  network_passphrase: string;
  xdr: string;
  expected:
    | { unanalyzable: string }
    | {
        envelope: DecodedTransaction["envelope"];
        network: DecodedTransaction["network"];
        tx_hash: string;
        source: string;
        source_muxed_id?: string;
        fee_source?: string;
        time_bounds: { min: string; max: string } | null;
        memo_type: string;
        operations: { type: string; source: string; has_own_source: boolean }[];
        auth?: { credential: string; signatureExpirationLedger?: number }[];
      };
}

const FIXTURES = new URL("../../../fixtures/tx/", import.meta.url);

function load(dir: "benign" | "hostile"): Fixture[] {
  const base = new URL(`${dir}/`, FIXTURES);
  return readdirSync(base)
    .filter((f) => f.endsWith(".json"))
    .sort()
    .map((f) => JSON.parse(readFileSync(new URL(f, base), "utf8")) as Fixture);
}

const fixtures = [...load("benign"), ...load("hostile")];

describe("fixtures", () => {
  it.each(fixtures.map((f) => [f.name, f] as const))("%s", (_name, f) => {
    const res = decodeEnvelope(f.xdr, f.network_passphrase);
    const exp = f.expected;
    if ("unanalyzable" in exp) {
      expect(res).toEqual({ ok: false, status: "unanalyzable", reason: exp.unanalyzable });
      return;
    }
    if (!res.ok) throw new Error(`unexpected unanalyzable: ${res.reason}`);
    const tx = res.tx;
    expect(tx.envelope).toBe(exp.envelope);
    expect(tx.network).toBe(exp.network);
    expect(tx.txHash).toBe(exp.tx_hash);
    expect(tx.source.account).toBe(exp.source);
    expect(tx.source.muxedId).toBe(exp.source_muxed_id);
    expect(tx.feeSource?.account).toBe(exp.fee_source);
    expect(tx.timeBounds).toEqual(exp.time_bounds);
    expect(tx.memo.type).toBe(exp.memo_type);
    expect(tx.operations.map((o) => ({ type: o.type, source: o.source.account, has_own_source: o.hasOwnSource }))).toEqual(exp.operations);
    tx.operations.forEach((o, i) => expect(o.index).toBe(i));
    for (const o of tx.operations) {
      // Only contract invocations carry auth entries.
      expect(o.auth !== undefined).toBe(o.type === "invokeHostFunction");
    }
    if (exp.auth) {
      expect(tx.operations.find((o) => o.type === "invokeHostFunction")?.auth).toEqual(exp.auth);
    }
  });
});

// Recomputes the signature payload hash without the SDK's transaction classes:
// sha256(sha256(passphrase) || envelope type || transaction XDR).
function signaturePayloadHash(envelopeB64: string, passphrase: string): string {
  const env = xdr.TransactionEnvelope.fromXdr(envelopeB64, "base64");
  let type: number;
  let body: Uint8Array;
  switch (env.type) {
    case "envelopeTypeTx":
      type = 2;
      body = env.v1.tx.toXdr();
      break;
    case "envelopeTypeTxFeeBump":
      type = 5;
      body = env.feeBump.tx.toXdr();
      break;
    case "envelopeTypeTxV0":
      throw new Error("not used by fixtures");
  }
  const networkId = hash(new TextEncoder().encode(passphrase));
  const payload = new Uint8Array(networkId.length + 4 + body.length);
  payload.set(networkId, 0);
  new DataView(payload.buffer).setUint32(networkId.length, type);
  payload.set(body, networkId.length + 4);
  return Array.from(hash(payload), (b) => b.toString(16).padStart(2, "0")).join("");
}

describe("signed bytes", () => {
  const decodable = fixtures.filter((f) => !("unanalyzable" in f.expected));
  it.each(decodable.map((f) => [f.name, f] as const))("%s hash covers exactly the signature payload", (_n, f) => {
    const res = decodeEnvelope(f.xdr, f.network_passphrase);
    if (!res.ok) throw new Error(res.reason);
    expect(res.tx.txHash).toBe(signaturePayloadHash(f.xdr, f.network_passphrase));
  });

  it("the same envelope hashes differently per network (passphrase is part of the payload)", () => {
    const f = decodable.find((x) => x.name === "payment_native")!;
    const pub = decodeEnvelope(f.xdr, f.network_passphrase);
    const test = decodeEnvelope(f.xdr, "Test SDF Network ; September 2015");
    if (!pub.ok || !test.ok) throw new Error("decode failed");
    expect(pub.tx.txHash).not.toBe(test.tx.txHash);
    expect(test.tx.network).toBe("testnet");
  });
});

describe("operation support", () => {
  // Record<OperationType, …> forces this list to stay complete at compile time.
  const all: Record<OperationType, true> = {
    createAccount: true, payment: true, pathPaymentStrictReceive: true, manageSellOffer: true,
    createPassiveSellOffer: true, setOptions: true, changeTrust: true, allowTrust: true,
    accountMerge: true, inflation: true, manageData: true, bumpSequence: true, manageBuyOffer: true,
    pathPaymentStrictSend: true, createClaimableBalance: true, claimClaimableBalance: true,
    beginSponsoringFutureReserves: true, endSponsoringFutureReserves: true, revokeSponsorship: true,
    clawback: true, clawbackClaimableBalance: true, setTrustLineFlags: true, liquidityPoolDeposit: true,
    liquidityPoolWithdraw: true, invokeHostFunction: true, extendFootprintTtl: true, restoreFootprint: true,
  };
  const types = Object.keys(all) as OperationType[];

  it("derives effects for exactly the v1 operations", () => {
    expect(types.filter((t) => operationSupport(t) === "effects").sort()).toEqual(
      ["accountMerge", "changeTrust", "createAccount", "invokeHostFunction", "pathPaymentStrictReceive", "pathPaymentStrictSend", "payment", "setOptions"],
    );
  });

  it("every operation type has a fixture (fails when a protocol adds one)", () => {
    const covered = new Set(fixtures.flatMap((f) => ("operations" in f.expected ? f.expected.operations.map((o) => o.type) : [])));
    expect(types.filter((t) => !covered.has(t))).toEqual([]);
  });

  it("covers every Soroban credential arm an envelope can carry", () => {
    const creds = new Set(fixtures.flatMap((f) => ("auth" in f.expected ? (f.expected.auth ?? []).map((a) => a.credential) : [])));
    expect([...creds].sort()).toEqual([
      "sorobanCredentialsAddress",
      "sorobanCredentialsAddressV2",
      "sorobanCredentialsAddressWithDelegates",
      "sorobanCredentialsSourceAccount",
    ]);
  });
});

describe("hostile input", () => {
  const P = "Public Global Stellar Network ; September 2015";
  const valid = fixtures.find((f) => f.name === "payment_native")!.xdr;

  it("rejects oversized input before decoding", () => {
    expect(decodeEnvelope("A".repeat(MAX_ENVELOPE_BASE64_LENGTH + 1), P)).toEqual({ ok: false, status: "unanalyzable", reason: "input_too_large" });
  });

  it.each(["", "x".repeat(257)])("rejects passphrase of length %#", (pp) => {
    expect(decodeEnvelope(valid, pp)).toEqual({ ok: false, status: "unanalyzable", reason: "invalid_network_passphrase" });
  });

  it.each(["", "AAAA", "////////", "AAAAAgAAAAA="])("empty or garbage envelope %j is unanalyzable", (input) => {
    expect(decodeEnvelope(input, P)).toEqual({ ok: false, status: "unanalyzable", reason: "decode_failed" });
  });

  it("never throws on byte-level mutations of a valid envelope", () => {
    const bytes = Uint8Array.from(atob(valid), (c) => c.charCodeAt(0));
    let decoded = 0;
    for (let i = 0; i < bytes.length; i++) {
      for (const flip of [0x01, 0x80, 0xff]) {
        const m = bytes.slice();
        m[i] = (m[i] ?? 0) ^ flip;
        const res = decodeEnvelope(btoa(String.fromCharCode(...m)), P);
        expect(res.ok || res.status === "unanalyzable").toBe(true);
        if (res.ok) decoded++;
      }
    }
    expect(decoded).toBeGreaterThan(0);
  });

  it("is deterministic", () => {
    expect(decodeEnvelope(valid, P)).toEqual(decodeEnvelope(valid, P));
  });
});
