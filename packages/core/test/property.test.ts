// Property-based tests over hostile input (AGENTS.md §3.2, §3.5): random and
// mutated data must never throw and never produce a clean result.

import { readdirSync, readFileSync } from "node:fs";

import {
  Account,
  Asset,
  Contract,
  MuxedAccount,
  Operation,
  StrKey,
  TimeoutInfinite,
  TransactionBuilder,
  xdr,
} from "@stellar/stellar-sdk/base";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { accountRef } from "../src/decode/account.ts";
import {
  KeyError,
  MAX_DISPLAY_LENGTH,
  analyze,
  canonicalKey,
  checkSnapshot,
  decodeAuthEntry,
  decodeEnvelope,
  sanitizeUntrusted,
  type AnalysisResult,
  type Snapshot,
} from "../src/index.ts";
import { UNICODE_UNSAFE_REGEX } from "../src/wording/sanitize.ts";

interface Fixture {
  name: string;
  network_passphrase: string;
  xdr: string;
}

const FIXTURES = new URL("../../../fixtures/tx/", import.meta.url);
const fixtures: Fixture[] = (["benign", "hostile"] as const).flatMap((dir) => {
  const base = new URL(`${dir}/`, FIXTURES);
  return readdirSync(base)
    .filter((f) => f.endsWith(".json"))
    .sort()
    .map((f) => JSON.parse(readFileSync(new URL(f, base), "utf8")) as Fixture);
});
const decodable = fixtures.filter((f) => decodeEnvelope(f.xdr, f.network_passphrase).ok);

const PUBLIC = "Public Global Stellar Network ; September 2015";
const TESTNET = "Test SDF Network ; September 2015";
const passphrase = fc.constantFrom(PUBLIC, TESTNET, "Unknown Network ; 2026");

const toBase64 = (b: Uint8Array) => btoa(Array.from(b, (x) => String.fromCharCode(x)).join(""));
const fromBase64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

/** Byte-level mutations an attacker can make to a valid envelope. */
const mutation = fc.oneof(
  fc.record({ kind: fc.constant("flip" as const), at: fc.nat(), value: fc.integer({ min: 0, max: 255 }) }),
  fc.record({ kind: fc.constant("truncate" as const), at: fc.nat() }),
  fc.record({ kind: fc.constant("insert" as const), at: fc.nat(), bytes: fc.uint8Array({ minLength: 1, maxLength: 16 }) }),
  fc.record({ kind: fc.constant("delete" as const), at: fc.nat(), count: fc.integer({ min: 1, max: 16 }) }),
);
type Mutation = typeof mutation extends fc.Arbitrary<infer M> ? M : never;

function mutate(bytes: Uint8Array, m: Mutation): Uint8Array {
  const at = bytes.length === 0 ? 0 : m.at % bytes.length;
  switch (m.kind) {
    case "flip": {
      const out = bytes.slice();
      out[at] = m.value;
      return out;
    }
    case "truncate":
      return bytes.slice(0, at);
    case "insert":
      return Uint8Array.from([...bytes.subarray(0, at), ...m.bytes, ...bytes.subarray(at)]);
    case "delete":
      return Uint8Array.from([...bytes.subarray(0, at), ...bytes.subarray(at + m.count)]);
  }
}

/** Without a verified snapshot, counterparties are unchecked: never a clean result. */
function expectNotClean(r: AnalysisResult): void {
  expect(["partial", "unanalyzable"]).toContain(r.status);
  expect(r.notChecked.length).toBeGreaterThan(0);
  if (r.status === "unanalyzable") {
    expect(r.txHash).toBeNull();
    expect(r.notChecked).toEqual(["NC-DECODE"]);
  } else {
    expect(r.notChecked).toContain("NC-COUNTERPARTY-SIGNALS");
    expect(r.txHash).toMatch(/^[0-9a-f]{64}$/);
  }
}

describe("decoder and analyze on hostile envelopes", () => {
  it("random bytes are unanalyzable", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 2048 }), passphrase, (bytes, p) => {
        expectNotClean(analyze(toBase64(bytes), { networkPassphrase: p }));
      }),
    );
  });

  it("random strings never throw and are never clean", () => {
    fc.assert(
      fc.property(fc.string({ unit: "binary", maxLength: 512 }), fc.string({ maxLength: 300 }), (s, p) => {
        expectNotClean(analyze(s, { networkPassphrase: p }));
      }),
    );
  });

  it("mutated fixtures never throw and are never clean", () => {
    fc.assert(
      fc.property(fc.constantFrom(...decodable), fc.array(mutation, { minLength: 1, maxLength: 4 }), passphrase, (f, ms, p) => {
        const bytes = ms.reduce(mutate, fromBase64(f.xdr));
        expectNotClean(analyze(toBase64(bytes), { networkPassphrase: p }));
      }),
    );
  });

  it("valid fixtures are never clean without a snapshot, whatever asOf is", () => {
    fc.assert(
      fc.property(fc.constantFrom(...decodable), fc.date({ noInvalidDate: false }), (f, asOf) => {
        expectNotClean(analyze(f.xdr, { networkPassphrase: f.network_passphrase, asOf }));
      }),
    );
  });
});

describe("canonicalKey", () => {
  const network = fc.oneof(fc.constantFrom("public", "testnet"), fc.string({ maxLength: 12 }));
  const type = fc.oneof(fc.constantFrom("account", "asset", "contract", "wasm_hash", "domain"), fc.string({ maxLength: 12 }));
  const key = fc.oneof(
    fc.string({ unit: "binary", maxLength: 320 }),
    fc.stringMatching(/^[A-Za-z0-9-]{1,20}(\.[A-Za-z0-9-]{1,20}){1,3}\.?$/),
    fc.stringMatching(/^[0-9a-fA-F]{64}$/),
  );

  it("either throws KeyError or returns a stable, prefixed key", () => {
    fc.assert(
      fc.property(network, type, key, (n, t, k) => {
        let out: string;
        try {
          out = canonicalKey(n, t, k);
        } catch (e) {
          expect(e).toBeInstanceOf(KeyError);
          return;
        }
        expect(out.startsWith(`${n}|${t}|`)).toBe(true);
        const normalized = out.slice(n.length + t.length + 2);
        expect(canonicalKey(n, t, normalized)).toBe(out);
        expect(/[\u0000-\u001f\u007f-￿]/.test(normalized)).toBe(false);
      }),
    );
  });

  it("domains and wasm hashes are case-insensitive", () => {
    fc.assert(
      fc.property(fc.constantFrom("domain", "wasm_hash"), key, (t, k) => {
        const lower = (() => {
          try {
            return canonicalKey("public", t, k.toLowerCase());
          } catch {
            return null;
          }
        })();
        if (lower === null || k.toUpperCase().toLowerCase() !== k.toLowerCase()) return;
        expect(canonicalKey("public", t, k.toUpperCase())).toBe(lower);
      }),
    );
  });
});

describe("checkSnapshot", () => {
  const vector = JSON.parse(readFileSync(new URL("../../../intel-schemas/snapshot_signing.json", import.meta.url), "utf8")) as {
    public_key_hex: string;
    snapshot: Snapshot;
  };
  const pinnedKeys = { [vector.snapshot.key_id]: Uint8Array.from(vector.public_key_hex.match(/../g) ?? [], (b) => Number.parseInt(b, 16)) };
  const generated = Date.parse(vector.snapshot.generated_at);
  const opts = (asOf = new Date(generated + 60_000)) => ({ pinnedKeys, network: "public" as const, asOf });

  it("arbitrary values never throw and are never accepted", () => {
    fc.assert(
      fc.property(fc.anything({ withNullPrototype: true, withBigInt: true, withDate: true, withMap: true }), (raw) => {
        expect(checkSnapshot(raw, opts()).ok).toBe(false);
      }),
    );
  });

  it("any changed field is rejected", () => {
    const fields = Object.keys(vector.snapshot) as (keyof Snapshot)[];
    fc.assert(
      fc.property(fc.constantFrom(...fields), fc.jsonValue(), (field, value) => {
        fc.pre(JSON.stringify(value) !== JSON.stringify(vector.snapshot[field]));
        const s: Record<string, unknown> = { ...vector.snapshot, [field]: value };
        expect(checkSnapshot(s, opts()).ok).toBe(false);
      }),
    );
  });

  it("the signed vector is accepted only inside the freshness window", () => {
    fc.assert(
      fc.property(fc.date({ noInvalidDate: false }), (asOf) => {
        const r = checkSnapshot(vector.snapshot, opts(asOf));
        const age = (asOf.getTime() - generated) / 1000;
        expect(r.ok).toBe(Number.isFinite(age) && age >= -5 * 60 && age <= 15 * 60);
      }),
    );
  });
});

describe("sanitizeUntrusted", () => {
  const UNSAFE = UNICODE_UNSAFE_REGEX;
  const input = fc.oneof(fc.string({ unit: "binary", maxLength: 600 }), fc.uint8Array({ maxLength: 1200 }));

  it("output has no unsafe characters and is capped", () => {
    fc.assert(
      fc.property(input, (x) => {
        const out = sanitizeUntrusted(x);
        expect(UNSAFE.test(out)).toBe(false);
        expect([...out].length).toBeLessThanOrEqual(MAX_DISPLAY_LENGTH);
      }),
    );
  });

  it("is idempotent", () => {
    fc.assert(
      fc.property(input, (x) => {
        const once = sanitizeUntrusted(x);
        expect(sanitizeUntrusted(once)).toBe(once);
      }),
    );
  });
});

describe("muxed account normalization", () => {
  const ed25519Bytes = fc.uint8Array({ minLength: 32, maxLength: 32 });
  const uint64Id = fc.oneof(
    fc.constantFrom(0n, 1n, 9_007_199_254_740_993n, 18_446_744_073_709_551_615n),
    fc.bigInt({ min: 0n, max: 18_446_744_073_709_551_615n }),
  );
  const contractId = StrKey.encodeContract(new Uint8Array(32).fill(7));
  const rootInvocation = (() => {
    const call = new Contract(contractId).call("transfer");
    if (call.body.type !== "invokeHostFunction" || call.body.invokeHostFunctionOp.hostFunction.type !== "hostFunctionTypeInvokeContract") {
      throw new Error("unexpected contract call shape");
    }
    return new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(call.body.invokeHostFunctionOp.hostFunction.invokeContract),
      subInvocations: [],
    });
  })();

  it("normalizes arbitrary M... muxed accounts strictly to SDK G... base address and exact uint64 id", () => {
    fc.assert(
      fc.property(ed25519Bytes, uint64Id, (rawKey, subId) => {
        const gAddress = StrKey.encodeEd25519PublicKey(rawKey);
        const muxed = new MuxedAccount(new Account(gAddress, "100"), subId.toString());
        const mAddress = muxed.accountId();
        expect(mAddress.startsWith("M")).toBe(true);

        const parsedFromM = MuxedAccount.fromAddress(mAddress, "100");
        const normalized = accountRef(parsedFromM.toXDRObject());

        expect(normalized).toEqual({
          account: parsedFromM.baseAccount().accountId(),
          muxedId: subId.toString(),
        });
        expect(normalized.account).toBe(gAddress);
        expect(accountRef(parsedFromM.toXDRObject())).toEqual(normalized);

        expect(canonicalKey("public", "account", normalized.account)).toBe(`public|account|${gAddress}`);
        expect(() => canonicalKey("public", "account", mAddress)).toThrowError(KeyError);
      }),
    );
  });

  it("normalizes muxed transaction sources, operation sources, and payment destinations in decodeEnvelope and analyze", () => {
    fc.assert(
      fc.property(ed25519Bytes, uint64Id, ed25519Bytes, uint64Id, (srcKey, srcId, dstKey, dstId) => {
        const srcBase = StrKey.encodeEd25519PublicKey(srcKey);
        const dstBase = StrKey.encodeEd25519PublicKey(dstKey);
        const srcMuxed = new MuxedAccount(new Account(srcBase, "100"), srcId.toString());
        const dstMuxed = new MuxedAccount(new Account(dstBase, "0"), dstId.toString());

        const tx = new TransactionBuilder(srcMuxed, { fee: "100", networkPassphrase: PUBLIC })
          .setTimeout(TimeoutInfinite)
          .addOperation(
            Operation.payment({
              source: dstMuxed.accountId(),
              destination: dstMuxed.accountId(),
              asset: Asset.native(),
              amount: "1",
            }),
          )
          .build();

        const xdrB64 = tx.toXDR();
        const decoded = decodeEnvelope(xdrB64, PUBLIC);
        expect(decoded.ok).toBe(true);
        if (!decoded.ok) return;

        expect(decoded.tx.source).toEqual({
          account: srcMuxed.baseAccount().accountId(),
          muxedId: srcId.toString(),
        });
        expect(decoded.tx.operations[0]?.source).toEqual({
          account: dstMuxed.baseAccount().accountId(),
          muxedId: dstId.toString(),
        });

        const result = analyze(xdrB64, { networkPassphrase: PUBLIC });
        expect(result.status).toBe("partial");
        for (const effect of result.effects) {
          expect(effect.account.startsWith("G")).toBe(true);
          expect([srcBase, dstBase]).toContain(effect.account);
          expect(typeof effect.deltaMin).toBe("bigint");
          expect(effect.deltaMax === null || typeof effect.deltaMax === "bigint").toBe(true);
        }
      }),
    );
  });

  it("normalizes Soroban scAddressTypeMuxedAccount credentials strictly to G... base address and exact uint64 id", () => {
    fc.assert(
      fc.property(ed25519Bytes, uint64Id, (rawKey, subId) => {
        const gAddress = StrKey.encodeEd25519PublicKey(rawKey);
        const muxed = new MuxedAccount(new Account(gAddress, "0"), subId.toString());
        const scAddr = xdr.ScAddress.scAddressTypeMuxedAccount(
          new xdr.MuxedEd25519Account({ id: subId, ed25519: rawKey }),
        );
        const entry = new xdr.SorobanAuthorizationEntry({
          credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
            new xdr.SorobanAddressCredentials({
              address: scAddr,
              nonce: 7n,
              signatureExpirationLedger: 5_000_000,
              signature: xdr.ScVal.scvVoid(),
            }),
          ),
          rootInvocation,
        });

        const decoded = decodeAuthEntry(entry.toXDR("base64"), TESTNET);
        expect(decoded).toEqual({
          ok: true,
          entry: expect.objectContaining({
            address: {
              kind: "account",
              account: muxed.baseAccount().accountId(),
              muxedId: subId.toString(),
            },
          }),
        });
      }),
    );
  });
});
