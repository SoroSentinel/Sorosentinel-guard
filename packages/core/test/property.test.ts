// Property-based tests over hostile input (AGENTS.md §3.2, §3.5): random and
// mutated data must never throw and never produce a clean result.

import { readdirSync, readFileSync } from "node:fs";

import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  KeyError,
  MAX_DISPLAY_LENGTH,
  analyze,
  canonicalKey,
  checkSnapshot,
  decodeEnvelope,
  sanitizeUntrusted,
  type AnalysisResult,
  type Snapshot,
} from "../src/index.ts";

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
        expect(r.ok).toBe(Number.isFinite(age) && age >= -5 * 60 && age <= 60 * 60);
      }),
    );
  });
});

describe("sanitizeUntrusted", () => {
  const UNSAFE = /[\u0000-\u001f\u007f-\u009f؜​-‏‪-‮⁠⁦-⁩﻿]/u;
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
