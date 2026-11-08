import { readFileSync } from "node:fs";

import { hash } from "@stellar/stellar-sdk/base";
import { describe, expect, it } from "vitest";

import { checkSnapshot, snapshotPayload, type Snapshot } from "../../src/intel/snapshot.ts";

// Pinned from sorosentinel-intel (intel-schemas/PINNED); never edited here.
const vector = JSON.parse(readFileSync(new URL("../../../../intel-schemas/snapshot_signing.json", import.meta.url), "utf8")) as {
  public_key_hex: string;
  payload_sha256: string;
  snapshot: Snapshot;
};

const bytes = (hex: string) => Uint8Array.from(hex.match(/../g) ?? [], (b) => Number.parseInt(b, 16));
const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const pinned = { "test-key-1": bytes(vector.public_key_hex) };
const generated = Date.parse(vector.snapshot.generated_at);
const opts = (over: Partial<{ asOf: Date; network: "public" | "testnet"; maxAgeSeconds: number; minVersion: number }> = {}) => ({
  pinnedKeys: pinned,
  network: "public" as const,
  asOf: new Date(generated + 60_000),
  ...over,
});
const clone = (): Snapshot => JSON.parse(JSON.stringify(vector.snapshot)) as Snapshot;

describe("snapshot verification matches Intel's vector", () => {
  it("rebuilds exactly the signed bytes", () => {
    expect(toHex(hash(snapshotPayload(vector.snapshot)))).toBe(vector.payload_sha256);
  });

  it("accepts the vector with the pinned key", () => {
    const r = checkSnapshot(vector.snapshot, opts());
    expect(r.ok).toBe(true);
    if (r.ok) expect([...r.entries]).toEqual(vector.snapshot.entries);
  });
});

describe("snapshot rejection", () => {
  const tampered: [string, (s: Snapshot) => void, string][] = [
    ["entry removed", (s) => s.entries.shift(), "bad_signature"],
    ["entry changed", (s) => (s.entries[0] = "8b079656a7f799dc45e331128db881e3"), "bad_signature"],
    ["version", (s) => (s.version = 2), "bad_signature"],
    ["ruleset", (s) => (s.ruleset_version = "2026.10.2"), "bad_signature"],
    ["network relabel", (s) => (s.network = "testnet"), "bad_signature"],
    ["unsorted", (s) => s.entries.reverse(), "malformed"],
    ["duplicate", (s) => (s.entries[1] = s.entries[0] ?? ""), "malformed"],
    ["uppercase entry", (s) => (s.entries[0] = (s.entries[0] ?? "").toUpperCase()), "malformed"],
    ["newline in key id", (s) => (s.key_id = "test-key-1\nentries:0"), "malformed"],
    ["non-UTC time", (s) => (s.generated_at = "2026-10-27T01:00:00+01:00"), "malformed"],
    ["format version", (s) => ((s as { format_version: number }).format_version = 2), "malformed"],
    ["unknown key id", (s) => (s.key_id = "other-key"), "unknown_key"],
    ["bad base64", (s) => (s.signature = "!!!!"), "bad_signature"],
    ["short signature", (s) => (s.signature = s.signature.slice(0, 20)), "bad_signature"],
  ];
  it.each(tampered)("%s", (_n, mutate, reason) => {
    const s = clone();
    mutate(s);
    expect(checkSnapshot(s, opts())).toEqual({ ok: false, reason });
  });

  it.each([
    ["extra field", { ...vector.snapshot, note: "x" }],
    ["missing field", { ...vector.snapshot, signature: undefined }],
    ["array", []],
    ["null", null],
    ["string", "snapshot"],
    ["version as string", { ...vector.snapshot, version: "1" }],
  ])("%s is malformed", (_n, raw) => {
    expect(checkSnapshot(JSON.parse(JSON.stringify(raw) ?? "null"), opts())).toEqual({ ok: false, reason: "malformed" });
  });

  it("rejects a snapshot for another network", () => {
    expect(checkSnapshot(vector.snapshot, opts({ network: "testnet" }))).toEqual({ ok: false, reason: "network_mismatch" });
  });

  it("rejects stale and future-dated snapshots", () => {
    expect(checkSnapshot(vector.snapshot, opts({ asOf: new Date(generated + 901_000) }))).toEqual({ ok: false, reason: "stale" });
    expect(checkSnapshot(vector.snapshot, opts({ asOf: new Date(generated + 900_000) })).ok).toBe(true);
    expect(checkSnapshot(vector.snapshot, opts({ asOf: new Date(generated - 301_000) }))).toEqual({ ok: false, reason: "from_future" });
    expect(checkSnapshot(vector.snapshot, opts({ asOf: new Date(Number.NaN) }))).toEqual({ ok: false, reason: "stale" });
  });

  it("rejects rolled-back snapshot versions below minVersion", () => {
    expect(checkSnapshot(vector.snapshot, opts({ minVersion: 2 }))).toEqual({ ok: false, reason: "rollback" });
    expect(checkSnapshot(vector.snapshot, opts({ minVersion: 1 })).ok).toBe(true);
  });

  it("rejects a wrong-length pinned key", () => {
    expect(checkSnapshot(vector.snapshot, { ...opts(), pinnedKeys: { "test-key-1": new Uint8Array(31) } })).toEqual({
      ok: false,
      reason: "unknown_key",
    });
  });

  it("enforces byte limits and declaredLength ceiling", () => {
    expect(checkSnapshot(vector.snapshot, { ...opts(), declaredLength: 45 * 1024 * 1024 })).toEqual({
      ok: false,
      reason: "malformed",
    });

    const rawStr = JSON.stringify(vector.snapshot);
    expect(checkSnapshot(rawStr, { ...opts(), maxBytes: 10 })).toEqual({ ok: false, reason: "malformed" });
    expect(checkSnapshot(rawStr, opts()).ok).toBe(true);

    const rawBytes = new TextEncoder().encode(rawStr);
    expect(checkSnapshot(rawBytes, { ...opts(), maxBytes: 10 })).toEqual({ ok: false, reason: "malformed" });
    expect(checkSnapshot(rawBytes, opts()).ok).toBe(true);
  });

  it("rejects entries array exceeding MAX_ENTRIES ceiling", () => {
    const oversized = { ...vector.snapshot, entries: new Array(1_000_001) };
    expect(checkSnapshot(oversized, opts())).toEqual({ ok: false, reason: "malformed" });
  });
});
