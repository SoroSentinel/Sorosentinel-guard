import { verify } from "@stellar/stellar-sdk/base";

/**
 * Client-side verification of Intel's signed snapshot
 * (sorosentinel-intel schemas/snapshot-signing.md, format version 1).
 * Any failure means the snapshot is not used; it is never partially trusted.
 */

export const MAX_ENTRIES = 10_000_000;
/** Snapshots are published every few minutes; older than this is "protection data stale". TODO: confirm the product value. */
export const DEFAULT_MAX_AGE_SECONDS = 60 * 60;
/** Tolerated clock skew for a snapshot dated after `asOf`. */
export const MAX_FUTURE_SKEW_SECONDS = 5 * 60;

const MAGIC = "SOROSENTINEL-SNAPSHOT-V1\n";
const KEY_ID = /^[a-z0-9-]{1,64}$/;
const RULESET = /^[0-9]{4}\.[0-9]{2}\.[0-9]+$/;
const ENTRY = /^[0-9a-f]{32}$/;
const GENERATED_AT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const FIELDS = ["format_version", "network", "version", "generated_at", "ruleset_version", "key_id", "entries", "signature"];

export interface Snapshot {
  format_version: 1;
  network: "public" | "testnet";
  version: number;
  generated_at: string;
  ruleset_version: string;
  key_id: string;
  entries: string[];
  signature: string;
}

export type SnapshotRejection =
  | "malformed"
  | "unknown_key"
  | "bad_signature"
  | "network_mismatch"
  | "stale"
  | "from_future";

export type SnapshotCheck =
  | { ok: true; snapshot: Snapshot; entries: ReadonlySet<string> }
  | { ok: false; reason: SnapshotRejection };

export interface SnapshotOptions {
  /** Public keys pinned in the integrator's build, by key id (32 raw bytes each). */
  pinnedKeys: Readonly<Record<string, Uint8Array>>;
  /** Network the transaction is for; the snapshot must match. */
  network: "public" | "testnet";
  /** Reference time supplied by the caller (Guard never reads the clock). */
  asOf: Date;
  maxAgeSeconds?: number;
}

/** Strict structural parse: exact field set, every pattern, sorted unique entries. */
export function parseSnapshot(raw: unknown): Snapshot | null {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return null;
  const o = raw as Record<string, unknown>;
  const keys = Object.keys(o);
  if (keys.length !== FIELDS.length || !FIELDS.every((f) => keys.includes(f))) return null;
  const { format_version, network, version, generated_at, ruleset_version, key_id, entries, signature } = o;
  if (
    format_version !== 1 ||
    (network !== "public" && network !== "testnet") ||
    typeof version !== "number" || !Number.isSafeInteger(version) || version < 1 ||
    typeof generated_at !== "string" || !GENERATED_AT.test(generated_at) || Number.isNaN(Date.parse(generated_at)) ||
    typeof ruleset_version !== "string" || !RULESET.test(ruleset_version) ||
    typeof key_id !== "string" || !KEY_ID.test(key_id) ||
    typeof signature !== "string" ||
    !Array.isArray(entries) || entries.length > MAX_ENTRIES
  ) {
    return null;
  }
  let prev = "";
  for (const e of entries) {
    if (typeof e !== "string" || !ENTRY.test(e) || e <= prev) return null;
    prev = e;
  }
  return { format_version, network, version, generated_at, ruleset_version, key_id, entries: entries as string[], signature };
}

/** Exactly the bytes Intel signs. */
export function snapshotPayload(s: Snapshot): Uint8Array {
  const header =
    MAGIC +
    `network:${s.network}\n` +
    `version:${s.version}\n` +
    `generated_at:${s.generated_at}\n` +
    `ruleset_version:${s.ruleset_version}\n` +
    `key_id:${s.key_id}\n` +
    `entries:${s.entries.length}\n`;
  const head = new TextEncoder().encode(header);
  const out = new Uint8Array(head.length + s.entries.length * 16);
  out.set(head, 0);
  s.entries.forEach((e, i) => {
    for (let j = 0; j < 16; j++) out[head.length + i * 16 + j] = Number.parseInt(e.slice(j * 2, j * 2 + 2), 16);
  });
  return out;
}

/** Parses, checks network and age, and verifies the Ed25519 signature against a pinned key. */
export function checkSnapshot(raw: unknown, opts: SnapshotOptions): SnapshotCheck {
  const s = parseSnapshot(raw);
  if (s === null) return { ok: false, reason: "malformed" };
  const key = opts.pinnedKeys[s.key_id];
  if (key === undefined || key.length !== 32) return { ok: false, reason: "unknown_key" };
  const sig = decodeBase64(s.signature);
  if (sig === null || sig.length !== 64) return { ok: false, reason: "bad_signature" };
  let valid = false;
  try {
    valid = verify(snapshotPayload(s), sig, key);
  } catch {
    valid = false;
  }
  if (!valid) return { ok: false, reason: "bad_signature" };
  if (s.network !== opts.network) return { ok: false, reason: "network_mismatch" };

  const asOfMs = opts.asOf.getTime();
  if (!Number.isFinite(asOfMs)) return { ok: false, reason: "stale" };
  const ageSeconds = (asOfMs - Date.parse(s.generated_at)) / 1000;
  if (ageSeconds < -MAX_FUTURE_SKEW_SECONDS) return { ok: false, reason: "from_future" };
  if (ageSeconds > (opts.maxAgeSeconds ?? DEFAULT_MAX_AGE_SECONDS)) return { ok: false, reason: "stale" };
  return { ok: true, snapshot: s, entries: new Set(s.entries) };
}

function decodeBase64(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4 !== 0) return null;
  try {
    return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}
