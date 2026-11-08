import { verify } from "@stellar/stellar-sdk/base";

/**
 * Client-side verification of Intel's signed snapshot
 * (sorosentinel-intel schemas/snapshot-signing.md, format version 1).
 * Any failure means the snapshot is not used; it is never partially trusted.
 */

export const MAX_ENTRIES = 1_000_000;
/** Maximum allowed serialized snapshot size in bytes (40 MiB). */
export const MAX_SNAPSHOT_BYTES = 40 * 1024 * 1024;
/** Snapshots are published every few minutes; older than 15 minutes is "protection data stale". */
export const DEFAULT_MAX_AGE_SECONDS = 15 * 60;
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
  | "revoked_key"
  | "bad_signature"
  | "network_mismatch"
  | "stale"
  | "from_future"
  | "rollback"
  | "invalid_options";

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
  /** Minimum version to accept, persisted from the last good snapshot to prevent rollback. */
  minVersion?: number;
  /** Declared or measured size of the snapshot in bytes, rejected if over maxBytes. */
  declaredLength?: number;
  /** Maximum allowed size in bytes (defaults to MAX_SNAPSHOT_BYTES). */
  maxBytes?: number;
  /** Set or list of revoked key IDs that Guard must refuse to trust even if pinned. */
  revokedKeyIds?: ReadonlySet<string> | readonly string[];
}

/** Strict structural parse: exact field set, every pattern, sorted unique entries. */
export function parseSnapshot(raw: unknown, opts?: { maxBytes?: number; declaredLength?: number }): Snapshot | null {
  const maxBytes = opts?.maxBytes ?? MAX_SNAPSHOT_BYTES;
  if (opts?.declaredLength !== undefined && opts.declaredLength > maxBytes) {
    return null;
  }
  if (raw instanceof Uint8Array) {
    if (raw.byteLength > maxBytes) return null;
    try {
      raw = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
    } catch {
      return null;
    }
  } else if (typeof raw === "string") {
    if (raw.length > maxBytes) return null;
    const byteLength = new TextEncoder().encode(raw).byteLength;
    if (byteLength > maxBytes) return null;
    try {
      raw = JSON.parse(raw);
    } catch {
      return null;
    }
  }
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
  if (!validOptions(opts)) return { ok: false, reason: "invalid_options" };
  const s = parseSnapshot(raw, opts);
  if (s === null) return { ok: false, reason: "malformed" };
  if (isRevoked(s.key_id, opts.revokedKeyIds)) {
    return { ok: false, reason: "revoked_key" };
  }
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
  // A minVersion read back from storage that is not a positive integer would
  // otherwise compare false and silently switch rollback protection off.
  if (opts.minVersion !== undefined) {
    if (!Number.isSafeInteger(opts.minVersion) || opts.minVersion < 1) return { ok: false, reason: "invalid_options" };
    if (s.version < opts.minVersion) return { ok: false, reason: "rollback" };
  }

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

function isRevoked(keyId: string, revoked?: ReadonlySet<string> | readonly string[]): boolean {
  if (revoked === undefined) return false;
  if (revoked instanceof Set) return revoked.has(keyId);
  if (Array.isArray(revoked)) return revoked.includes(keyId);
  return false;
}

/** Numeric options must be finite and positive; anything else is a caller bug, not a usable bound. */
function validOptions(opts: SnapshotOptions): boolean {
  const positive = (n: number | undefined) => n === undefined || (Number.isFinite(n) && n > 0);
  return positive(opts.maxAgeSeconds) && positive(opts.maxBytes) && (opts.declaredLength === undefined || (Number.isSafeInteger(opts.declaredLength) && opts.declaredLength >= 0));
}
