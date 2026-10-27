import { hash } from "@stellar/stellar-sdk/base";

/**
 * Canonical entity-key encoding, ported from sorosentinel-intel
 * (schemas/canonical-key.md, internal/entity). Must agree byte for byte with
 * Go and Rust: `make test-contract` runs Intel's pinned vectors.
 */

export type EntityType = "account" | "asset" | "contract" | "wasm_hash" | "domain";
export type KeyErrorCode = "unknown_network" | "unknown_type" | "invalid_key" | "muxed_not_normalized" | "non_ascii";

export class KeyError extends Error {
  constructor(readonly code: KeyErrorCode) {
    super(`entity key: ${code}`);
  }
}

const MAX_KEY_BYTES = 300;
// TODO(verify): shape only; strkey checksums are checked by the SDK where keys come from XDR.
const ACCOUNT = /^G[A-Z2-7]{55}$/;
const CONTRACT = /^C[A-Z2-7]{55}$/;
const ASSET_CODE = /^[A-Za-z0-9]{1,12}$/;
const WASM_HASH = /^[0-9a-f]{64}$/;
const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

/** Returns "<network>|<type>|<normalized key>". Throws KeyError. */
export function canonicalKey(network: string, type: string, key: string): string {
  if (network !== "public" && network !== "testnet") throw new KeyError("unknown_network");
  return `${network}|${type}|${normalizeKey(type, key)}`;
}

/** First 128 bits of SHA-256(canonical), lowercase hex: the snapshot entry. */
export function snapshotHash(canonical: string): string {
  return hex(hash(new TextEncoder().encode(canonical)).subarray(0, 16));
}

export function normalizeKey(type: string, key: string): string {
  const bytes = new TextEncoder().encode(key).length;
  if (bytes === 0 || bytes > MAX_KEY_BYTES) throw new KeyError("invalid_key");
  switch (type) {
    case "account":
      return account(key);
    case "asset": {
      if (key === "native") return key;
      const i = key.indexOf(":");
      if (i < 0 || !ASSET_CODE.test(key.slice(0, i))) throw new KeyError("invalid_key");
      return `${key.slice(0, i)}:${account(key.slice(i + 1))}`;
    }
    case "contract":
      if (!CONTRACT.test(key)) throw new KeyError("invalid_key");
      return key;
    case "wasm_hash": {
      const k = key.toLowerCase();
      if (!WASM_HASH.test(k)) throw new KeyError("invalid_key");
      return k;
    }
    case "domain":
      return domain(key);
    default:
      throw new KeyError("unknown_type");
  }
}

function account(key: string): string {
  if (key.startsWith("M")) throw new KeyError("muxed_not_normalized");
  if (!ACCOUNT.test(key)) throw new KeyError("invalid_key");
  return key;
}

function domain(key: string): string {
  for (let i = 0; i < key.length; i++) {
    if (key.charCodeAt(i) >= 0x80) throw new KeyError("non_ascii");
  }
  let d = key.toLowerCase();
  if (d.endsWith(".")) d = d.slice(0, -1);
  if (d.length > 253) throw new KeyError("invalid_key");
  const labels = d.split(".");
  if (labels.length < 2 || !labels.every((l) => LABEL.test(l))) throw new KeyError("invalid_key");
  return d;
}

function hex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}
