import { KeyError, normalizeKey } from "../canonical/key.ts";
import type { EntityType } from "../canonical/key.ts";
import { assertNever } from "../assert-never.ts";

/**
 * Typed slot values, ported from sorosentinel-intel internal/wording/slots.go.
 * There is no free-text slot type, by design.
 */

export const SLOT_TYPES = [
  "timestamp",
  "account",
  "asset_key",
  "contract",
  "wasm_hash",
  "domain",
  "ledger",
  "signer_key",
  "weight",
] as const;
export type SlotType = (typeof SLOT_TYPES)[number];

export function isSlotType(t: string): t is SlotType {
  return (SLOT_TYPES as readonly string[]).includes(t);
}

export type WordingErrorCode =
  | "unknown_template"
  | "not_approved"
  | "invalid_template"
  | "level_not_allowed"
  | "missing_slot"
  | "unexpected_slot"
  | "slot_type_mismatch"
  | "invalid_slot_value"
  | "blocked_term";

/** Rendering failed closed: show structured facts, never prose. `detail` is for logs, not users. */
export interface WordingError {
  readonly code: WordingErrorCode;
  readonly detail: string;
}

export type Result<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: WordingError };

const fail = (code: WordingErrorCode, detail: string): { ok: false; error: WordingError } => ({
  ok: false,
  error: { code, detail },
});

// Only this module can construct a SlotValue, so every value was validated here.
const MINT = Symbol("SlotValue");

/** A validated, typed slot value. Build with slotValue or timestampValue. */
export class SlotValue {
  readonly #type: SlotType;
  readonly #display: string;
  readonly #fact: string;

  constructor(mint: symbol, type: SlotType, display: string, fact: string) {
    if (mint !== MINT) throw new TypeError("use slotValue() or timestampValue()");
    this.#type = type;
    this.#display = display;
    this.#fact = fact;
  }

  get type(): SlotType {
    return this.#type;
  }
  /** Form used in rendered text. */
  get display(): string {
    return this.#display;
  }
  /** Form used in structured facts. */
  get fact(): string {
    return this.#fact;
  }
}

// Go's zero time.Time: 0001-01-01T00:00:00Z.
const GO_ZERO_TIME_MS = -62135596800000;

export function isZeroTime(t: Date): boolean {
  const ms = t.getTime();
  return Number.isNaN(ms) || ms === GO_ZERO_TIME_MS;
}

/** Builds a timestamp slot value. An invalid or zero date is rejected. */
export function timestampValue(t: Date): Result<SlotValue> {
  if (isZeroTime(t)) return fail("invalid_slot_value", "zero timestamp");
  return { ok: true, value: new SlotValue(MINT, "timestamp", displayTime(t), rfc3339(t)) };
}

const SIGNER_KEY = /^(?:[GTX][A-Z2-7]{55}|P[A-Z2-7]{60,200})$/;
const DIGITS = /^[0-9]+$/;

/**
 * Validates raw as type. Untrusted strings with control or bidi characters are
 * rejected, and every accepted value matches a strict ASCII shape.
 */
export function slotValue(type: SlotType, raw: string): Result<SlotValue> {
  if (!isWellFormed(raw) || hasUnsafeChar(raw)) return fail("invalid_slot_value", "control or bidi character");
  switch (type) {
    case "timestamp": {
      const t = parseRfc3339(raw);
      if (t === null) return fail("invalid_slot_value", "timestamp must be RFC 3339");
      return timestampValue(t);
    }
    case "signer_key":
      // Shape only: G (ed25519), T (pre-auth tx), X (hash-x), P (signed payload).
      // TODO(verify): strkey checksums need the Stellar SDK (same gap as Intel).
      if (!SIGNER_KEY.test(raw)) return fail("invalid_slot_value", "not a signer strkey");
      return { ok: true, value: new SlotValue(MINT, type, raw, raw) };
    case "weight": {
      const n = parseUint(raw, 255n);
      if (n === null) return fail("invalid_slot_value", "weight must be an integer from 0 to 255");
      return { ok: true, value: new SlotValue(MINT, type, n, n) };
    }
    case "ledger": {
      const n = parseUint(raw, 0xffffffffn);
      if (n === null || n === "0") return fail("invalid_slot_value", "ledger must be a positive 32-bit integer");
      return { ok: true, value: new SlotValue(MINT, type, n, n) };
    }
    case "account":
    case "asset_key":
    case "contract":
    case "wasm_hash":
    case "domain": {
      let norm: string;
      try {
        norm = normalizeKey(entityType(type), raw);
      } catch (e) {
        if (e instanceof KeyError) return fail("invalid_slot_value", e.message);
        throw e;
      }
      return { ok: true, value: new SlotValue(MINT, type, norm, norm) };
    }
    default:
      return assertNever(type);
  }
}

function entityType(t: "account" | "asset_key" | "contract" | "wasm_hash" | "domain"): EntityType {
  switch (t) {
    case "account":
      return "account";
    case "asset_key":
      return "asset";
    case "contract":
      return "contract";
    case "wasm_hash":
      return "wasm_hash";
    case "domain":
      return "domain";
    default:
      return assertNever(t);
  }
}

/** strconv.ParseUint(raw, 10, bits) bounded by max; returns the canonical decimal or null. */
function parseUint(raw: string, max: bigint): string | null {
  if (!DIGITS.test(raw)) return null;
  const n = BigInt(raw);
  return n > max ? null : n.toString();
}

/** Same set as Go's hasUnsafeRune: C0, DEL, C1, and bidi controls. */
export function hasUnsafeChar(s: string): boolean {
  for (const ch of s) {
    const r = ch.codePointAt(0) ?? 0;
    if (r < 0x20 || r === 0x7f || (r >= 0x80 && r < 0xa0)) return true;
    if (r === 0x061c || r === 0x200e || r === 0x200f || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)) {
      return true;
    }
  }
  return false;
}

/** utf8.ValidString for a JS string: no lone surrogates. */
function isWellFormed(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return false;
    }
  }
  return true;
}

const pad = (n: number, w: number): string => String(n).padStart(w, "0");

function year(t: Date): string {
  const y = t.getUTCFullYear();
  return y < 0 ? `-${pad(-y, 4)}` : pad(y, 4);
}

/** Go layout "2006-01-02 15:04 UTC". */
function displayTime(t: Date): string {
  return `${year(t)}-${pad(t.getUTCMonth() + 1, 2)}-${pad(t.getUTCDate(), 2)} ${pad(t.getUTCHours(), 2)}:${pad(t.getUTCMinutes(), 2)} UTC`;
}

/** Go's t.UTC().Format(time.RFC3339): whole seconds, "Z". */
export function rfc3339(t: Date): string {
  return `${year(t)}-${pad(t.getUTCMonth() + 1, 2)}-${pad(t.getUTCDate(), 2)}T${pad(t.getUTCHours(), 2)}:${pad(t.getUTCMinutes(), 2)}:${pad(t.getUTCSeconds(), 2)}Z`;
}

const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{1,2}):(\d{2}):(\d{2})(?:[.,](\d+))?(?:Z|([+-])(\d{2}):(\d{2}))$/;

/**
 * time.Parse(time.RFC3339, s), including the leniency of Go's fallback parser
 * (checked against Go): four-digit year, real calendar day, a one- or
 * two-digit hour < 24, second < 60, optional fraction ("." or ","), and "Z"
 * or ±hh:mm with hh <= 24 and mm <= 60. Sub-millisecond digits are dropped
 * (output never shows them).
 */
export function parseRfc3339(s: string): Date | null {
  const m = RFC3339.exec(s);
  if (m === null) return null;
  const [y, mo, d, h, mi, sec] = [m[1], m[2], m[3], m[4], m[5], m[6]].map(Number) as [number, number, number, number, number, number];
  if (mo < 1 || mo > 12 || d < 1 || d > daysIn(y, mo) || h > 23 || mi > 59 || sec > 59) return null;
  let offsetMin = 0;
  if (m[8] !== undefined) {
    const oh = Number(m[9]);
    const om = Number(m[10]);
    if (oh > 24 || om > 60) return null;
    offsetMin = (m[8] === "-" ? -1 : 1) * (oh * 60 + om);
  }
  const ms = Number((m[7] ?? "").slice(0, 3).padEnd(3, "0"));
  const t = new Date(0);
  t.setUTCFullYear(y, mo - 1, d);
  t.setUTCHours(h, mi, sec, ms);
  return new Date(t.getTime() - offsetMin * 60_000);
}

function daysIn(y: number, mo: number): number {
  if (mo === 2) return (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0 ? 29 : 28;
  return [4, 6, 9, 11].includes(mo) ? 30 : 31;
}
