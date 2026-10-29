import { KeyError, normalizeKey } from "../canonical/key.ts";
import { isRecord, postJson, type ExchangeFailure, type RpcConfig } from "../rpc/transport.ts";
import { MAX_FUTURE_SKEW_SECONDS } from "./snapshot.ts";
import { eachEntity, flaggedHits, type Entities, type HitType } from "./lookup.ts";
import type { CounterpartyHit } from "./lookup.ts";

/**
 * Intel's public read API as the fallback for the signed snapshot: one
 * `POST /v1/entities:batchGet` (sorosentinel-intel `schemas/openapi/intel.v1.yaml`,
 * request and response shapes pinned in `intel-schemas/`). Opt-in: Guard has no
 * Intel endpoint and sends nothing unless the integrator configures one.
 *
 * The response is hostile input. Unlike the snapshot it carries no signature,
 * so the endpoint must be https and every field Guard acts on is checked
 * against the pinned schema; anything unexpected means "not checked", never
 * "no signals". Only `signal_level` is acted on: `facts` and `statements` are
 * validated as data and then dropped, because public prose comes only from the
 * renderer (AGENTS.md §5) and `Finding.statement` is pinned to null.
 */

/** Intel's own batch limit (`store.MaxLookupKeys`, the OpenAPI `maxItems`). */
export const MAX_INTEL_BATCH = 100;
/** Response cap, as for an RPC reply: 1 MiB bounds 100 entities with a wide margin. */
export const MAX_INTEL_RESPONSE_BYTES = 1024 * 1024;

/** Exported so `test/contract` can check them against Intel's pinned schemas. */
export const BATCH_PATH = "/v1/entities:batchGet";
export const SIGNAL_LEVELS = ["consistent", "no_signals", "caution", "high_caution"] as const;
export const ENTITY_SIGNAL_FIELDS = ["entity", "signal_level", "as_of", "facts", "statements"];
export const ENTITY_SIGNAL_OPTIONAL_FIELDS = ["ruleset_version", "disputed"];
export const ENTITY_FIELDS = ["network", "type", "key"];

export type IntelSignalLevel = (typeof SIGNAL_LEVELS)[number];

/**
 * The public levels that mean "Intel has an active flag on this entity":
 * `caution` and `high_caution` are what a suspicious and a malicious verdict
 * map to, which is exactly what a snapshot entry says. `consistent` and
 * `no_signals` are not hits, and never reassurance.
 */
export const HIT_LEVELS: readonly IntelSignalLevel[] = ["caution", "high_caution"];

/**
 * Intel endpoint chosen by the integrator; Guard has no default. Only an
 * entity's key is sent, never the transaction, its XDR or its hash. `https` is
 * required because the response is unsigned: transport integrity is the only
 * guarantee that the answer came from Intel.
 */
export type IntelApiConfig = RpcConfig;

/** Why the fallback produced no answer. The caller keeps NC-COUNTERPARTY-SIGNALS. */
export type IntelFailure =
  | ExchangeFailure
  | { status: "too_many"; count: number }
  | { status: "unexpected_response" }
  | { status: "as_of"; reason: "invalid" | "from_future" };

export type IntelLookup = { ok: true; hits: CounterpartyHit[]; checked: boolean } | { ok: false; failure: IntelFailure };

/**
 * Asks Intel about every counterparty the transaction touches, in one request,
 * and returns the hits among them with the roles the transaction gives them.
 * Never throws; any failure means no counterparty was checked.
 *
 * `asOf` is the caller's reference time, never a clock read here. It bounds
 * only future-dating: a verdict's `as_of` is the date it was decided, which is
 * legitimately old while the verdict stays active, so the snapshot's max age
 * does not apply to it.
 */
export async function lookupEntitySignals(
  entities: Entities,
  network: "public" | "testnet",
  intel: IntelApiConfig,
  asOf: Date,
): Promise<IntelLookup> {
  const requested: { network: string; type: HitType; key: string }[] = [];
  let unresolved = 0;
  for (const e of eachEntity(entities)) {
    try {
      requested.push({ network, type: e.type, key: normalizeKey(e.type, e.key) });
    } catch (err) {
      // An entity whose key Intel cannot be asked about is a coverage gap, not a hit.
      if (!(err instanceof KeyError)) throw err;
      unresolved++;
    }
  }
  // As in the snapshot lookup, an unnamed contract (creation, Wasm upload) or an
  // uncanonicalizable key leaves counterparties not fully checked.
  const checked = unresolved === 0 && !entities.contractsUnchecked;
  if (requested.length === 0) return { ok: true, hits: [], checked };
  if (requested.length > MAX_INTEL_BATCH) return { ok: false, failure: { status: "too_many", count: requested.length } };
  if (!isHttpsEndpoint(intel.url)) return { ok: false, failure: { status: "error", reason: "invalid_config" } };

  const reply = await postJson({ ...intel, url: endpoint(intel.url) }, JSON.stringify({ entities: requested }), MAX_INTEL_RESPONSE_BYTES);
  if (!reply.ok) return { ok: false, failure: reply.failure };

  const flagged = parseSignals(reply.json, network, requested, asOf);
  if (flagged === null) return { ok: false, failure: { status: "unexpected_response" } };
  if (typeof flagged === "string") return { ok: false, failure: { status: "as_of", reason: flagged } };
  return { ok: true, hits: flaggedHits(entities, flagged), checked };
}

/** One result per requested entity, in request order, or why the response is unusable. */
function parseSignals(
  json: unknown,
  network: string,
  requested: readonly { type: HitType; key: string }[],
  asOf: Date,
): ReadonlySet<string> | "invalid" | "from_future" | null {
  if (!isRecord(json) || Object.keys(json).length !== 1 || !Array.isArray(json["results"])) return null;
  const results = json["results"] as unknown[];
  if (results.length !== requested.length) return null;

  const flagged = new Set<string>();
  for (const [i, raw] of results.entries()) {
    const wanted = requested[i];
    if (wanted === undefined || !isRecord(raw)) return null;
    const keys = Object.keys(raw);
    // Every required field, and nothing the pinned schema does not define.
    if (
      keys.length < ENTITY_SIGNAL_FIELDS.length ||
      !keys.every((k) => ENTITY_SIGNAL_FIELDS.includes(k) || ENTITY_SIGNAL_OPTIONAL_FIELDS.includes(k)) ||
      !ENTITY_SIGNAL_FIELDS.every((f) => keys.includes(f))
    ) {
      return null;
    }

    if (!matchesEntity(raw["entity"], network, wanted)) return null;
    const level = raw["signal_level"];
    if (typeof level !== "string" || !SIGNAL_LEVELS.includes(level as IntelSignalLevel)) return null;
    const notFresh = ageCheck(raw["as_of"], asOf);
    if (notFresh !== null) return notFresh;
    // Validated as data, then dropped: the level is all Guard acts on.
    if (!isRecord(raw["facts"]) || !Array.isArray(raw["statements"])) return null;
    if (raw["ruleset_version"] !== undefined && typeof raw["ruleset_version"] !== "string") return null;
    if (raw["disputed"] !== undefined && typeof raw["disputed"] !== "boolean") return null;
    if (HIT_LEVELS.includes(level as IntelSignalLevel)) flagged.add(`${wanted.type}|${wanted.key}`);
  }
  return flagged;
}

/** The response must echo exactly the entity that was asked about. */
function matchesEntity(raw: unknown, network: string, wanted: { type: HitType; key: string }): boolean {
  if (!isRecord(raw)) return false;
  const keys = Object.keys(raw);
  return keys.length === ENTITY_FIELDS.length && keys.every((k) => ENTITY_FIELDS.includes(k))
    && raw["network"] === network && raw["type"] === wanted.type && raw["key"] === wanted.key;
}

/** A response dated after the reference time is a broken clock or a planted future. */
function ageCheck(raw: unknown, asOf: Date): "invalid" | "from_future" | null {
  const reference = asOf.getTime();
  if (typeof raw !== "string" || !TIMESTAMP.test(raw) || !Number.isFinite(reference)) return "invalid";
  const ms = Date.parse(raw);
  if (!Number.isFinite(ms)) return "invalid";
  return ms - reference > MAX_FUTURE_SKEW_SECONDS * 1000 ? "from_future" : null;
}

const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

function isHttpsEndpoint(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol === "https:" && u.hostname.length > 0;
  } catch {
    return false;
  }
}

/** The batch endpoint under the integrator's base URL. */
const endpoint = (base: string): string => `${base.replace(/\/$/, "")}${BATCH_PATH}`;
