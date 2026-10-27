import { xdr } from "@stellar/stellar-sdk/base";
import type { Api } from "@stellar/stellar-sdk/rpc";

import { authSummary } from "../decode/operations.ts";
import type { AuthEntrySummary } from "../decode/types.ts";

// The SDK's rpc.Server cannot take an injected fetch or cap the response
// size, so Guard calls the JSON-RPC method directly. Field names are checked
// against the SDK's response type so a rename fails at compile time.
type RawSimulation = Api.RawSimulateTransactionResponse;

export const DEFAULT_SIMULATION_TIMEOUT_MS = 10_000;
export const MAX_SIMULATION_TIMEOUT_MS = 60_000;
// TODO(verify): largest legitimate simulateTransaction response.
export const MAX_SIMULATION_RESPONSE_BYTES = 1024 * 1024;

const REQUEST_ID = 1;
const INT64_MAX = 2n ** 63n - 1n;

/** RPC endpoint chosen by the integrator. Guard has no default endpoint. */
export interface RpcConfig {
  url: string;
  /** Deadline for the whole exchange (request and response body). */
  timeoutMs?: number;
  /** Defaults to the global fetch. */
  fetch?: typeof fetch;
}

/** Structured simulation data; carries no RPC-provided prose. */
export type SimulationOutcome =
  | {
      status: "ok";
      latestLedger: number;
      /** Stroops, decimal string. */
      minResourceFee: string;
      /** Resource fee in the simulated transaction data, stroops, decimal string. */
      resourceFee: string;
      footprint: { readOnly: number; readWrite: number };
      /** Authorization entries the invocation requires. */
      authRequired: AuthEntrySummary[];
      /** Present when archived entries must be restored first. */
      restore: { minResourceFee: string } | null;
    }
  | { status: "skipped"; reason: "not_decoded" | "no_invoke_host_function" | "no_rpc" }
  | { status: "timeout"; timeoutMs: number }
  | {
      status: "error";
      reason: "invalid_config" | "network" | "http" | "rpc" | "simulation";
      httpStatus?: number;
      rpcCode?: number;
    }
  | { status: "malformed"; reason: "too_large" | "invalid_json" | "invalid_shape" };

type Failure = Exclude<SimulationOutcome, { status: "ok" | "skipped" | "timeout" }>;

/**
 * Calls `simulateTransaction` on the configured endpoint. Sends only the
 * envelope; never throws. Anything other than a well-formed success is a
 * failure outcome, never a guess.
 */
export async function simulateTransaction(envelopeBase64: string, rpc: RpcConfig): Promise<SimulationOutcome> {
  const timeoutMs = rpc.timeoutMs ?? DEFAULT_SIMULATION_TIMEOUT_MS;
  const fetchImpl = rpc.fetch ?? globalThis.fetch;
  if (!validEndpoint(rpc.url) || !validTimeout(timeoutMs) || typeof fetchImpl !== "function") {
    return { status: "error", reason: "invalid_config" };
  }

  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  // Raced rather than relying on the signal alone: an injected fetch may ignore it.
  const deadline = new Promise<SimulationOutcome>((resolve) => {
    timer = setTimeout(() => {
      controller.abort();
      resolve({ status: "timeout", timeoutMs });
    }, timeoutMs);
  });
  try {
    return await Promise.race([exchange(fetchImpl, rpc.url, envelopeBase64, controller.signal), deadline]);
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
}

async function exchange(fetchImpl: typeof fetch, url: string, envelopeBase64: string, signal: AbortSignal): Promise<SimulationOutcome> {
  let response: Response;
  try {
    response = await fetchImpl(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: REQUEST_ID, method: "simulateTransaction", params: { transaction: envelopeBase64 } }),
      signal,
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
      cache: "no-store",
    });
  } catch {
    return { status: "error", reason: "network" };
  }
  if (!response.ok) {
    return { status: "error", reason: "http", httpStatus: response.status };
  }
  try {
    const body = await readCapped(response, MAX_SIMULATION_RESPONSE_BYTES);
    if (!body.ok) return { status: "malformed", reason: body.reason };
    let json: unknown;
    try {
      json = JSON.parse(body.text);
    } catch {
      return { status: "malformed", reason: "invalid_json" };
    }
    return parseResponse(json);
  } catch {
    // Body stream failed (including abort after the deadline).
    return { status: "error", reason: "network" };
  }
}

type Body = { ok: true; text: string } | { ok: false; reason: "too_large" | "invalid_json" };

/** Reads the body as UTF-8, stopping as soon as it exceeds `maxBytes`. */
async function readCapped(response: Response, maxBytes: number): Promise<Body> {
  const declared = response.headers.get("content-length");
  if (declared !== null && /^\d+$/.test(declared) && Number(declared) > maxBytes) {
    await response.body?.cancel().catch(() => undefined);
    return { ok: false, reason: "too_large" };
  }
  const decoder = new TextDecoder("utf-8", { fatal: true });
  if (response.body === null) {
    const text = await response.text();
    return new TextEncoder().encode(text).byteLength > maxBytes ? { ok: false, reason: "too_large" } : { ok: true, text };
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      return { ok: false, reason: "too_large" };
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    bytes.set(c, offset);
    offset += c.byteLength;
  }
  try {
    return { ok: true, text: decoder.decode(bytes) };
  } catch {
    return { ok: false, reason: "invalid_json" };
  }
}

function parseResponse(json: unknown): SimulationOutcome {
  const malformed: Failure = { status: "malformed", reason: "invalid_shape" };
  if (!isRecord(json) || json["jsonrpc"] !== "2.0" || json["id"] !== REQUEST_ID) return malformed;
  if (Object.hasOwn(json, "error")) {
    const err = json["error"];
    return isRecord(err) && Number.isSafeInteger(err["code"])
      ? { status: "error", reason: "rpc", rpcCode: err["code"] as number }
      : malformed;
  }
  const result = json["result"];
  if (!isRecord(result)) return malformed;
  if (field(result, "error") !== undefined) {
    // Simulation ran and failed; its message is untrusted text and is not kept.
    return typeof field(result, "error") === "string" ? { status: "error", reason: "simulation" } : malformed;
  }

  const latestLedger = field(result, "latestLedger");
  const minResourceFee = stroops(field(result, "minResourceFee"));
  const data = sorobanData(field(result, "transactionData"));
  const results = field(result, "results");
  // One invokeHostFunction per transaction, so exactly one result.
  if (!isLedger(latestLedger) || minResourceFee === null || data === null || !Array.isArray(results) || results.length !== 1) {
    return malformed;
  }
  const authRequired = authEntries(results[0]);
  if (authRequired === null) return malformed;

  let restore: { minResourceFee: string } | null = null;
  const preamble = field(result, "restorePreamble");
  if (preamble !== undefined) {
    if (!isRecord(preamble)) return malformed;
    const fee = stroops(preamble["minResourceFee"]);
    if (fee === null || sorobanData(preamble["transactionData"]) === null) return malformed;
    restore = { minResourceFee: fee };
  }

  const footprint = data.resources.footprint;
  return {
    status: "ok",
    latestLedger,
    minResourceFee,
    resourceFee: data.resourceFee.toString(),
    footprint: { readOnly: footprint.readOnly.length, readWrite: footprint.readWrite.length },
    authRequired,
    restore,
  };
}

function authEntries(hostResult: unknown): AuthEntrySummary[] | null {
  if (!isRecord(hostResult) || typeof hostResult["xdr"] !== "string") return null;
  const auth = hostResult["auth"];
  if (auth === undefined) return [];
  if (!Array.isArray(auth)) return null;
  const out: AuthEntrySummary[] = [];
  for (const entry of auth) {
    if (typeof entry !== "string") return null;
    try {
      out.push(authSummary(xdr.SorobanAuthorizationEntry.fromXdr(entry, "base64")));
    } catch {
      return null;
    }
  }
  return out;
}

function sorobanData(value: unknown): xdr.SorobanTransactionData | null {
  if (typeof value !== "string" || value.length === 0) return null;
  try {
    return xdr.SorobanTransactionData.fromXdr(value, "base64");
  } catch {
    return null;
  }
}

/** Non-negative int64 decimal string; amounts stay integers. */
function stroops(value: unknown): string | null {
  if (typeof value !== "string" || !/^(0|[1-9]\d{0,18})$/.test(value)) return null;
  return BigInt(value) <= INT64_MAX ? value : null;
}

function isLedger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff;
}

function field<K extends keyof RawSimulation>(result: Record<string, unknown>, key: K): unknown {
  return Object.hasOwn(result, key) ? result[key] : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validEndpoint(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol === "https:" || u.protocol === "http:";
  } catch {
    return false;
  }
}

function validTimeout(ms: number): boolean {
  return Number.isFinite(ms) && ms > 0 && ms <= MAX_SIMULATION_TIMEOUT_MS;
}
