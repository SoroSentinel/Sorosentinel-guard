import { xdr } from "@stellar/stellar-sdk/base";
import type { Api } from "@stellar/stellar-sdk/rpc";

import { authSummary } from "../decode/operations.ts";
import type { AuthEntrySummary } from "../decode/types.ts";
import { DEFAULT_RPC_TIMEOUT_MS, MAX_RPC_TIMEOUT_MS, callRpc, isLedger, isRecord, type RpcConfig } from "../rpc/transport.ts";

// Field names are checked against the SDK's response type so a rename fails at compile time.
type RawSimulation = Api.RawSimulateTransactionResponse;

export const DEFAULT_SIMULATION_TIMEOUT_MS = DEFAULT_RPC_TIMEOUT_MS;
export const MAX_SIMULATION_TIMEOUT_MS = MAX_RPC_TIMEOUT_MS;
// TODO(verify): largest legitimate simulateTransaction response.
export const MAX_SIMULATION_RESPONSE_BYTES = 1024 * 1024;
// TODO(verify): largest legitimate event and state-change counts.
const MAX_EVENTS = 2_000;
const MAX_STATE_CHANGES = 2_000;

const INT64_MAX = 2n ** 63n - 1n;

export type { RpcConfig };

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

/** One ledger entry the simulated invocation creates, updates or removes. */
export interface StateChange {
  key: xdr.LedgerKey;
  before: xdr.LedgerEntry | null;
  after: xdr.LedgerEntry | null;
}

/**
 * Decoded events and state changes of a successful simulation, used to derive
 * contract effects. Internal: never part of a result. `stateChanges` is null
 * when the endpoint did not report them. `ok: false` means they were present
 * but could not be decoded.
 */
export type SimulationTrace =
  | { ok: true; events: xdr.DiagnosticEvent[]; stateChanges: StateChange[] | null }
  | { ok: false };

interface Simulated {
  outcome: SimulationOutcome;
  /** Present only with an `ok` outcome. */
  trace: SimulationTrace | null;
}

/**
 * Calls `simulateTransaction` on the configured endpoint. Sends only the
 * envelope; never throws. Anything other than a well-formed success is a
 * failure outcome, never a guess.
 */
export async function simulateTransaction(envelopeBase64: string, rpc: RpcConfig): Promise<SimulationOutcome> {
  return (await runSimulation(envelopeBase64, rpc)).outcome;
}

/** Like `simulateTransaction`, but also returns the decoded trace of a successful simulation. */
export async function runSimulation(envelopeBase64: string, rpc: RpcConfig): Promise<Simulated> {
  const reply = await callRpc(rpc, "simulateTransaction", { transaction: envelopeBase64 }, MAX_SIMULATION_RESPONSE_BYTES);
  return reply.ok ? parseResponse(reply.result) : { outcome: reply.failure, trace: null };
}

function parseResponse(result: Record<string, unknown>): Simulated {
  const outcome = parseOutcome(result);
  return outcome.status === "ok" ? { outcome, trace: parseTrace(result) } : { outcome, trace: null };
}

function parseOutcome(result: Record<string, unknown>): SimulationOutcome {
  const malformed: Failure = { status: "malformed", reason: "invalid_shape" };
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

// Absent events mean none were emitted. Absent state changes are not taken
// to mean "no changes": older endpoints omit them, so they stay unknown.
function parseTrace(result: Record<string, unknown>): SimulationTrace {
  const rawEvents = field(result, "events") ?? [];
  const rawChanges = field(result, "stateChanges");
  if (!Array.isArray(rawEvents) || rawEvents.length > MAX_EVENTS) return { ok: false };
  if (rawChanges !== undefined && (!Array.isArray(rawChanges) || rawChanges.length > MAX_STATE_CHANGES)) return { ok: false };
  try {
    const events = rawEvents.map((e: unknown) => {
      if (typeof e !== "string") throw new TypeError("event");
      return xdr.DiagnosticEvent.fromXdr(e, "base64");
    });
    const stateChanges = rawChanges === undefined ? null : rawChanges.map(stateChange);
    return { ok: true, events, stateChanges };
  } catch {
    return { ok: false };
  }
}

/** Throws on anything that is not a well-formed change. */
function stateChange(raw: unknown): StateChange {
  if (!isRecord(raw) || typeof raw["key"] !== "string") throw new TypeError("state change");
  const entry = (v: unknown): xdr.LedgerEntry | null => {
    if (v === null || v === undefined) return null;
    if (typeof v !== "string") throw new TypeError("state change entry");
    return xdr.LedgerEntry.fromXdr(v, "base64");
  };
  const change = { key: xdr.LedgerKey.fromXdr(raw["key"], "base64"), before: entry(raw["before"]), after: entry(raw["after"]) };
  if (change.before === null && change.after === null) throw new TypeError("empty state change");
  return change;
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

function field<K extends keyof RawSimulation>(result: Record<string, unknown>, key: K): unknown {
  return Object.hasOwn(result, key) ? result[key] : undefined;
}
