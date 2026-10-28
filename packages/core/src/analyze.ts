import { xdr } from "@stellar/stellar-sdk/base";

import { decodeForAnalysis, type AnalysisInput } from "./decode/envelope.ts";
import type { Network, UnanalyzableReason } from "./decode/types.ts";
import { contractEffects, type ContractEffects } from "./effects/contract.ts";
import { deriveEffects } from "./effects/derive.ts";
import type { AccountEffect, BalanceEffect } from "./effects/types.ts";
import { collectEntities, lookup, type CounterpartyHit } from "./intel/lookup.ts";
import { checkSnapshot, type SnapshotRejection } from "./intel/snapshot.ts";
import { accountControl } from "./rules/account-control.ts";
import { counterpartyFlagged } from "./rules/counterparty-flagged.ts";
import { networkUnknown } from "./rules/network-unknown.ts";
import { noExpiry } from "./rules/no-expiry.ts";
import { signerAdded } from "./rules/signer-added.ts";
import { orderFindings, type Finding, type Rule, type RuleContext } from "./rules/types.ts";
import { runSimulation, type RpcConfig, type SimulationOutcome } from "./simulate/simulate.ts";

export type AnalysisStatus = "findings_present" | "no_issues_found" | "partial" | "unanalyzable";

/** Codes for what was not checked; every result carries at least one. */
export type NotChecked =
  /** The envelope could not be decoded. */
  | "NC-DECODE"
  /** Behavior when the transaction lands can differ if contract code or state changes. */
  | "NC-EXECUTION-TIME"
  /** Counterparties were not looked up in the Intel snapshot. */
  | "NC-COUNTERPARTY-SIGNALS"
  /** Some operations have no derived effects yet, or carry invalid values. */
  | "NC-OPERATION-EFFECTS"
  /** Soroban invocations were not simulated. */
  | "NC-SIMULATION"
  /** The network has no Intel coverage. */
  | "NC-NETWORK-COVERAGE";

export interface AnalyzeContext {
  /** Passphrase of the network the transaction will be signed for. */
  networkPassphrase: string;
  /**
   * Reference time for time-relative checks (e.g. an expiry far in the future).
   * Supplied by the caller so results are reproducible; Guard never reads the clock.
   */
  asOf?: Date;
  /**
   * Intel's signed snapshot, already parsed from JSON, plus the public keys
   * pinned in the integrator's build. Used only when it verifies, matches the
   * network, and is fresh relative to `asOf`.
   */
  snapshot?: {
    data: unknown;
    pinnedKeys: Readonly<Record<string, Uint8Array>>;
    maxAgeSeconds?: number;
  };
  /**
   * RPC endpoint for simulating Soroban invocations, chosen by the integrator
   * (Guard has no default). Used only by `analyzeAsync`; it receives the
   * transaction envelope and nothing else.
   */
  rpc?: RpcConfig;
}

/**
 * Whether counterparties were checked against the snapshot. Any value other
 * than `verified` means they were not, and the result carries
 * NC-COUNTERPARTY-SIGNALS. `stale` is the "protection data stale" state.
 */
export type SnapshotStatus = "verified" | "not_provided" | "no_as_of" | "not_applicable" | SnapshotRejection;

export interface AnalysisResult {
  status: AnalysisStatus;
  /** Hash of exactly the bytes being signed; null only when decoding failed. */
  txHash: string | null;
  network: Network;
  operationCount: number;
  effects: BalanceEffect[];
  accountEffects: AccountEffect[];
  /** Most severe first; never truncated. */
  findings: Finding[];
  notChecked: NotChecked[];
  snapshotStatus: SnapshotStatus;
  /** Present when status is `unanalyzable`. */
  unanalyzableReason?: UnanalyzableReason;
  /** Present only on `analyzeAsync` results. */
  simulation?: SimulationOutcome;
}

const RULES: readonly Rule[] = [accountControl, counterpartyFlagged, networkUnknown, noExpiry, signerAdded];

/**
 * Analyzes a base64 transaction envelope before signing. Never throws and
 * never reports a clean result for anything it did not fully check.
 */
export function analyze(envelopeBase64: string, ctx: AnalyzeContext): AnalysisResult {
  const decoded = decodeForAnalysis(envelopeBase64, ctx.networkPassphrase);
  return decoded.ok ? evaluate(decoded.input, ctx, null) : undecodable(decoded.reason);
}

/**
 * Runs `analyze`, then simulates Soroban invocations against `ctx.rpc`.
 * Never throws. A successful simulation clears NC-SIMULATION and supplies the
 * invocation's balance effects; NC-OPERATION-EFFECTS clears only when those
 * are complete. Any failure keeps both, so the result stays `partial`.
 */
export async function analyzeAsync(envelopeBase64: string, ctx: AnalyzeContext): Promise<AnalysisResult> {
  const decoded = decodeForAnalysis(envelopeBase64, ctx.networkPassphrase);
  if (!decoded.ok) return { ...undecodable(decoded.reason), simulation: { status: "skipped", reason: "not_decoded" } };
  const { input } = decoded;
  const invocations = input.tx.operations.filter((op) => op.type === "invokeHostFunction").length;
  if (invocations === 0) return { ...evaluate(input, ctx, null), simulation: { status: "skipped", reason: "no_invoke_host_function" } };
  if (ctx.rpc === undefined) return { ...evaluate(input, ctx, null), simulation: { status: "skipped", reason: "no_rpc" } };

  // Re-encoded from the decoded envelope: the endpoint simulates exactly what was analyzed.
  const envelope = xdr.TransactionEnvelope.fromXdr(envelopeBase64, "base64").toXdr("base64");
  const { outcome, trace } = await runSimulation(envelope, ctx.rpc);
  if (outcome.status !== "ok" || trace === null) return { ...evaluate(input, ctx, null), simulation: outcome };

  // The network allows one invocation per transaction; anything else is not attributed.
  const contract = invocations === 1 ? contractEffects(trace, ctx.networkPassphrase) : undefined;
  return { ...evaluate(input, ctx, { contract }), simulation: outcome };
}

function undecodable(reason: UnanalyzableReason): AnalysisResult {
  return {
    status: "unanalyzable",
    txHash: null,
    network: "unknown",
    operationCount: 0,
    effects: [],
    accountEffects: [],
    findings: [],
    notChecked: ["NC-DECODE"],
    snapshotStatus: "not_applicable",
    unanalyzableReason: reason,
  };
}

/** `simulated` is null when Soroban invocations were not simulated successfully. */
function evaluate(input: AnalysisInput, ctx: AnalyzeContext, simulated: { contract: ContractEffects | undefined } | null): AnalysisResult {
  const effects = deriveEffects(input, simulated?.contract);
  const rc = ruleContext(ctx);

  // Counterparty lookup: only against a snapshot that verifies, matches the
  // network and is fresh. Everything else leaves counterparties unchecked.
  let snapshotStatus: SnapshotStatus = "not_provided";
  let counterpartiesChecked = false;
  const network = input.tx.network;
  if (ctx.snapshot !== undefined) {
    if (network === "unknown") {
      snapshotStatus = "not_applicable";
    } else if (ctx.asOf === undefined || !Number.isFinite(ctx.asOf.getTime())) {
      snapshotStatus = "no_as_of";
    } else {
      const check = checkSnapshot(ctx.snapshot.data, {
        pinnedKeys: ctx.snapshot.pinnedKeys,
        network,
        asOf: ctx.asOf,
        ...(ctx.snapshot.maxAgeSeconds === undefined ? {} : { maxAgeSeconds: ctx.snapshot.maxAgeSeconds }),
      });
      if (!check.ok) {
        snapshotStatus = check.reason;
      } else {
        snapshotStatus = "verified";
        const entities = collectEntities(input, effects);
        const { hits, unresolved } = lookup(entities, network, check.entries);
        rc.hits = hits;
        counterpartiesChecked = !entities.contractsUnchecked && unresolved === 0;
      }
    }
  }

  const findings = orderFindings(RULES.flatMap((rule) => rule(input, effects, rc)));

  const notChecked = new Set<NotChecked>(["NC-EXECUTION-TIME"]);
  if (!counterpartiesChecked) notChecked.add("NC-COUNTERPARTY-SIGNALS");
  if (effects.uncovered.length > 0) notChecked.add("NC-OPERATION-EFFECTS");
  if (simulated === null && input.tx.operations.some((op) => op.type === "invokeHostFunction")) notChecked.add("NC-SIMULATION");
  if (input.tx.network === "unknown") notChecked.add("NC-NETWORK-COVERAGE");

  return {
    status: statusOf([...notChecked], findings),
    txHash: input.tx.txHash,
    network: input.tx.network,
    operationCount: input.tx.operations.length,
    effects: effects.effects,
    accountEffects: effects.accountEffects,
    findings,
    notChecked: [...notChecked].sort(),
    snapshotStatus,
  };
}

// Only a complete check may report `findings_present` or `no_issues_found`.
// NC-EXECUTION-TIME is inherent to pre-signing analysis; any other gap (and
// any code added later) makes the result `partial`. Without a verified
// snapshot, counterparties are unchecked, so the result is `partial`.
function statusOf(notChecked: readonly NotChecked[], findings: readonly Finding[]): AnalysisStatus {
  const complete = notChecked.every((c) => c === "NC-EXECUTION-TIME");
  return !complete ? "partial" : findings.length > 0 ? "findings_present" : "no_issues_found";
}

function ruleContext(ctx: AnalyzeContext): RuleContext {
  const ms = ctx.asOf?.getTime();
  return ms === undefined || !Number.isFinite(ms) ? {} : { asOf: BigInt(Math.floor(ms / 1000)) };
}

export type { CounterpartyHit };
