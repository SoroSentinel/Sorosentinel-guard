import { decodeForAnalysis } from "./decode/envelope.ts";
import type { Network, UnanalyzableReason } from "./decode/types.ts";
import { deriveEffects } from "./effects/derive.ts";
import type { AccountEffect, BalanceEffect } from "./effects/types.ts";
import { networkUnknown } from "./rules/network-unknown.ts";
import { orderFindings, type Finding, type Rule } from "./rules/types.ts";

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
}

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
  /** Present when status is `unanalyzable`. */
  unanalyzableReason?: UnanalyzableReason;
}

const RULES: readonly Rule[] = [networkUnknown];

/**
 * Analyzes a base64 transaction envelope before signing. Never throws and
 * never reports a clean result for anything it did not fully check.
 */
export function analyze(envelopeBase64: string, ctx: AnalyzeContext): AnalysisResult {
  const decoded = decodeForAnalysis(envelopeBase64, ctx.networkPassphrase);
  if (!decoded.ok) {
    return {
      status: "unanalyzable",
      txHash: null,
      network: "unknown",
      operationCount: 0,
      effects: [],
      accountEffects: [],
      findings: [],
      notChecked: ["NC-DECODE"],
      unanalyzableReason: decoded.reason,
    };
  }

  const { input } = decoded;
  const effects = deriveEffects(input);
  const findings = orderFindings(RULES.flatMap((rule) => rule(input, effects)));

  const notChecked = new Set<NotChecked>(["NC-EXECUTION-TIME", "NC-COUNTERPARTY-SIGNALS"]);
  if (effects.uncovered.length > 0) notChecked.add("NC-OPERATION-EFFECTS");
  if (input.tx.operations.some((op) => op.type === "invokeHostFunction")) notChecked.add("NC-SIMULATION");
  if (input.tx.network === "unknown") notChecked.add("NC-NETWORK-COVERAGE");

  // Only a complete check may report `findings_present` or `no_issues_found`.
  // NC-EXECUTION-TIME is inherent to pre-signing analysis; any other gap (and
  // any code added later) makes the result `partial`. Counterparty lookup is not
  // implemented yet, so today every decodable transaction is `partial`.
  const complete = [...notChecked].every((c) => c === "NC-EXECUTION-TIME");
  const status: AnalysisStatus = !complete ? "partial" : findings.length > 0 ? "findings_present" : "no_issues_found";

  return {
    status,
    txHash: input.tx.txHash,
    network: input.tx.network,
    operationCount: input.tx.operations.length,
    effects: effects.effects,
    accountEffects: effects.accountEffects,
    findings,
    notChecked: [...notChecked].sort(),
  };
}
