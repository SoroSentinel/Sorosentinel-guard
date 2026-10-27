/** Where an effect's numbers come from. Contract-reported values are never presented as ledger truth. */
export type Assurance = "ledger" | "contract_reported";

/**
 * Net change to one account's balance of one asset, in stroops (integers only).
 * `deltaMin` is the worst case and is shown first ("up to X").
 */
export interface BalanceEffect {
  account: string;
  /** "native" or "CODE:ISSUER" in canonical form. */
  asset: string;
  deltaMin: bigint;
  /** null when there is no upper bound (e.g. the receiver of a strict-send path payment). */
  deltaMax: bigint | null;
  assurance: Assurance;
}

export type UncoveredReason =
  /** Effects for this operation type are not derived yet (v1 scope grows op by op). */
  | "not_derived_yet"
  /** The operation carries values the network would reject (non-positive amount, malformed asset code). */
  | "invalid_operation";

export interface UncoveredOperation {
  index: number;
  reason: UncoveredReason;
}

export interface EffectsResult {
  /** Aggregated per (account, asset), worst case first. */
  effects: BalanceEffect[];
  /** Any entry here means the effects are incomplete: the analysis is at best `partial`. */
  uncovered: UncoveredOperation[];
}
