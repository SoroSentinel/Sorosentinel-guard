/** Where an effect's numbers come from. Contract-reported values are never presented as ledger truth. */
export type Assurance = "ledger" | "contract_reported";

/**
 * Net change to one account's balance of one asset, in stroops (integers only).
 * `deltaMin` is the worst case and is shown first ("up to X").
 */
export interface BalanceEffect {
  /** `G…` account or `C…` contract address. */
  account: string;
  /**
   * "native" or "CODE:ISSUER" in canonical form; for a token that is not a
   * Stellar Asset Contract, the token contract's address (`C…`).
   */
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
  | "invalid_operation"
  /** Simulation succeeded, but its events or state changes could not be read. */
  | "contract_events_malformed"
  /**
   * Simulation was read, but the invocation may change more than the balances
   * derived (custom-token or other contract state, unrecognized events).
   */
  | "contract_effects_incomplete";

export interface UncoveredOperation {
  index: number;
  reason: UncoveredReason;
}

/** Signer key kinds. hash_x and pre_auth_tx have no visible owner key. */
export type SignerType = "ed25519" | "pre_auth_tx" | "hash_x" | "ed25519_signed_payload";

/** Changes to an account other than balances. `operationIndex` points at the operation that causes it. */
export type AccountEffect =
  /** Trustline created or limit changed (`limit` > 0), or removed (`limit` = 0). */
  | { kind: "trustline"; operationIndex: number; account: string; asset: string; limit: bigint }
  /** Signer added or re-weighted (`weight` > 0), or removed (`weight` = 0). `signer` is the strkey. */
  | { kind: "signer"; operationIndex: number; account: string; signer: string; signerType: SignerType; weight: number }
  /** Only the fields the operation sets are non-null. */
  | {
      kind: "thresholds";
      operationIndex: number;
      account: string;
      masterWeight: number | null;
      low: number | null;
      medium: number | null;
      high: number | null;
    }
  | { kind: "flags"; operationIndex: number; account: string; set: number | null; clear: number | null }
  /** Raw bytes only: the home domain is untrusted and is sanitized at display time. */
  | { kind: "home_domain"; operationIndex: number; account: string; bytesHex: string }
  | { kind: "inflation_destination"; operationIndex: number; account: string; destination: string }
  /** The account is removed and its entire native balance moves to `destination` (amount unknown without ledger data). */
  | { kind: "merge"; operationIndex: number; account: string; destination: string };

export interface EffectsResult {
  /** Aggregated per (account, asset), worst case first. */
  effects: BalanceEffect[];
  /** Non-balance changes, in operation order. */
  accountEffects: AccountEffect[];
  /** Any entry here means the effects are incomplete: the analysis is at best `partial`. */
  uncovered: UncoveredOperation[];
}
