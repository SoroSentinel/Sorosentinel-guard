import type { xdr } from "@stellar/stellar-sdk/base";

export type OperationType = xdr.OperationBodyVariantName;
export type CredentialType = xdr.SorobanCredentialsVariantName;

/** Networks with Intel coverage; anything else is `unknown` (never `no_signals`). */
export type Network = "public" | "testnet" | "unknown";

/** v1 derives effects for these operations; all others are decoded only. */
export type OperationSupport = "effects" | "decode_only";

export interface AccountRef {
  /** Underlying `G…` account (muxed input is normalized). */
  account: string;
  /** Muxed ID as a decimal string, when the input was an `M…` account. */
  muxedId?: string;
}

export interface AuthEntrySummary {
  credential: CredentialType;
  /** Ledger after which the signed entry stops being valid (address credentials only). */
  signatureExpirationLedger?: number;
}

export interface DecodedOperation {
  index: number;
  type: OperationType;
  support: OperationSupport;
  /** Account the operation acts on: its own source, or the transaction source. */
  source: AccountRef;
  /** True when the operation names its own source account. */
  hasOwnSource: boolean;
  /** Soroban authorization entries (invokeHostFunction only). */
  auth?: AuthEntrySummary[];
}

export type Memo =
  | { type: "none" }
  | { type: "text"; bytesHex: string }
  | { type: "id"; id: string }
  | { type: "hash"; hashHex: string }
  | { type: "return"; hashHex: string };

export interface TimeBounds {
  /** Unix seconds as decimal strings. `max` of "0" means no upper bound. */
  min: string;
  max: string;
}

export interface DecodedTransaction {
  envelope: "tx_v0" | "tx" | "fee_bump";
  network: Network;
  /** Hex hash of exactly the payload being signed (outer hash for fee bumps). */
  txHash: string;
  /** Present for fee bumps: hash of the inner transaction. */
  innerTxHash?: string;
  /** Present for fee bumps: account paying the outer fee. */
  feeSource?: AccountRef;
  /** Fee bump outer fee, in stroops (decimal string). */
  feeBumpFee?: string;
  source: AccountRef;
  /** Inner transaction fee, in stroops (decimal string). */
  fee: string;
  sequence: string;
  timeBounds: TimeBounds | null;
  memo: Memo;
  operations: DecodedOperation[];
}

export type UnanalyzableReason =
  | "input_too_large"
  | "invalid_network_passphrase"
  | "decode_failed";

export type DecodeResult =
  | { ok: true; tx: DecodedTransaction }
  | { ok: false; status: "unanalyzable"; reason: UnanalyzableReason };
