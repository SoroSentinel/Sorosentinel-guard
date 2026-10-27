import { StrKey, TransactionBuilder, FeeBumpTransaction, xdr } from "@stellar/stellar-sdk/base";

import { assertNever } from "../assert-never.ts";
import { accountRef } from "./account.ts";
import { networkOf } from "./network.ts";
import { decodeOperation } from "./operations.ts";
import type { AccountRef, DecodeResult, DecodedTransaction, Memo, TimeBounds, UnanalyzableReason } from "./types.ts";

// TODO(verify): largest valid envelope (Soroban transactions can be large).
export const MAX_ENVELOPE_BASE64_LENGTH = 256 * 1024;
const MAX_PASSPHRASE_LENGTH = 256;

/** Decoded transaction plus the raw operations that effect derivation reads. */
export interface AnalysisInput {
  tx: DecodedTransaction;
  /** Same order as `tx.operations`; from the transaction that is signed (inner tx for fee bumps). */
  operations: readonly xdr.Operation[];
}

export type AnalysisDecodeResult =
  | { ok: true; input: AnalysisInput }
  | { ok: false; status: "unanalyzable"; reason: UnanalyzableReason };

/**
 * Decodes a base64 transaction envelope. Never throws: any failure is an
 * `unanalyzable` result, never a partially decoded transaction.
 */
export function decodeEnvelope(envelopeBase64: string, networkPassphrase: string): DecodeResult {
  const res = decodeForAnalysis(envelopeBase64, networkPassphrase);
  return res.ok ? { ok: true, tx: res.input.tx } : res;
}

/** Like decodeEnvelope, but also returns the raw operations for effect derivation. */
export function decodeForAnalysis(envelopeBase64: string, networkPassphrase: string): AnalysisDecodeResult {
  if (envelopeBase64.length > MAX_ENVELOPE_BASE64_LENGTH) {
    return { ok: false, status: "unanalyzable", reason: "input_too_large" };
  }
  if (networkPassphrase.length === 0 || networkPassphrase.length > MAX_PASSPHRASE_LENGTH) {
    return { ok: false, status: "unanalyzable", reason: "invalid_network_passphrase" };
  }
  try {
    return { ok: true, input: decodeUnchecked(envelopeBase64, networkPassphrase) };
  } catch {
    return { ok: false, status: "unanalyzable", reason: "decode_failed" };
  }
}

function decodeUnchecked(envelopeBase64: string, networkPassphrase: string): AnalysisInput {
  const env = xdr.TransactionEnvelope.fromXdr(envelopeBase64, "base64");
  // The SDK computes the signature-payload hash: exactly what the signer signs.
  const sdkTx = TransactionBuilder.fromXdr(env, networkPassphrase);
  const network = networkOf(networkPassphrase);

  switch (env.type) {
    case "envelopeTypeTxV0": {
      const tx = env.v0.tx;
      const source: AccountRef = { account: StrKey.encodeEd25519PublicKey(tx.sourceAccountEd25519.toBytes()) };
      return {
        tx: {
          envelope: "tx_v0",
          network,
          txHash: hex(sdkTx.hash()),
          source,
          fee: String(tx.fee),
          sequence: tx.seqNum.toString(),
          timeBounds: tx.timeBounds ? timeBounds(tx.timeBounds) : null,
          memo: memo(tx.memo),
          operations: tx.operations.map((op, i) => decodeOperation(op, i, source)),
        },
        operations: tx.operations,
      };
    }
    case "envelopeTypeTx":
      return {
        tx: { envelope: "tx", network, txHash: hex(sdkTx.hash()), ...decodeV1(env.v1.tx) },
        operations: env.v1.tx.operations,
      };
    case "envelopeTypeTxFeeBump": {
      if (!(sdkTx instanceof FeeBumpTransaction)) {
        throw new Error("fee bump envelope did not decode as a fee bump");
      }
      const outer = env.feeBump.tx;
      return {
        tx: {
          envelope: "fee_bump",
          network,
          txHash: hex(sdkTx.hash()),
          innerTxHash: hex(sdkTx.innerTransaction.hash()),
          feeSource: accountRef(outer.feeSource),
          feeBumpFee: outer.fee.toString(),
          ...decodeV1(outer.innerTx.v1.tx),
        },
        operations: outer.innerTx.v1.tx.operations,
      };
    }
    default:
      return assertNever(env);
  }
}

function decodeV1(tx: xdr.Transaction) {
  const source = accountRef(tx.sourceAccount);
  return {
    source,
    fee: String(tx.fee),
    sequence: tx.seqNum.toString(),
    timeBounds: preconditionTimeBounds(tx.cond),
    memo: memo(tx.memo),
    operations: tx.operations.map((op, i) => decodeOperation(op, i, source)),
  };
}

function preconditionTimeBounds(cond: xdr.Preconditions): TimeBounds | null {
  switch (cond.type) {
    case "precondNone":
      return null;
    case "precondTime":
      return timeBounds(cond.timeBounds);
    case "precondV2":
      return cond.v2.timeBounds ? timeBounds(cond.v2.timeBounds) : null;
    default:
      return assertNever(cond);
  }
}

function timeBounds(tb: xdr.TimeBounds): TimeBounds {
  return { min: tb.minTime.toString(), max: tb.maxTime.toString() };
}

function memo(m: xdr.Memo): Memo {
  switch (m.type) {
    case "memoNone":
      return { type: "none" };
    case "memoText":
      // Raw bytes only: memo text is untrusted and is sanitized at display time.
      return { type: "text", bytesHex: hex(m.text.bytes) };
    case "memoId":
      return { type: "id", id: m.id.toString() };
    case "memoHash":
      return { type: "hash", hashHex: hex(m.hash.toBytes()) };
    case "memoReturn":
      return { type: "return", hashHex: hex(m.retHash.toBytes()) };
    default:
      return assertNever(m);
  }
}

function hex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) {
    s += b.toString(16).padStart(2, "0");
  }
  return s;
}
