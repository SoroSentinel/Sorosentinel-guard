import type { xdr } from "@stellar/stellar-sdk/base";

import { assertNever } from "../assert-never.ts";
import { accountRef } from "../decode/account.ts";
import type { AnalysisInput } from "../decode/envelope.ts";
import { InvalidOperation, accountId, assetKey } from "./asset.ts";
import type { BalanceEffect, EffectsResult, UncoveredOperation } from "./types.ts";

interface Delta {
  account: string;
  asset: string;
  min: bigint;
  max: bigint | null;
}

/**
 * Derives balance effects per affected account. Covered so far: the fee,
 * payment, createAccount and both path payments. Every other operation is
 * listed in `uncovered`, so callers can never mistake missing effects for none.
 */
export function deriveBalanceEffects(input: AnalysisInput): EffectsResult {
  const deltas: Delta[] = [feeDelta(input)];
  const uncovered: UncoveredOperation[] = [];

  input.operations.forEach((op, index) => {
    const source = input.tx.operations[index]?.source.account ?? input.tx.source.account;
    try {
      const d = operationDeltas(op.body, source);
      if (d === null) {
        uncovered.push({ index, reason: "not_derived_yet" });
      } else {
        deltas.push(...d);
      }
    } catch (e) {
      if (!(e instanceof InvalidOperation)) throw e;
      uncovered.push({ index, reason: "invalid_operation" });
    }
  });

  return { effects: aggregate(deltas), uncovered };
}

/**
 * The account paying the fee loses at most the declared fee. For a fee bump the
 * outer fee source pays and the inner fee is not charged: CAP-15 requires the
 * fee source to cover `feeBump.tx.fee` and lets the inner source lack the balance.
 */
function feeDelta(input: AnalysisInput): Delta {
  const { tx } = input;
  if (tx.envelope === "fee_bump" && tx.feeSource && tx.feeBumpFee !== undefined) {
    return { account: tx.feeSource.account, asset: "native", min: -BigInt(tx.feeBumpFee), max: 0n };
  }
  return { account: tx.source.account, asset: "native", min: -BigInt(tx.fee), max: 0n };
}

/** Returns null when effects for this operation type are not derived yet. */
function operationDeltas(body: xdr.OperationBody, source: string): Delta[] | null {
  switch (body.type) {
    case "payment": {
      const op = body.paymentOp;
      const amount = positive(op.amount);
      const asset = assetKey(op.asset);
      return [
        { account: source, asset, min: -amount, max: -amount },
        { account: accountRef(op.destination).account, asset, min: amount, max: amount },
      ];
    }
    case "createAccount": {
      const op = body.createAccountOp;
      const amount = positive(op.startingBalance);
      return [
        { account: source, asset: "native", min: -amount, max: -amount },
        { account: accountId(op.destination), asset: "native", min: amount, max: amount },
      ];
    }
    case "pathPaymentStrictReceive": {
      // The sender authorizes up to sendMax; the receiver gets exactly destAmount.
      const op = body.pathPaymentStrictReceiveOp;
      const sendMax = positive(op.sendMax);
      const destAmount = positive(op.destAmount);
      return [
        { account: source, asset: assetKey(op.sendAsset), min: -sendMax, max: 0n },
        { account: accountRef(op.destination).account, asset: assetKey(op.destAsset), min: destAmount, max: destAmount },
      ];
    }
    case "pathPaymentStrictSend": {
      // The sender pays exactly sendAmount; the receiver gets at least destMin, with no upper bound.
      const op = body.pathPaymentStrictSendOp;
      const sendAmount = positive(op.sendAmount);
      const destMin = positive(op.destMin);
      return [
        { account: source, asset: assetKey(op.sendAsset), min: -sendAmount, max: -sendAmount },
        { account: accountRef(op.destination).account, asset: assetKey(op.destAsset), min: destMin, max: null },
      ];
    }
    case "manageSellOffer":
    case "createPassiveSellOffer":
    case "setOptions":
    case "changeTrust":
    case "allowTrust":
    case "accountMerge":
    case "inflation":
    case "manageData":
    case "bumpSequence":
    case "manageBuyOffer":
    case "createClaimableBalance":
    case "claimClaimableBalance":
    case "beginSponsoringFutureReserves":
    case "endSponsoringFutureReserves":
    case "revokeSponsorship":
    case "clawback":
    case "clawbackClaimableBalance":
    case "setTrustLineFlags":
    case "liquidityPoolDeposit":
    case "liquidityPoolWithdraw":
    case "invokeHostFunction":
    case "extendFootprintTtl":
    case "restoreFootprint":
      return null;
    default:
      return assertNever(body);
  }
}

function positive(amount: bigint): bigint {
  if (amount <= 0n) {
    throw new InvalidOperation("non-positive amount");
  }
  return amount;
}

/** Nets deltas per (account, asset); worst case first, ties broken deterministically. */
function aggregate(deltas: Delta[]): BalanceEffect[] {
  const byKey = new Map<string, Delta>();
  for (const d of deltas) {
    const key = `${d.account}|${d.asset}`;
    const prev = byKey.get(key);
    if (!prev) {
      byKey.set(key, { ...d });
    } else {
      prev.min += d.min;
      prev.max = prev.max === null || d.max === null ? null : prev.max + d.max;
    }
  }
  return [...byKey.values()]
    .map((d): BalanceEffect => ({ account: d.account, asset: d.asset, deltaMin: d.min, deltaMax: d.max, assurance: "ledger" }))
    .sort((a, b) => (a.deltaMin < b.deltaMin ? -1 : a.deltaMin > b.deltaMin ? 1 : `${a.account}|${a.asset}` < `${b.account}|${b.asset}` ? -1 : 1));
}
