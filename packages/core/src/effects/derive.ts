import { SignerKey, type xdr } from "@stellar/stellar-sdk/base";

import { assertNever } from "../assert-never.ts";
import { accountRef } from "../decode/account.ts";
import type { AnalysisInput } from "../decode/envelope.ts";
import { InvalidOperation, accountId, assetKey, creditKey } from "./asset.ts";
import type { AccountEffect, BalanceEffect, EffectsResult, SignerType, UncoveredOperation } from "./types.ts";

interface Delta {
  account: string;
  asset: string;
  min: bigint;
  max: bigint | null;
}

interface OperationEffects {
  deltas: Delta[];
  account: AccountEffect[];
}

// TODO(verify): the network rejects weights and thresholds above 255 (SetOptions
// out-of-range result). Treated as invalid here, which fails loud either way.
const MAX_WEIGHT = 255;

/**
 * Derives effects per affected account: balance changes (the fee, payment,
 * createAccount, both path payments) and account changes (changeTrust,
 * setOptions, accountMerge). Every other operation is listed in `uncovered`,
 * so callers can never mistake missing effects for none.
 */
export function deriveEffects(input: AnalysisInput): EffectsResult {
  const deltas: Delta[] = [feeDelta(input)];
  const accountEffects: AccountEffect[] = [];
  const uncovered: UncoveredOperation[] = [];

  input.operations.forEach((op, index) => {
    const source = input.tx.operations[index]?.source.account ?? input.tx.source.account;
    try {
      const e = operationEffects(op.body, source, index);
      if (e === null) {
        uncovered.push({ index, reason: "not_derived_yet" });
      } else {
        deltas.push(...e.deltas);
        accountEffects.push(...e.account);
      }
    } catch (err) {
      if (!(err instanceof InvalidOperation)) throw err;
      uncovered.push({ index, reason: "invalid_operation" });
    }
  });

  return { effects: aggregate(deltas), accountEffects, uncovered };
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

const balances = (deltas: Delta[]): OperationEffects => ({ deltas, account: [] });
const changes = (account: AccountEffect[]): OperationEffects => ({ deltas: [], account });

/** Returns null when effects for this operation type are not derived yet. */
function operationEffects(body: xdr.OperationBody, source: string, index: number): OperationEffects | null {
  switch (body.type) {
    case "payment": {
      const op = body.paymentOp;
      const amount = positive(op.amount);
      const asset = assetKey(op.asset);
      return balances([
        { account: source, asset, min: -amount, max: -amount },
        { account: accountRef(op.destination).account, asset, min: amount, max: amount },
      ]);
    }
    case "createAccount": {
      const op = body.createAccountOp;
      const amount = positive(op.startingBalance);
      return balances([
        { account: source, asset: "native", min: -amount, max: -amount },
        { account: accountId(op.destination), asset: "native", min: amount, max: amount },
      ]);
    }
    case "pathPaymentStrictReceive": {
      // The sender authorizes up to sendMax; the receiver gets exactly destAmount.
      const op = body.pathPaymentStrictReceiveOp;
      const sendMax = positive(op.sendMax);
      const destAmount = positive(op.destAmount);
      return balances([
        { account: source, asset: assetKey(op.sendAsset), min: -sendMax, max: 0n },
        { account: accountRef(op.destination).account, asset: assetKey(op.destAsset), min: destAmount, max: destAmount },
      ]);
    }
    case "pathPaymentStrictSend": {
      // The sender pays exactly sendAmount; the receiver gets at least destMin, with no upper bound.
      const op = body.pathPaymentStrictSendOp;
      const sendAmount = positive(op.sendAmount);
      const destMin = positive(op.destMin);
      return balances([
        { account: source, asset: assetKey(op.sendAsset), min: -sendAmount, max: -sendAmount },
        { account: accountRef(op.destination).account, asset: assetKey(op.destAsset), min: destMin, max: null },
      ]);
    }
    case "changeTrust":
      return changeTrust(body.changeTrustOp, source, index);
    case "setOptions":
      return changes(setOptions(body.setOptionsOp, source, index));
    case "accountMerge":
      // The entire native balance moves; its amount is unknown without ledger data,
      // so it is a merge effect, not a balance effect.
      return changes([{ kind: "merge", operationIndex: index, account: source, destination: accountRef(body.destination).account }]);
    case "manageSellOffer":
    case "createPassiveSellOffer":
    case "allowTrust":
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

function changeTrust(op: xdr.ChangeTrustOp, source: string, index: number): OperationEffects | null {
  if (op.limit < 0n) {
    throw new InvalidOperation("negative trustline limit");
  }
  const line = op.line;
  switch (line.type) {
    case "assetTypeNative":
      throw new InvalidOperation("trustline to the native asset");
    case "assetTypeCreditAlphanum4": {
      const asset = creditKey(line.alphaNum4.assetCode.toBytes(), line.alphaNum4.issuer);
      return changes([{ kind: "trustline", operationIndex: index, account: source, asset, limit: op.limit }]);
    }
    case "assetTypeCreditAlphanum12": {
      const asset = creditKey(line.alphaNum12.assetCode.toBytes(), line.alphaNum12.issuer);
      return changes([{ kind: "trustline", operationIndex: index, account: source, asset, limit: op.limit }]);
    }
    case "assetTypePoolShare":
      // Liquidity-pool share trustlines have no canonical key yet.
      return null;
    default:
      return assertNever(line);
  }
}

function setOptions(op: xdr.SetOptionsOp, source: string, index: number): AccountEffect[] {
  const out: AccountEffect[] = [];
  const weights = [op.masterWeight, op.lowThreshold, op.medThreshold, op.highThreshold];
  if (weights.some((w) => w !== null && (w < 0 || w > MAX_WEIGHT))) {
    throw new InvalidOperation("threshold out of range");
  }
  if (op.signer) {
    if (op.signer.weight < 0 || op.signer.weight > MAX_WEIGHT) {
      throw new InvalidOperation("signer weight out of range");
    }
    out.push({
      kind: "signer",
      operationIndex: index,
      account: source,
      signer: SignerKey.encodeSignerKey(op.signer.key),
      signerType: signerType(op.signer.key),
      weight: op.signer.weight,
    });
  }
  if (weights.some((w) => w !== null)) {
    out.push({
      kind: "thresholds",
      operationIndex: index,
      account: source,
      masterWeight: op.masterWeight,
      low: op.lowThreshold,
      medium: op.medThreshold,
      high: op.highThreshold,
    });
  }
  if (op.setFlags !== null || op.clearFlags !== null) {
    out.push({ kind: "flags", operationIndex: index, account: source, set: op.setFlags, clear: op.clearFlags });
  }
  if (op.homeDomain !== null) {
    out.push({ kind: "home_domain", operationIndex: index, account: source, bytesHex: hex(op.homeDomain.bytes) });
  }
  if (op.inflationDest !== null) {
    out.push({ kind: "inflation_destination", operationIndex: index, account: source, destination: accountId(op.inflationDest) });
  }
  return out;
}

function signerType(key: xdr.SignerKey): SignerType {
  switch (key.type) {
    case "signerKeyTypeEd25519":
      return "ed25519";
    case "signerKeyTypePreAuthTx":
      return "pre_auth_tx";
    case "signerKeyTypeHashX":
      return "hash_x";
    case "signerKeyTypeEd25519SignedPayload":
      return "ed25519_signed_payload";
    default:
      return assertNever(key);
  }
}

function positive(amount: bigint): bigint {
  if (amount <= 0n) {
    throw new InvalidOperation("non-positive amount");
  }
  return amount;
}

function hex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) {
    s += b.toString(16).padStart(2, "0");
  }
  return s;
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
