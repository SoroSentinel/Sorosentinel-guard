import type { xdr } from "@stellar/stellar-sdk/base";

import { assertNever } from "../assert-never.ts";
import { accountRef } from "./account.ts";
import type { AccountRef, AuthEntrySummary, DecodedOperation, OperationSupport, OperationType } from "./types.ts";

/**
 * Exhaustive over every operation type the pinned XDR knows. A protocol upgrade
 * that adds a variant fails to compile here until it is classified.
 */
export function operationSupport(type: OperationType): OperationSupport {
  switch (type) {
    case "createAccount":
    case "payment":
    case "pathPaymentStrictReceive":
    case "pathPaymentStrictSend":
    case "changeTrust":
    case "setOptions":
    case "accountMerge":
    case "invokeHostFunction":
      return "effects";
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
    case "extendFootprintTtl":
    case "restoreFootprint":
      return "decode_only";
    default:
      return assertNever(type);
  }
}

export function decodeOperation(op: xdr.Operation, index: number, txSource: AccountRef): DecodedOperation {
  const body = op.body;
  const decoded: DecodedOperation = {
    index,
    type: body.type,
    support: operationSupport(body.type),
    source: op.sourceAccount ? accountRef(op.sourceAccount) : txSource,
    hasOwnSource: op.sourceAccount !== null,
  };
  if (body.type === "invokeHostFunction") {
    decoded.auth = body.invokeHostFunctionOp.auth.map(authSummary);
  }
  return decoded;
}

export function authSummary(entry: xdr.SorobanAuthorizationEntry): AuthEntrySummary {
  const cred = entry.credentials;
  switch (cred.type) {
    case "sorobanCredentialsSourceAccount":
      return { credential: cred.type };
    case "sorobanCredentialsAddress":
      return { credential: cred.type, signatureExpirationLedger: cred.address.signatureExpirationLedger };
    case "sorobanCredentialsAddressV2":
      return { credential: cred.type, signatureExpirationLedger: cred.addressV2.signatureExpirationLedger };
    case "sorobanCredentialsAddressWithDelegates":
      // TODO(verify): expiration field for delegated credentials; reported as type only.
      return { credential: cred.type };
    default:
      return assertNever(cred);
  }
}
