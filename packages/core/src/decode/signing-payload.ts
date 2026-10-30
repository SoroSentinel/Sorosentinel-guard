import { xdr } from "@stellar/stellar-sdk/base";

import { assertNever } from "../assert-never.ts";

/**
 * Did the wallet sign exactly the bytes that were analyzed (AGENTS.md §3.8)?
 *
 * Signing only ever adds `DecoratedSignature`s, which in this XDR live on the
 * envelope, not inside the transaction, and on the signature fields of an auth
 * entry. Both functions therefore compare the signed payload with its
 * signature-bearing fields removed: an entry or transaction that changed in any
 * other way — a different destination, amount, operation, address, nonce or
 * authorized tree — compares unequal.
 *
 * Neither proves *which* payload the wallet hashed: only the signer can compute
 * that, and Guard never holds a private key. A `false` here is the honest
 * failure mode, and the caller must stop presenting the earlier analysis as if
 * it described the returned bytes.
 */
export function sameTransactionPayload(analyzedBase64: string, returnedBase64: string): boolean {
  const a = unsignedPayload(analyze(analyzedBase64));
  const b = unsignedPayload(analyze(returnedBase64));
  return a !== null && b !== null && sameBytes(a, b);
}

/** As `sameTransactionPayload`, for one `SorobanAuthorizationEntry`. */
export function sameAuthEntry(analyzedBase64: string, returnedBase64: string): boolean {
  const a = signatureless(analyzeEntry(analyzedBase64));
  const b = signatureless(analyzeEntry(returnedBase64));
  return a !== null && b !== null && sameBytes(a, b);
}

function analyze(envelopeBase64: string): xdr.TransactionEnvelope | null {
  try {
    return xdr.TransactionEnvelope.fromXdr(envelopeBase64, "base64");
  } catch {
    return null;
  }
}

function analyzeEntry(authEntryBase64: string): xdr.SorobanAuthorizationEntry | null {
  try {
    return xdr.SorobanAuthorizationEntry.fromXdr(authEntryBase64, "base64");
  } catch {
    return null;
  }
}

/** The transaction actually signed, with the envelope signatures it carries dropped. */
function unsignedPayload(env: xdr.TransactionEnvelope | null): Uint8Array | null {
  if (env === null) return null;
  switch (env.type) {
    case "envelopeTypeTxV0":
      return env.v0.tx.toXdr();
    case "envelopeTypeTx":
      return env.v1.tx.toXdr();
    case "envelopeTypeTxFeeBump": {
      const outer = env.feeBump.tx;
      const inner = xdr.FeeBumpTransactionInnerTx.envelopeTypeTx(
        new xdr.TransactionV1Envelope({ tx: outer.innerTx.v1.tx, signatures: [] }),
      );
      return new xdr.FeeBumpTransaction({ feeSource: outer.feeSource, fee: outer.fee, innerTx: inner, ext: outer.ext }).toXdr();
    }
    default:
      return assertNever(env);
  }
}

/** The entry as authorized, with every signature field set to void. */
function signatureless(entry: xdr.SorobanAuthorizationEntry | null): Uint8Array | null {
  if (entry === null) return null;
  return new xdr.SorobanAuthorizationEntry({
    credentials: signaturelessCredentials(entry.credentials),
    rootInvocation: entry.rootInvocation,
  }).toXdr();
}

/** Exhaustive: a credential arm the pinned XDR adds fails to compile here. */
function signaturelessCredentials(cred: xdr.SorobanCredentials): xdr.SorobanCredentials {
  switch (cred.type) {
    case "sorobanCredentialsSourceAccount":
      return cred;
    case "sorobanCredentialsAddress":
      return xdr.SorobanCredentials.sorobanCredentialsAddress(signaturelessAddressCredentials(cred.address));
    case "sorobanCredentialsAddressV2":
      return xdr.SorobanCredentials.sorobanCredentialsAddressV2(signaturelessAddressCredentials(cred.addressV2));
    case "sorobanCredentialsAddressWithDelegates":
      return xdr.SorobanCredentials.sorobanCredentialsAddressWithDelegates(
        new xdr.SorobanAddressCredentialsWithDelegates({
          addressCredentials: signaturelessAddressCredentials(cred.addressWithDelegates.addressCredentials),
          delegates: signaturelessDelegates(cred.addressWithDelegates.delegates),
        }),
      );
    default:
      return assertNever(cred);
  }
}

function signaturelessAddressCredentials(creds: xdr.SorobanAddressCredentials): xdr.SorobanAddressCredentials {
  return new xdr.SorobanAddressCredentials({
    address: creds.address,
    nonce: creds.nonce,
    signatureExpirationLedger: creds.signatureExpirationLedger,
    signature: xdr.ScVal.scvVoid(),
  });
}

function signaturelessDelegates(delegates: readonly xdr.SorobanDelegateSignature[]): xdr.SorobanDelegateSignature[] {
  return delegates.map(
    (d) =>
      new xdr.SorobanDelegateSignature({
        address: d.address,
        signature: xdr.ScVal.scvVoid(),
        nestedDelegates: signaturelessDelegates(d.nestedDelegates),
      }),
  );
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
