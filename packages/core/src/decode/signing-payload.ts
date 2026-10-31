import { StrKey, buildAuthorizationEntryPreimage, hash, verify, xdr } from "@stellar/stellar-sdk/base";

import { assertNever } from "../assert-never.ts";
import { MAX_AUTH_ENTRY_BASE64_LENGTH } from "./auth-entry.ts";

const EQUALS = 0x3d; // "="
const STANDARD_BASE64 = /^[A-Za-z0-9+/]+$/;

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

/** Whether the base64 parses at all as a `SorobanAuthorizationEntry`. */
export function isAuthEntry(base64: string): boolean {
  return analyzeEntry(base64) !== null;
}

/**
 * Whether the base64 is the encoding of exactly 64 bytes, the length of an
 * Ed25519 signature. A statement about length only: nothing here proves what
 * those bytes sign, which is why `sameAuthEntry` cannot be used on them.
 */
export function isSignatureLength(base64: string): boolean {
  // Padding is scanned from the end rather than stripped with a regex: this
  // string comes from a wallet, and `=+$` backtracks over a run of `=`.
  let body = base64.length;
  while (body > 0 && base64.charCodeAt(body - 1) === EQUALS) body--;
  const pads = base64.length - body;
  if (pads > 2) return false;
  if (pads > 0 && base64.length % 4 !== 0) return false;
  // Length decides first, so the charset is only ever tested on the ~88
  // characters that could still be a signature.
  if (Math.floor((body * 3) / 4) !== 64) return false;
  return STANDARD_BASE64.test(base64.slice(0, body));
}

/**
 * Why a reply cannot be related to the entry that was analyzed. Each value is a
 * code so the integrator owns the wording (AGENTS.md §5).
 */
export type UnverifiableReply =
  /** The bytes given as the entry do not decode as one, at this build's size ceiling included. */
  | "entry_undecodable"
  /** The reply is not 64 bytes, so it is not a bare Ed25519 signature either. */
  | "reply_not_a_signature"
  /** Source-account credentials carry no signature: the envelope's signer authorizes them. */
  | "credential_has_no_signature"
  /**
   * The credentials name something other than an ed25519 key (a contract, a
   * claimable balance, a liquidity pool, a pre-auth or hash signer), so only that
   * address's own `__check_auth` can say whether these bytes authorize it.
   */
  | "credential_not_ed25519";

export type ReplyVerification =
  /** The reply is `authorizedBy`'s authorization of this entry: its credential address. */
  | { verdict: "verified"; authorizedBy: string }
  /** Verifiable ed25519 bytes, but not this entry's authorization: another tree, nonce, ledger bound, network, or key. */
  | { verdict: "mismatch"; authorizedBy: string }
  | { verdict: "unverifiable"; reason: UnverifiableReply };

/**
 * Do `signatureBase64` authorize `authEntryBase64`?
 *
 * A SEP-43 wallet that reads `signAuthEntry`'s parameter as the entry's preimage
 * returns nothing but a bare Ed25519 signature, so `sameAuthEntry` has no payload
 * to compare. The payload is recoverable: `HashIdPreimage.sorobanAuthorization`
 * is built from the entry itself (invocation tree, nonce, ledger bound, network
 * passphrase, and for the address-bound arms the credential address), so checking
 * the reply against it says who authorized which entry, on which network, until
 * which ledger.
 *
 * The verifier is the entry's own credential address, not anything the wallet
 * reports, because that is what the network uses: `__check_auth` checks the
 * signature on the credentials against the key those credentials name. So
 * `verified` means exactly "these bytes are that key's authorization of this
 * entry" and nothing more: the entry is not assembled, nothing is submitted, and
 * Guard holds no key.
 *
 * The derivation is the pinned SDK's own (`buildAuthorizationEntryPreimage`), the
 * same function `authorizeEntry` signs with, and it is the rule the CAPs state:
 * CAP-0046-11 "Soroban Authorization Signature Payload" fixes the legacy arm
 * (`ENVELOPE_TYPE_SOROBAN_AUTHORIZATION`: `networkID` = sha256 of the passphrase,
 * the credentials' `nonce` and `signatureExpirationLedger`, the entry's
 * `rootInvocation`, and no address), and CAP-0071-01/-02 fix the address-bound arm
 * (`..._WITH_ADDRESS`: the same contents plus the top-level `address`) that V2 and
 * delegated credentials use. A signature over any other payload verifies against
 * no accepted entry, which is why `mismatch` is reportable rather than merely
 * unknown.
 *
 * Two limits are stated rather than papered over. Only the top-level credential is
 * checked: a delegated entry's `delegates` signatures are separate claims by other
 * addresses. And a custom account whose `__check_auth` accepts a non-master signer
 * or a threshold can reject what this calls `verified` — never the other way round,
 * which is the direction that matters (§3.8).
 *
 * It never returns a claim it cannot support: every input it cannot put a verdict
 * on record for comes back `unverifiable`, because a false `verified` would hand an
 * integrator a clean result for bytes nothing checked (§3.2). A credential arm this
 * build does not know throws instead, as the other decoders here do.
 */
export function verifyAuthEntrySignature(
  authEntryBase64: string,
  signatureBase64: string,
  networkPassphrase: string,
): ReplyVerification {
  const signature = decodeSignature(signatureBase64);
  if (signature === null) return { verdict: "unverifiable", reason: "reply_not_a_signature" };
  if (authEntryBase64.length > MAX_AUTH_ENTRY_BASE64_LENGTH) {
    return { verdict: "unverifiable", reason: "entry_undecodable" };
  }
  const entry = analyzeEntry(authEntryBase64);
  if (entry === null) return { verdict: "unverifiable", reason: "entry_undecodable" };
  const credentials = addressCredentialsOf(entry.credentials);
  if (credentials === null) return { verdict: "unverifiable", reason: "credential_has_no_signature" };
  const authorizedBy = ed25519OfAddress(credentials.address);
  if (authorizedBy === null) return { verdict: "unverifiable", reason: "credential_not_ed25519" };
  const preimage = buildAuthorizationEntryPreimage(entry, credentials.signatureExpirationLedger, networkPassphrase);
  return verify(hash(preimage.toXdr()), signature, authorizedBy)
    ? { verdict: "verified", authorizedBy: StrKey.encodeEd25519PublicKey(authorizedBy) }
    : { verdict: "mismatch", authorizedBy: StrKey.encodeEd25519PublicKey(authorizedBy) };
}

/** The arm that holds a signature, or null when the credential carries none. */
function addressCredentialsOf(cred: xdr.SorobanCredentials): xdr.SorobanAddressCredentials | null {
  switch (cred.type) {
    case "sorobanCredentialsSourceAccount":
      return null;
    case "sorobanCredentialsAddress":
      return cred.address;
    case "sorobanCredentialsAddressV2":
      return cred.addressV2;
    case "sorobanCredentialsAddressWithDelegates":
      return cred.addressWithDelegates.addressCredentials;
    default:
      return assertNever(cred);
  }
}

/**
 * The ed25519 key an `ScAddress` names, or null for the kinds that name no such
 * key: their authorization is whatever their own `__check_auth` decides. A muxed
 * account normalizes to the key it wraps, and its id stays bound through the
 * preimage, which carries the address as it appears on the credentials.
 */
function ed25519OfAddress(address: xdr.ScAddress): Uint8Array | null {
  switch (address.type) {
    case "scAddressTypeAccount":
      return address.accountId.type === "publicKeyTypeEd25519" ? address.accountId.ed25519.toBytes() : null;
    case "scAddressTypeMuxedAccount":
      return address.muxedAccount.ed25519.toBytes();
    case "scAddressTypeContract":
    case "scAddressTypeClaimableBalance":
    case "scAddressTypeLiquidityPool":
      return null;
    default:
      return assertNever(address);
  }
}

/** The 64 bytes an Ed25519 signature is, or null if these base64 characters are not them. */
function decodeSignature(base64: string): Uint8Array | null {
  if (!isSignatureLength(base64)) return null;
  try {
    const bytes = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
    return bytes.length === 64 ? bytes : null;
  } catch {
    return null;
  }
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
