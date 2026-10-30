import { StrKey, xdr } from "@stellar/stellar-sdk/base";

import { assertNever } from "../assert-never.ts";
import { networkOf } from "./network.ts";
import type { CredentialType, Network, UnanalyzableReason } from "./types.ts";

/** Same ceiling as an envelope: an auth entry is a component of one. */
export const MAX_AUTH_ENTRY_BASE64_LENGTH = 256 * 1024;
const MAX_PASSPHRASE_LENGTH = 256;

/**
 * Guard's own caps on the trees an entry can carry: a hostile caller can nest
 * invocations and delegates arbitrarily deep inside the size ceiling.
 * TODO(verify): the limits the network itself enforces on these trees.
 */
export const MAX_INVOCATION_NODES = 1024;
export const MAX_INVOCATION_DEPTH = 16;
export const MAX_DELEGATE_SIGNATURES = 64;

/**
 * The address whose signature an entry requires. `kind` fixes how the key is
 * encoded, so an address with no StrKey codec is still reported, not dropped.
 */
export type AuthEntryAddress =
  | { kind: "account"; account: string; muxedId: string | null }
  | { kind: "contract"; contract: string }
  | { kind: "claimable_balance"; idHex: string }
  | { kind: "liquidity_pool"; poolHex: string };

export interface DecodedAuthEntry {
  /** From the passphrase the caller asks about: an entry carries no network field. */
  network: Network;
  credential: CredentialType;
  /** Null for source-account credentials: the transaction's source signs, so the entry names no address. */
  address: AuthEntryAddress | null;
  /** Decimal string; null unless the credential is address-based. */
  nonce: string | null;
  /** Ledger after which the signature stops being valid; null when the credential carries none. */
  signatureExpirationLedger: number | null;
  /** Signatures beyond the credential's own (delegated credentials only). */
  delegateSignatures: number;
  /** Nodes of the authorized invocation tree, the root included. */
  invocationNodes: number;
  /** `C…` addresses the tree calls, deduped and sorted. */
  contracts: string[];
  /** The tree calls a non-contract address or creates a contract: there is nothing to look up. */
  contractsUnchecked: boolean;
}

export type AuthEntryDecodeResult =
  | { ok: true; entry: DecodedAuthEntry }
  | { ok: false; reason: UnanalyzableReason };

/**
 * Decodes one base64 `SorobanAuthorizationEntry`, as SEP-43's `signAuthEntry`
 * passes it. Never throws: any failure is an `unanalyzable` reason.
 *
 * It does not compute the preimage the wallet signs. That payload is built by
 * the signer from the entry, a ledger bound and the passphrase (SDK
 * `buildAuthorizationEntryPreimage`), and an entry carries no network field of
 * its own, so Guard reports the entry's content instead and `sameAuthEntry`
 * compares it after signing.
 */
export function decodeAuthEntry(authEntryBase64: string, networkPassphrase: string): AuthEntryDecodeResult {
  if (authEntryBase64.length > MAX_AUTH_ENTRY_BASE64_LENGTH) return { ok: false, reason: "input_too_large" };
  if (networkPassphrase.length === 0 || networkPassphrase.length > MAX_PASSPHRASE_LENGTH) {
    return { ok: false, reason: "invalid_network_passphrase" };
  }
  let raw: xdr.SorobanAuthorizationEntry;
  try {
    raw = xdr.SorobanAuthorizationEntry.fromXdr(authEntryBase64, "base64");
  } catch {
    return { ok: false, reason: "decode_failed" };
  }
  const creds = readCredentials(raw.credentials);
  if (!creds.ok) return { ok: false, reason: creds.reason };
  const tree = readInvocations(raw.rootInvocation, 1, { nodes: 0, contracts: new Set(), unchecked: false });
  if (!tree.ok) return { ok: false, reason: tree.reason };
  return {
    ok: true,
    entry: {
      network: networkOf(networkPassphrase),
      credential: raw.credentials.type,
      address: creds.address,
      nonce: creds.nonce,
      signatureExpirationLedger: creds.signatureExpirationLedger,
      delegateSignatures: creds.delegateSignatures,
      invocationNodes: tree.nodes,
      contracts: [...tree.contracts].sort(),
      contractsUnchecked: tree.unchecked,
    },
  };
}

/** Everything an entry requires of the signer except the signature itself. */
interface Credentials {
  address: AuthEntryAddress | null;
  nonce: string | null;
  signatureExpirationLedger: number | null;
  delegateSignatures: number;
}

/** Exhaustive: a credential arm the pinned XDR adds fails to compile here. */
function readCredentials(cred: xdr.SorobanCredentials): { ok: true } & Credentials | { ok: false; reason: UnanalyzableReason } {
  switch (cred.type) {
    case "sorobanCredentialsSourceAccount":
      return { ok: true, address: null, nonce: null, signatureExpirationLedger: null, delegateSignatures: 0 };
    case "sorobanCredentialsAddress":
      return { ok: true, ...addressCredentials(cred.address), delegateSignatures: 0 };
    case "sorobanCredentialsAddressV2":
      return { ok: true, ...addressCredentials(cred.addressV2), delegateSignatures: 0 };
    case "sorobanCredentialsAddressWithDelegates": {
      const inner = addressCredentials(cred.addressWithDelegates.addressCredentials);
      const delegates = countDelegates(cred.addressWithDelegates.delegates, 0);
      if (delegates > MAX_DELEGATE_SIGNATURES) return { ok: false, reason: "input_too_large" };
      return { ok: true, ...inner, delegateSignatures: delegates };
    }
    default:
      return assertNever(cred);
  }
}

function addressCredentials(creds: xdr.SorobanAddressCredentials): Pick<Credentials, "address" | "nonce" | "signatureExpirationLedger"> {
  return {
    address: readAddress(creds.address),
    nonce: creds.nonce.toString(),
    signatureExpirationLedger: creds.signatureExpirationLedger,
  };
}

/** Bounded: delegate chains nest, and each level is a signature the entry collects. */
function countDelegates(delegates: readonly xdr.SorobanDelegateSignature[], soFar: number): number {
  let n = soFar + delegates.length;
  if (n > MAX_DELEGATE_SIGNATURES) return n;
  for (const d of delegates) n = countDelegates(d.nestedDelegates, n);
  return n;
}

interface Tree {
  nodes: number;
  contracts: Set<string>;
  unchecked: boolean;
}

/** Walks the authorized invocation tree, refusing anything past Guard's caps. */
function readInvocations(node: xdr.SorobanAuthorizedInvocation, depth: number, acc: Tree): { ok: true } & Tree | { ok: false; reason: UnanalyzableReason } {
  if (depth > MAX_INVOCATION_DEPTH || acc.nodes + 1 > MAX_INVOCATION_NODES) return { ok: false, reason: "input_too_large" };
  acc.nodes += 1;
  readFunction(node.function, acc);
  for (const sub of node.subInvocations) {
    const res = readInvocations(sub, depth + 1, acc);
    if (!res.ok) return res;
  }
  return { ok: true, ...acc };
}

/** Exhaustive over every authorized-function arm; only a call names a contract. */
function readFunction(fn: xdr.SorobanAuthorizedFunction, acc: Tree): void {
  switch (fn.type) {
    case "sorobanAuthorizedFunctionTypeContractFn": {
      const address = readAddress(fn.contractFn.contractAddress);
      if (address.kind !== "contract") acc.unchecked = true;
      else acc.contracts.add(address.contract);
      return;
    }
    case "sorobanAuthorizedFunctionTypeCreateContractHostFn":
    case "sorobanAuthorizedFunctionTypeCreateContractV2HostFn":
      // The contract does not exist yet, so Intel has nothing to look up.
      acc.unchecked = true;
      return;
    default:
      return assertNever(fn);
  }
}

/** An `ScAddress`. Muxed accounts are normalized to their `G…` key; the arms with no StrKey codec are reported as hex. */
function readAddress(a: xdr.ScAddress): AuthEntryAddress {
  switch (a.type) {
    case "scAddressTypeAccount":
      return { kind: "account", account: StrKey.encodeEd25519PublicKey(a.accountId.ed25519.toBytes()), muxedId: null };
    case "scAddressTypeContract":
      return { kind: "contract", contract: StrKey.encodeContract(a.contractId.toBytes()) };
    case "scAddressTypeMuxedAccount":
      return { kind: "account", account: StrKey.encodeEd25519PublicKey(a.muxedAccount.ed25519.toBytes()), muxedId: a.muxedAccount.id.toString() };
    case "scAddressTypeClaimableBalance":
      // A versioned balance id, so the whole arm is encoded rather than one hash.
      return { kind: "claimable_balance", idHex: hex(a.claimableBalanceId.toXdr()) };
    case "scAddressTypeLiquidityPool":
      return { kind: "liquidity_pool", poolHex: hex(a.liquidityPoolId.toBytes()) };
    default:
      return assertNever(a);
  }
}

function hex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}
