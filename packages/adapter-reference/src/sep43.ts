/**
 * SEP-43 ("Standard Web Wallet API Interface") v1.2.1, **status: Draft**, the
 * two signing methods only. Checked against
 * `stellar-protocol/ecosystem/SEP-0043.md` on 2026-10-29, not inferred from any
 * wallet's typings. SEP-60 requires an announced wallet to implement it.
 *
 * The spec writes its results as `Promise<{ ... } & error?: Error>`, which is
 * pseudo-code rather than valid TypeScript: an optional property cannot be
 * intersected onto an object literal. Its prose is unambiguous about the
 * behaviour — a wallet reports a refusal **resolved**, not thrown — so these
 * types carry `error` as an optional field and Guard checks it before anything
 * else. A wallet that throws instead is handled the same way by the adapter.
 *
 * TODO(verify): `signAuthEntry`'s parameter is described in prose as an
 * "authorization entry preimage" while the interface types it as a base64
 * string. The adapter treats it as a base64 `SorobanAuthorizationEntry`, the
 * only reading consistent with the interface and with what a wallet can fill a
 * signature into.
 */

/** Errors carry a message meant for the user and one of the spec's codes. */
export interface Sep43Error {
  message: string;
  /** `-1` internal, `-2` external service, `-3` invalid request, `-4` user rejected. */
  code: number;
  ext?: string[];
}

export interface SignTransactionOptions {
  networkPassphrase?: string;
  address?: string;
  /** The wallet submits the transaction itself after signing. */
  submit?: boolean;
  submitUrl?: string;
}

export interface SignTransactionResponse {
  signedTxXdr?: string;
  signerAddress?: string;
  error?: Sep43Error;
}

export interface SignAuthEntryOptions {
  networkPassphrase?: string;
  address?: string;
}

export interface SignAuthEntryResponse {
  signedAuthEntry?: string;
  signerAddress?: string;
  error?: Sep43Error;
}

/** The subset of the wallet interface Guard's reference adapter calls. */
export interface Sep43Signer {
  signTransaction(xdr: string, opts?: SignTransactionOptions): Promise<SignTransactionResponse>;
  signAuthEntry(authEntry: string, opts?: SignAuthEntryOptions): Promise<SignAuthEntryResponse>;
}

/**
 * The error a wallet reported for itself, or null if it reported none.
 *
 * Nothing is invented here: a refusal's wording belongs to the wallet and is
 * untrusted text, and a wallet that reported nothing is a coded failure in the
 * adapter, not a sentence (AGENTS.md §5). A malformed `error` field reads as
 * absent, so the caller falls through to its own reason code.
 */
export function walletErrorOf(response: { error?: Sep43Error } | null | undefined): Sep43Error | null {
  if (response === null || response === undefined || response.error === undefined) return null;
  const e = response.error;
  return typeof e.message === "string" && typeof e.code === "number" ? e : null;
}
