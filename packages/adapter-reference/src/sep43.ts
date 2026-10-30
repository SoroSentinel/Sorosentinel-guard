/**
 * SEP-43 ("Standard Web Wallet API Interface") v1.2.1, **status: Draft**, the
 * two signing methods only. Checked against
 * `stellar/stellar-protocol@62a67297ea14 ecosystem/sep-0043.md` on 2026-10-30,
 * not inferred from any wallet's typings. SEP-60 requires an announced wallet to
 * implement it.
 *
 * The spec writes its results as `Promise<{ ... } & error?: Error>`, which is
 * pseudo-code rather than valid TypeScript: an optional property cannot be
 * intersected onto an object literal. Its prose is unambiguous about the
 * behaviour — a wallet reports a refusal **resolved**, not thrown — so these
 * types carry `error` as an optional field and Guard checks it before anything
 * else. A wallet that throws instead is handled the same way by the adapter.
 *
 * `signAuthEntry`'s payload is genuinely ambiguous in the spec, and both
 * readings ship in wallets. Its interface types the parameter `authEntry: string`
 * and the result `signedAuthEntry: string`; its prose calls the same parameter an
 * "authorization entry preimage" and links it to
 * `js-stellar-base@a9567e584376 types/curr.d.ts:6894`, which is
 * `HashIdPreimageSorobanAuthorization`. Freighter — an announced wallet, so bound
 * by SEP-60 — follows the preimage reading at
 * `stellar/freighter@b237323ccf55`: its popup parses the parameter with
 * `xdr.HashIdPreimage.fromXdr(entry, "base64")` and its background handler returns
 * `base64(Keypair.sign(hash(entryBytes)))`, i.e. a bare 64-byte signature, and its
 * own playground labels the input "entry preimage XDR". Guard works in the entry
 * reading, because an entry is the only form whose authorized call tree it can
 * analyze; `guardSignAuthEntry` classifies whatever comes back rather than
 * assuming either wallet.
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
