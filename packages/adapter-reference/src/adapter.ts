import {
  analyze,
  analyzeAuthEntry,
  isAuthEntry,
  sameAuthEntry,
  sameTransactionPayload,
  verifyAuthEntrySignature,
  type AnalyzeContext,
  type AnalysisResult,
  type AnalysisStatus,
  type AuthEntryAnalysisResult,
  type UnverifiableReply,
} from "@sorosentinel/guard-core";

import {
  walletErrorOf,
  type Sep43Error,
  type Sep43Signer,
  type SignAuthEntryOptions,
  type SignTransactionOptions,
} from "./sep43.ts";

/**
 * Called with the analysis of exactly the bytes about to be signed, before the
 * wallet is asked for anything. Return `true` to proceed. `false`, a throw, or
 * anything that is not exactly `true` cancels: the adapter never signs on
 * somebody else's default.
 */
export type Review<A> = (analysis: A, xdrBase64: string) => boolean | Promise<boolean>;

/**
 * Why nothing was signed. Every value is a code: an integrator renders the
 * wording (AGENTS.md §5), and the only text this adapter passes through is the
 * wallet's own, unverified and not sanitized, in `walletError`.
 */
export type NotSignedReason =
  | "review_declined"
  | "network_mismatch"
  /** The wallet reported its own error (SEP-43 `-1`..`-4`) instead of signing. */
  | "wallet_rejected"
  /** The wallet threw, or resolved nothing. */
  | "wallet_no_response"
  /** The wallet reported no error but gave no usable signed bytes. */
  | "wallet_no_signed_bytes";

export type GuardedSignTransaction =
  /** The wallet signed exactly the transaction that was analyzed. */
  | { outcome: "signed"; analyzedBytesMatch: true; status: AnalysisStatus; analysis: AnalysisResult; signedTxXdr: string; signerAddress: string | null }
  /** The wallet signed, but not what was analyzed: `analysis` does not describe these bytes, so the result is `partial`. */
  | { outcome: "signed_other_bytes"; status: "partial"; analysis: AnalysisResult; signedTxXdr: string; signerAddress: string | null }
  /** Nothing was signed. */
  | { outcome: "not_signed"; reason: NotSignedReason; status: AnalysisStatus; analysis: AnalysisResult; walletError: Sep43Error | null };

export type GuardedSignAuthEntry =
  | { outcome: "signed"; analyzedBytesMatch: true; status: AnalysisStatus; analysis: AuthEntryAnalysisResult; signedAuthEntry: string; signerAddress: string | null }
  /** The wallet returned an auth entry, and it is not the one that was analyzed. */
  | { outcome: "signed_other_bytes"; status: "partial"; analysis: AuthEntryAnalysisResult; signedAuthEntry: string; signerAddress: string | null }
  /**
   * The wallet returned bytes that are not an auth entry, and nothing here can
   * relate them to what was analyzed. SEP-43 describes `signAuthEntry` both as
   * taking an entry and as taking its preimage, and Freighter implements the
   * preimage reading: it returns a bare Ed25519 signature, which the dApp
   * assembles into an entry itself. `reason` names the check that could not be
   * made; the result stays `partial` — never `signed`, and never a claim that
   * the wallet signed something else.
   */
  | { outcome: "signed_unverifiable"; status: "partial"; analysis: AuthEntryAnalysisResult; signedAuthEntry: string; signerAddress: string | null; reason: UnverifiableReply }
  /**
   * The wallet returned a bare signature, and it is this entry's authorization:
   * `authorizedBy`, the address the entry's credentials name, has signed the
   * payload those credentials imply — this invocation tree, on this network,
   * until that ledger. `status` is the analysis' own, as for `signed`; the entry
   * the network needs is still the dApp's to assemble, because Guard assembles
   * nothing and holds no key. `signerAddress` is the wallet's own claim and is
   * not what this verdict rests on.
   */
  | { outcome: "signed_preimage_verified"; status: AnalysisStatus; analysis: AuthEntryAnalysisResult; signature: string; authorizedBy: string; signerAddress: string | null }
  /**
   * The wallet returned a bare signature, and it is not this entry's
   * authorization for `authorizedBy`: a different tree, nonce, ledger bound,
   * network, or key. Reportable rather than unknown, and still `partial`.
   */
  | { outcome: "signed_preimage_mismatch"; status: "partial"; analysis: AuthEntryAnalysisResult; signature: string; authorizedBy: string; signerAddress: string | null }
  /** Nothing was signed. */
  | { outcome: "not_signed"; reason: NotSignedReason; status: AnalysisStatus; analysis: AuthEntryAnalysisResult; walletError: Sep43Error | null };

/**
 * Analyzes a base64 transaction envelope, shows the integrator the findings,
 * and only then asks the wallet to sign it. Guard holds no key and submits
 * nothing: the wallet is the only thing here that can sign.
 *
 * `ctx.networkPassphrase` is what the analysis is for, and it is what the wallet
 * is told to sign, so `opts.networkPassphrase` is filled in from it and a
 * conflict stops the call rather than being passed through.
 */
export async function guardSignTransaction(
  wallet: Pick<Sep43Signer, "signTransaction">,
  envelopeBase64: string,
  ctx: AnalyzeContext,
  review: Review<AnalysisResult>,
  opts?: SignTransactionOptions,
): Promise<GuardedSignTransaction> {
  const analysis = analyze(envelopeBase64, ctx);
  if (opts?.networkPassphrase !== undefined && opts.networkPassphrase !== ctx.networkPassphrase) {
    return notSigned("network_mismatch", analysis, null);
  }
  if (!(await approved(review, analysis, envelopeBase64))) return notSigned("review_declined", analysis, null);

  const response = await ask(() => wallet.signTransaction(envelopeBase64, { ...opts, networkPassphrase: ctx.networkPassphrase }));
  if (response === null) return notSigned("wallet_no_response", analysis, null);
  const error = walletErrorOf(response);
  if (error !== null) return notSigned("wallet_rejected", analysis, error);

  const signedTxXdr = response.signedTxXdr;
  if (typeof signedTxXdr !== "string" || signedTxXdr.length === 0) return notSigned("wallet_no_signed_bytes", analysis, null);
  const signerAddress = typeof response.signerAddress === "string" ? response.signerAddress : null;
  if (!sameTransactionPayload(envelopeBase64, signedTxXdr)) {
    return { outcome: "signed_other_bytes", status: "partial", analysis, signedTxXdr, signerAddress };
  }
  return { outcome: "signed", analyzedBytesMatch: true, status: analysis.status, analysis, signedTxXdr, signerAddress };
}

/**
 * As `guardSignTransaction`, for SEP-43's `signAuthEntry`.
 *
 * Guard passes a base64 `SorobanAuthorizationEntry`, because that is the only
 * form whose authorized call tree it can analyze. A wallet that expects the
 * entry's preimage instead answers with a bare signature; that reply is checked
 * against the preimage the analyzed entry implies, so it can come back
 * `signed_preimage_verified`, `signed_preimage_mismatch`, or
 * `signed_unverifiable` with the reason nothing could be checked.
 */
export async function guardSignAuthEntry(
  wallet: Pick<Sep43Signer, "signAuthEntry">,
  authEntryBase64: string,
  ctx: AnalyzeContext,
  review: Review<AuthEntryAnalysisResult>,
  opts?: SignAuthEntryOptions,
): Promise<GuardedSignAuthEntry> {
  const analysis = analyzeAuthEntry(authEntryBase64, ctx);
  if (opts?.networkPassphrase !== undefined && opts.networkPassphrase !== ctx.networkPassphrase) {
    return notSignedEntry("network_mismatch", analysis, null);
  }
  if (!(await approved(review, analysis, authEntryBase64))) return notSignedEntry("review_declined", analysis, null);

  const response = await ask(() => wallet.signAuthEntry(authEntryBase64, { ...opts, networkPassphrase: ctx.networkPassphrase }));
  if (response === null) return notSignedEntry("wallet_no_response", analysis, null);
  const error = walletErrorOf(response);
  if (error !== null) return notSignedEntry("wallet_rejected", analysis, error);

  const signedAuthEntry = response.signedAuthEntry;
  if (typeof signedAuthEntry !== "string" || signedAuthEntry.length === 0) return notSignedEntry("wallet_no_signed_bytes", analysis, null);
  const signerAddress = typeof response.signerAddress === "string" ? response.signerAddress : null;
  if (sameAuthEntry(authEntryBase64, signedAuthEntry)) {
    return { outcome: "signed", analyzedBytesMatch: true, status: analysis.status, analysis, signedAuthEntry, signerAddress };
  }
  if (isAuthEntry(signedAuthEntry)) {
    return { outcome: "signed_other_bytes", status: "partial", analysis, signedAuthEntry, signerAddress };
  }
  const check = verifyAuthEntrySignature(authEntryBase64, signedAuthEntry, ctx.networkPassphrase);
  if (check.verdict === "verified") {
    return { outcome: "signed_preimage_verified", status: analysis.status, analysis, signature: signedAuthEntry, authorizedBy: check.authorizedBy, signerAddress };
  }
  if (check.verdict === "mismatch") {
    return { outcome: "signed_preimage_mismatch", status: "partial", analysis, signature: signedAuthEntry, authorizedBy: check.authorizedBy, signerAddress };
  }
  return { outcome: "signed_unverifiable", status: "partial", analysis, signedAuthEntry, signerAddress, reason: check.reason };
}

async function approved<A>(review: Review<A>, analysis: A, xdrBase64: string): Promise<boolean> {
  try {
    return (await review(analysis, xdrBase64)) === true;
  } catch {
    return false;
  }
}

/** A wallet that throws is a wallet that did not sign; nothing about it is trusted. */
async function ask<T>(call: () => Promise<T>): Promise<T | null> {
  try {
    return await call();
  } catch {
    return null;
  }
}

function notSigned(reason: NotSignedReason, analysis: AnalysisResult, walletError: Sep43Error | null): GuardedSignTransaction {
  return { outcome: "not_signed", reason, status: analysis.status, analysis, walletError };
}

function notSignedEntry(reason: NotSignedReason, analysis: AuthEntryAnalysisResult, walletError: Sep43Error | null): GuardedSignAuthEntry {
  return { outcome: "not_signed", reason, status: analysis.status, analysis, walletError };
}
