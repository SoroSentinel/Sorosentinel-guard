import { readFileSync } from "node:fs";

import { Keypair, buildAuthorizationEntryPreimage, hash, xdr } from "@stellar/stellar-sdk/base";
import { describe, expect, it } from "vitest";

import {
  guardSignAuthEntry,
  guardSignTransaction,
  type Sep43Signer,
  type SignAuthEntryOptions,
  type SignAuthEntryResponse,
  type SignTransactionOptions,
  type SignTransactionResponse,
} from "../src/index.ts";

const TX = new URL("../../../fixtures/tx/", import.meta.url);
const ENTRIES = new URL("../../../fixtures/auth_entry/", import.meta.url);
const TESTNET = "Test SDF Network ; September 2015";
const PUBLIC = "Public Global Stellar Network ; September 2015";

const envelope = JSON.parse(readFileSync(new URL("benign/payment_native.json", TX), "utf8")) as { xdr: string };
const otherTx = JSON.parse(readFileSync(new URL("benign/create_account.json", TX), "utf8")) as { xdr: string };
const feeBump = JSON.parse(readFileSync(new URL("hostile/fee_bump.json", TX), "utf8")) as { xdr: string };
const authEntry = JSON.parse(readFileSync(new URL("benign/credential_address.json", ENTRIES), "utf8")) as { xdr: string };
const signedAuthEntry = JSON.parse(readFileSync(new URL("hostile/signature_prefilled.json", ENTRIES), "utf8")) as { xdr: string };
const otherAuthEntry = JSON.parse(readFileSync(new URL("benign/address_is_contract.json", ENTRIES), "utf8")) as { xdr: string };
const sourceAccountAuthEntry = JSON.parse(readFileSync(new URL("benign/credential_source_account.json", ENTRIES), "utf8")) as { xdr: string };
/** The only fixture whose credential address a test can sign for: its key is `testKey(1)`. */
const signableAuthEntry = JSON.parse(readFileSync(new URL("benign/credential_address_test_key.json", ENTRIES), "utf8")) as { xdr: string; expected: { signature_expiration_ledger: number } };
const SIGNABLE_EXPIRY = signableAuthEntry.expected.signature_expiration_ledger;

/** The fixture keys (gen-fixtures.ts `testKey`). */
const testKey = (byte: number) => Keypair.fromRawEd25519Seed(new Uint8Array(32).fill(byte));

/**
 * What a preimage-reading wallet answers: the signature over the entry's
 * authorization payload, and nothing else. The derivation is the pinned SDK's own,
 * so what is under test here is the adapter's dispatch; `test/auth-preimage.test.ts`
 * pins the payload itself against the CAPs.
 */
function signPreimage(entryBase64: string, by: Keypair, passphrase = TESTNET): string {
  const entry = xdr.SorobanAuthorizationEntry.fromXDR(entryBase64, "base64");
  const preimage = buildAuthorizationEntryPreimage(entry, SIGNABLE_EXPIRY, passphrase);
  return btoa(String.fromCharCode(...by.sign(hash(preimage.toXdr()))));
}

/** The entry with one of its payload-bound fields changed, so a signature over the original must not read as valid. */
function change(entryBase64: string, what: "nonce" | "expiry" | "tree"): string {
  const e = xdr.SorobanAuthorizationEntry.fromXDR(entryBase64, "base64");
  if (e.credentials.type !== "sorobanCredentialsAddress") throw new Error("fixture is not address credentials");
  const c = e.credentials.address;
  const creds = new xdr.SorobanAddressCredentials({
    address: c.address,
    nonce: what === "nonce" ? c.nonce + 1n : c.nonce,
    signatureExpirationLedger: what === "expiry" ? c.signatureExpirationLedger + 1 : c.signatureExpirationLedger,
    signature: xdr.ScVal.scvVoid(),
  });
  const root = what === "tree" ? new xdr.SorobanAuthorizedInvocation({ function: e.rootInvocation.function, subInvocations: [e.rootInvocation] }) : e.rootInvocation;
  return new xdr.SorobanAuthorizationEntry({ credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(creds), rootInvocation: root }).toXDR("base64");
}

const ctx = { networkPassphrase: TESTNET };
const approve = () => true;

/** A wallet that records what it was asked to sign and then answers. */
function txWallet(reply: SignTransactionResponse | Error) {
  const calls: { xdr: string; opts: SignTransactionOptions }[] = [];
  const wallet: Pick<Sep43Signer, "signTransaction"> = {
    signTransaction: async (xdrBase64, opts) => {
      calls.push({ xdr: xdrBase64, opts: opts ?? {} });
      if (reply instanceof Error) throw reply;
      return reply;
    },
  };
  return { wallet, calls };
}

function entryWallet(reply: SignAuthEntryResponse | Error) {
  const calls: { xdr: string; opts: SignAuthEntryOptions }[] = [];
  const wallet: Pick<Sep43Signer, "signAuthEntry"> = {
    signAuthEntry: async (authEntryBase64, opts) => {
      calls.push({ xdr: authEntryBase64, opts: opts ?? {} });
      if (reply instanceof Error) throw reply;
      return reply;
    },
  };
  return { wallet, calls };
}

/** What a wallet actually does: return the bytes it was given, plus a signature. */
function signLikeAWallet(envelopeBase64: string): string {
  const env = xdr.TransactionEnvelope.fromXdr(envelopeBase64, "base64");
  if (env.type !== "envelopeTypeTx") throw new Error("fixture is not a v1 envelope");
  const extra = new xdr.DecoratedSignature({ hint: new Uint8Array(4).fill(9), signature: new Uint8Array(64).fill(8) });
  return xdr.TransactionEnvelope.envelopeTypeTx(
    new xdr.TransactionV1Envelope({ tx: env.v1.tx, signatures: [...env.v1.signatures, extra] }),
  ).toXDR("base64");
}

describe("guardSignTransaction", () => {
  it("asks the wallet for exactly the bytes it analyzed", async () => {
    const { wallet, calls } = txWallet({ signedTxXdr: signLikeAWallet(envelope.xdr), signerAddress: "G-signer" });
    const r = await guardSignTransaction(wallet, envelope.xdr, ctx, approve);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.xdr).toBe(envelope.xdr);
    expect(r.outcome).toBe("signed");
    if (r.outcome !== "signed") throw new Error("expected a signature");
    expect(r.analyzedBytesMatch).toBe(true);
    expect(r.signedTxXdr).toBe(signLikeAWallet(envelope.xdr));
    expect(r.signerAddress).toBe("G-signer");
    expect(r.status).toBe(r.analysis.status);
  });

  it("fills in the passphrase it analyzed, and keeps the caller's other options", async () => {
    const { wallet, calls } = txWallet({ signedTxXdr: signLikeAWallet(envelope.xdr) });
    await guardSignTransaction(wallet, envelope.xdr, ctx, approve, { submit: true, address: "G-requested" });
    expect(calls[0]?.opts).toEqual({ submit: true, address: "G-requested", networkPassphrase: TESTNET });
    expect(calls[0]?.opts.networkPassphrase).toBe(ctx.networkPassphrase);
  });

  it("accepts an identical passphrase in the options", async () => {
    const { wallet, calls } = txWallet({ signedTxXdr: signLikeAWallet(envelope.xdr) });
    const r = await guardSignTransaction(wallet, envelope.xdr, ctx, approve, { networkPassphrase: TESTNET });
    expect(r.outcome).toBe("signed");
    expect(calls).toHaveLength(1);
  });

  it("stops before the wallet when the options name another network", async () => {
    const { wallet, calls } = txWallet({ signedTxXdr: signLikeAWallet(envelope.xdr) });
    const r = await guardSignTransaction(wallet, envelope.xdr, ctx, approve, { networkPassphrase: "Public Global Stellar Network ; September 2015" });
    expect(r).toMatchObject({ outcome: "not_signed", reason: "network_mismatch", walletError: null });
    expect(calls).toHaveLength(0);
  });

  it("does not sign on a declined review", async () => {
    const { wallet, calls } = txWallet({ signedTxXdr: signLikeAWallet(envelope.xdr) });
    const r = await guardSignTransaction(wallet, envelope.xdr, ctx, () => false);
    expect(r).toMatchObject({ outcome: "not_signed", reason: "review_declined", walletError: null });
    expect(calls).toHaveLength(0);
  });

  it("treats a review that throws as a refusal", async () => {
    const { wallet, calls } = txWallet({ signedTxXdr: signLikeAWallet(envelope.xdr) });
    const r = await guardSignTransaction(wallet, envelope.xdr, ctx, () => {
      throw new Error("the UI could not show the findings");
    });
    expect(r.outcome).toBe("not_signed");
    expect(calls).toHaveLength(0);
  });

  it("only proceeds on exactly true, not on another truthy value", async () => {
    const { wallet, calls } = txWallet({ signedTxXdr: signLikeAWallet(envelope.xdr) });
    const r = await guardSignTransaction(wallet, envelope.xdr, ctx, (() => "yes") as unknown as typeof approve);
    expect(r.outcome).toBe("not_signed");
    expect(calls).toHaveLength(0);
  });

  it("shows the review the analysis of an envelope it could not analyze", async () => {
    const seen: string[] = [];
    const { wallet } = txWallet({ signedTxXdr: envelope.xdr });
    await guardSignTransaction(wallet, "not valid base64 %%%%", ctx, (a) => {
      seen.push(a.status);
      return false;
    });
    expect(seen).toEqual(["unanalyzable"]);
  });

  it("passes a wallet's own refusal through, word for word", async () => {
    const { wallet } = txWallet({ error: { message: "User rejected the transaction", code: -4 } });
    const r = await guardSignTransaction(wallet, envelope.xdr, ctx, approve);
    expect(r).toMatchObject({ outcome: "not_signed", reason: "wallet_rejected", walletError: { message: "User rejected the transaction", code: -4 } });
    if (r.outcome !== "not_signed") throw new Error("expected no signature");
    expect(r.status).toBe(r.analysis.status);
  });

  it("treats a wallet that throws as a wallet that did not sign", async () => {
    const { wallet } = txWallet(new Error("the wallet popup crashed"));
    const r = await guardSignTransaction(wallet, envelope.xdr, ctx, approve);
    // Coded, and no text: Guard did not read the exception and does not put words in the wallet's mouth.
    expect(r).toMatchObject({ outcome: "not_signed", reason: "wallet_no_response", walletError: null });
  });

  it("codes an empty response and a malformed error as failures", async () => {
    const empty = await guardSignTransaction(txWallet({}).wallet, envelope.xdr, ctx, approve);
    expect(empty).toMatchObject({ outcome: "not_signed", reason: "wallet_no_signed_bytes", walletError: null });

    const malformed = txWallet({ error: { message: 7, code: "-4" } as unknown as { message: string; code: number } });
    const r = await guardSignTransaction(malformed.wallet, envelope.xdr, ctx, approve);
    expect(r).toMatchObject({ outcome: "not_signed", reason: "wallet_no_signed_bytes", walletError: null });
  });

  it("downgrades to partial when the returned bytes are not what was analyzed", async () => {
    const { wallet } = txWallet({ signedTxXdr: signLikeAWallet(otherTx.xdr), signerAddress: "G-other" });
    const r = await guardSignTransaction(wallet, envelope.xdr, ctx, approve);
    expect(r).toMatchObject({ outcome: "signed_other_bytes", status: "partial", signedTxXdr: signLikeAWallet(otherTx.xdr), signerAddress: "G-other" });
    if (r.outcome !== "signed_other_bytes") throw new Error("expected a downgrade");
    // The earlier analysis is kept as data, but it describes the analyzed envelope, not these bytes.
    expect(r.signedTxXdr).not.toBe(envelope.xdr);
  });

  it("a fee bump over the analyzed inner transaction is other bytes", async () => {
    const { wallet } = txWallet({ signedTxXdr: feeBump.xdr });
    const r = await guardSignTransaction(wallet, envelope.xdr, ctx, approve);
    expect(r.outcome).toBe("signed_other_bytes");
  });

  it("reports no signer address when the wallet omits it", async () => {
    const { wallet } = txWallet({ signedTxXdr: signLikeAWallet(envelope.xdr) });
    const r = await guardSignTransaction(wallet, envelope.xdr, ctx, approve);
    if (r.outcome !== "signed") throw new Error("expected a signature");
    expect(r.signerAddress).toBeNull();
  });
});

describe("guardSignAuthEntry", () => {
  it("signs the entry it analyzed once the wallet fills in its signature", async () => {
    const { wallet, calls } = entryWallet({ signedAuthEntry: signedAuthEntry.xdr, signerAddress: "G-signer" });
    const r = await guardSignAuthEntry(wallet, authEntry.xdr, ctx, approve);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.xdr).toBe(authEntry.xdr);
    if (r.outcome !== "signed") throw new Error(`expected a signature, got ${r.outcome}`);
    expect(r.analyzedBytesMatch).toBe(true);
    expect(r.signerAddress).toBe("G-signer");
  });

  it("an entry analysis is partial even when the wallet signs it", async () => {
    const { wallet } = entryWallet({ signedAuthEntry: signedAuthEntry.xdr });
    const r = await guardSignAuthEntry(wallet, authEntry.xdr, ctx, approve);
    if (r.outcome !== "signed") throw new Error("expected a signature");
    expect(r.status).toBe("partial");
    expect(r.analysis.status).toBe("partial");
    expect(r.analysis.notChecked).toContain("NC-EXECUTION-TIME");
  });

  it("passes the analyzed passphrase and the caller's options to the wallet", async () => {
    const { wallet, calls } = entryWallet({ signedAuthEntry: signedAuthEntry.xdr });
    await guardSignAuthEntry(wallet, authEntry.xdr, ctx, approve, { address: "G-requested" });
    expect(calls[0]?.opts).toEqual({ address: "G-requested", networkPassphrase: TESTNET });
  });

  it("stops before the wallet on a network conflict or a declined review", async () => {
    const mismatch = entryWallet({ signedAuthEntry: signedAuthEntry.xdr });
    const a = await guardSignAuthEntry(mismatch.wallet, authEntry.xdr, ctx, approve, { networkPassphrase: "Standalone Network ; February 2017" });
    expect(a).toMatchObject({ outcome: "not_signed", reason: "network_mismatch" });
    expect(mismatch.calls).toHaveLength(0);

    const declined = entryWallet({ signedAuthEntry: signedAuthEntry.xdr });
    const b = await guardSignAuthEntry(declined.wallet, authEntry.xdr, ctx, () => false);
    expect(b).toMatchObject({ outcome: "not_signed", reason: "review_declined" });
    expect(declined.calls).toHaveLength(0);
  });

  it("reports a wallet error, resolved or thrown", async () => {
    const refused = entryWallet({ error: { message: "User rejected the request", code: -3 } });
    const a = await guardSignAuthEntry(refused.wallet, authEntry.xdr, ctx, approve);
    expect(a).toMatchObject({ outcome: "not_signed", reason: "wallet_rejected", walletError: { message: "User rejected the request", code: -3 } });

    const crashed = entryWallet(new Error("no key in the device"));
    const b = await guardSignAuthEntry(crashed.wallet, authEntry.xdr, ctx, approve);
    expect(b).toMatchObject({ outcome: "not_signed", reason: "wallet_no_response", walletError: null });

    const blank = entryWallet({});
    const c = await guardSignAuthEntry(blank.wallet, authEntry.xdr, ctx, approve);
    expect(c).toMatchObject({ outcome: "not_signed", reason: "wallet_no_signed_bytes", walletError: null });
  });

  it("downgrades to partial when the returned entry is not the analyzed one", async () => {
    const { wallet } = entryWallet({ signedAuthEntry: otherAuthEntry.xdr });
    const r = await guardSignAuthEntry(wallet, authEntry.xdr, ctx, approve);
    expect(r).toMatchObject({ outcome: "signed_other_bytes", status: "partial", signedAuthEntry: otherAuthEntry.xdr });
    if (r.outcome !== "signed_other_bytes") throw new Error("expected a downgrade");
    expect(r.analysis.address).toEqual({ kind: "account", account: expect.any(String), muxedId: null });
  });

  it("a bare signature is checked against the analyzed entry's payload, not called unknowable", async () => {
    // Freighter reads the parameter as the entry's preimage and hands back 64
    // bytes. Those bytes are checkable: either the key the credentials name
    // signed this entry's payload or it did not. The findings must survive either way.
    const signatureOnly = btoa(String.fromCharCode(...new Uint8Array(64).fill(8)));
    const { wallet, calls } = entryWallet({ signedAuthEntry: signatureOnly, signerAddress: "G-signer" });
    const r = await guardSignAuthEntry(wallet, authEntry.xdr, ctx, approve);
    expect(calls[0]?.xdr).toBe(authEntry.xdr);
    expect(r).toMatchObject({ outcome: "signed_preimage_mismatch", status: "partial", signature: signatureOnly });
    if (r.outcome !== "signed_preimage_mismatch") throw new Error("expected a mismatch");
    // The wallet's own claim about who signed is not what the verdict rests on.
    expect(r.signerAddress).toBe("G-signer");
    expect(r.analysis.notChecked).toContain("NC-EXECUTION-TIME");
  });

  it("verifies a bare signature the analyzed entry's own key made", async () => {
    const signature = signPreimage(signableAuthEntry.xdr, testKey(1));
    const { wallet } = entryWallet({ signedAuthEntry: signature });
    const r = await guardSignAuthEntry(wallet, signableAuthEntry.xdr, ctx, approve);
    expect(r).toMatchObject({ outcome: "signed_preimage_verified", signature, authorizedBy: testKey(1).publicKey(), signerAddress: null });
    if (r.outcome !== "signed_preimage_verified") throw new Error("expected a verified reply");
    expect(r.status).toBe(r.analysis.status);
    expect(r.analysis.notChecked).toContain("NC-EXECUTION-TIME");
  });

  it.each(["nonce", "expiry", "tree"] as const)("is a mismatch once the %s the payload commits to changes", async (what) => {
    const signature = signPreimage(signableAuthEntry.xdr, testKey(1));
    const mutated = change(signableAuthEntry.xdr, what);
    const { wallet, calls } = entryWallet({ signedAuthEntry: signature });
    const r = await guardSignAuthEntry(wallet, mutated, ctx, approve);
    // The user saw one entry; these are the bytes that would go on the network.
    expect(calls[0]?.xdr).toBe(mutated);
    expect(r).toMatchObject({ outcome: "signed_preimage_mismatch", status: "partial", authorizedBy: testKey(1).publicKey() });
  });

  it("is a mismatch for a signature by another key, or for another network", async () => {
    for (const signature of [signPreimage(signableAuthEntry.xdr, testKey(2)), signPreimage(signableAuthEntry.xdr, testKey(1), PUBLIC)]) {
      const { wallet } = entryWallet({ signedAuthEntry: signature });
      const r = await guardSignAuthEntry(wallet, signableAuthEntry.xdr, ctx, approve);
      expect(r).toMatchObject({ outcome: "signed_preimage_mismatch", status: "partial", authorizedBy: testKey(1).publicKey() });
    }
  });

  it("an entry whose credentials name no ed25519 key, or no signature at all, stays unverifiable", async () => {
    const signatureOnly = btoa(String.fromCharCode(...new Uint8Array(64).fill(8)));
    const cases: [string, string][] = [
      [otherAuthEntry.xdr, "credential_not_ed25519"],
      [sourceAccountAuthEntry.xdr, "credential_has_no_signature"],
    ];
    for (const [entry, reason] of cases) {
      const { wallet } = entryWallet({ signedAuthEntry: signatureOnly });
      const r = await guardSignAuthEntry(wallet, entry, ctx, approve);
      expect(r).toMatchObject({ outcome: "signed_unverifiable", status: "partial", reason });
    }
  });

  it("a reply that is neither an entry nor signature-length is still partial", async () => {
    for (const junk of ["AAAA", "not base64 %%%%", btoa("a signature shorter than 64 bytes")]) {
      const { wallet } = entryWallet({ signedAuthEntry: junk });
      const r = await guardSignAuthEntry(wallet, authEntry.xdr, ctx, approve);
      expect(r).toMatchObject({ outcome: "signed_unverifiable", status: "partial", signedAuthEntry: junk, reason: "reply_not_a_signature" });
    }
  });

  it("an entry Guard could not analyze never ends as a clean result", async () => {
    const { wallet } = entryWallet({ signedAuthEntry: signedAuthEntry.xdr });
    const r = await guardSignAuthEntry(wallet, "not base64 %%%%", ctx, (a) => {
      expect(a.status).toBe("unanalyzable");
      expect(a.notChecked).toEqual(["NC-DECODE"]);
      return true;
    });
    // Nothing about these bytes was analyzed, so they cannot match what was.
    expect(r).toMatchObject({ outcome: "signed_other_bytes", status: "partial" });
  });
});
