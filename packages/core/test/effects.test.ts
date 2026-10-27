import { readFileSync } from "node:fs";

import {
  Account,
  Keypair,
  Networks,
  TransactionBuilder,
  decodeAddressToMuxedAccount,
  xdr,
} from "@stellar/stellar-sdk/base";
import { describe, expect, it } from "vitest";

import { decodeForAnalysis, deriveEffects } from "../src/index.ts";
import type { BalanceEffect, EffectsResult } from "../src/index.ts";

const FIXTURES = new URL("../../../fixtures/tx/", import.meta.url);

// Same fixed test-only keys as scripts/gen-fixtures.ts.
const key = (b: number) => Keypair.fromRawEd25519Seed(new Uint8Array(32).fill(b));
const S = key(1).publicKey();
const OTHER = key(2).publicKey();
const ISSUER = key(3).publicKey();
const FEE_PAYER = key(4).publicKey();
const USDC = `USDC:${ISSUER}`;

function effectsOf(fixture: string): EffectsResult {
  const f = JSON.parse(readFileSync(new URL(fixture, FIXTURES), "utf8")) as { xdr: string; network_passphrase: string };
  const res = decodeForAnalysis(f.xdr, f.network_passphrase);
  if (!res.ok) throw new Error(res.reason);
  return deriveEffects(res.input);
}

const eff = (account: string, asset: string, deltaMin: bigint, deltaMax: bigint | null): BalanceEffect => ({
  account,
  asset,
  deltaMin,
  deltaMax,
  assurance: "ledger",
});

describe("balance effects", () => {
  it("payment: sender loses amount plus up to the fee, receiver gains amount", () => {
    expect(effectsOf("benign/payment_native.json")).toEqual({
      effects: [eff(S, "native", -125_000_100n, -125_000_000n), eff(OTHER, "native", 125_000_000n, 125_000_000n)],
      accountEffects: [],
      uncovered: [],
    });
  });

  it("create account moves the starting balance", () => {
    expect(effectsOf("benign/create_account.json").effects).toEqual([
      eff(S, "native", -20_000_100n, -20_000_000n),
      eff(OTHER, "native", 20_000_000n, 20_000_000n),
    ]);
  });

  it("strict receive: sender authorizes up to sendMax (worst case first)", () => {
    expect(effectsOf("benign/path_payment_strict_receive.json").effects).toEqual([
      eff(S, "native", -1_000_000_100n, 0n),
      eff(OTHER, USDC, 100_000_000n, 100_000_000n),
    ]);
  });

  it("strict send: receiver gets at least destMin with no upper bound", () => {
    expect(effectsOf("benign/path_payment_strict_send.json").effects).toEqual([
      eff(S, USDC, -100_000_000n, -100_000_000n),
      eff(S, "native", -100n, 0n),
      eff(OTHER, "native", 500_000_000n, null),
    ]);
  });

  it("fee bump: the outer fee source pays the fee, the inner source only the payment", () => {
    const r = effectsOf("hostile/fee_bump.json");
    expect(r.effects.find((e) => e.account === S)).toEqual(eff(S, "native", -10_000_000n, -10_000_000n));
    const fee = r.effects.find((e) => e.account === FEE_PAYER);
    expect(fee?.deltaMax).toBe(0n);
    expect(fee?.deltaMin).toBeLessThan(0n);
  });

  it("an operation with its own source moves that account's funds, not the signer's", () => {
    expect(effectsOf("hostile/op_source_other_account.json").effects).toEqual([
      eff(ISSUER, USDC, -50_000_000n, -50_000_000n),
      eff(S, "native", -100n, 0n),
      eff(OTHER, USDC, 50_000_000n, 50_000_000n),
    ]);
  });

  it("muxed source is normalized to its G account", () => {
    expect(effectsOf("hostile/muxed_source.json").effects[0]?.account).toBe(S);
  });

  it("buried account-control change surfaces as signer and threshold effects", () => {
    const r = effectsOf("hostile/padding_buried_set_options.json");
    expect(r.uncovered).toEqual([]);
    // 49 one-stroop payments plus a fee of 100 stroops per operation (50 operations).
    expect(r.effects[0]).toEqual(eff(S, "native", -5_049n, -49n));
    expect(r.accountEffects).toEqual([
      { kind: "signer", operationIndex: 49, account: S, signer: OTHER, signerType: "ed25519", weight: 255 },
      { kind: "thresholds", operationIndex: 49, account: S, masterWeight: 0, low: null, medium: null, high: null },
    ]);
  });

  it("change trust adds a trustline with the default maximum limit", () => {
    const r = effectsOf("benign/change_trust.json");
    expect(r.uncovered).toEqual([]);
    expect(r.accountEffects).toEqual([
      { kind: "trustline", operationIndex: 0, account: S, asset: USDC, limit: 9_223_372_036_854_775_807n },
    ]);
  });

  it("set options reports the added ed25519 signer", () => {
    expect(effectsOf("benign/set_options_add_signer.json").accountEffects).toEqual([
      { kind: "signer", operationIndex: 0, account: S, signer: OTHER, signerType: "ed25519", weight: 1 },
    ]);
  });

  it("a hash(x) signer is typed as hash_x", () => {
    const [e] = effectsOf("hostile/hashx_signer.json").accountEffects;
    expect(e).toMatchObject({ kind: "signer", signerType: "hash_x", weight: 1 });
    expect(e?.kind === "signer" && e.signer.startsWith("X")).toBe(true);
  });

  it("account merge moves the whole native balance to the destination", () => {
    const r = effectsOf("benign/account_merge.json");
    expect(r.uncovered).toEqual([]);
    expect(r.accountEffects).toEqual([{ kind: "merge", operationIndex: 0, account: S, destination: OTHER }]);
  });

  it("operations without derived effects are listed as uncovered", () => {
    for (const f of ["benign/invoke_contract.json", "benign/manage_data_decode_only.json", "benign/decode_only_clawback.json"]) {
      expect(effectsOf(f).uncovered).toEqual([{ index: 0, reason: "not_derived_yet" }]);
    }
  });

  it("is deterministic", () => {
    expect(effectsOf("hostile/op_source_other_account.json")).toEqual(effectsOf("hostile/op_source_other_account.json"));
  });
});

describe("hostile operations", () => {
  function rawOp(body: xdr.OperationBody) {
    const tx = new TransactionBuilder(new Account(S, "1"), { fee: "100", networkPassphrase: Networks.TESTNET })
      .setTimebounds(0, 1)
      .addOperation(new xdr.Operation({ sourceAccount: null, body }))
      .build();
    return decodeForAnalysis(tx.toXDR(), Networks.TESTNET);
  }

  const setOpts = (over: Partial<Record<"masterWeight" | "lowThreshold" | "highThreshold", number>>, signerWeight?: number) =>
    xdr.OperationBody.setOptions(
      new xdr.SetOptionsOp({
        inflationDest: null,
        clearFlags: null,
        setFlags: null,
        masterWeight: over.masterWeight ?? null,
        lowThreshold: over.lowThreshold ?? null,
        medThreshold: null,
        highThreshold: over.highThreshold ?? null,
        homeDomain: null,
        signer:
          signerWeight === undefined
            ? null
            : new xdr.Signer({ key: xdr.SignerKey.signerKeyTypeEd25519(key(2).rawPublicKey()), weight: signerWeight }),
      }),
    );

  it.each([
    ["master weight 256", () => rawOp(setOpts({ masterWeight: 256 }))],
    ["high threshold 1000", () => rawOp(setOpts({ highThreshold: 1000 }))],
    ["signer weight 300", () => rawOp(setOpts({}, 300))],
    ["negative trustline limit", () => rawOp(xdr.OperationBody.changeTrust(new xdr.ChangeTrustOp({ line: xdr.ChangeTrustAsset.assetTypeNative(), limit: -1n })))],
    ["trustline to the native asset", () => rawOp(xdr.OperationBody.changeTrust(new xdr.ChangeTrustOp({ line: xdr.ChangeTrustAsset.assetTypeNative(), limit: 5n })))],
  ])("%s is marked invalid, never a clean effect", (_n, build) => {
    // The SDK builds and decodes these, so Guard's own range checks must catch them.
    const res = build();
    if (!res.ok) throw new Error(res.reason);
    const r = deriveEffects(res.input);
    expect(r.uncovered).toEqual([{ index: 0, reason: "invalid_operation" }]);
    expect(r.accountEffects).toEqual([]);
  });

  function rawPayment(asset: xdr.Asset, amount: bigint): EffectsResult {
    const op = new xdr.Operation({
      sourceAccount: null,
      body: xdr.OperationBody.payment(
        new xdr.PaymentOp({ destination: decodeAddressToMuxedAccount(OTHER), asset, amount }),
      ),
    });
    const tx = new TransactionBuilder(new Account(S, "1"), { fee: "100", networkPassphrase: Networks.TESTNET })
      .setTimebounds(0, 1)
      .addOperation(op)
      .build();
    const res = decodeForAnalysis(tx.toXDR(), Networks.TESTNET);
    if (!res.ok) throw new Error(res.reason);
    return deriveEffects(res.input);
  }

  const credit4 = (code: string | Uint8Array) =>
    xdr.Asset.assetTypeCreditAlphanum4(new xdr.AlphaNum4({ assetCode: new xdr.AssetCode4(code), issuer: key(3).xdrAccountId() }));

  it.each([
    ["negative amount", xdr.Asset.assetTypeNative(), -5n],
    ["zero amount", xdr.Asset.assetTypeNative(), 0n],
  ])("%s is invalid, not a reversed effect", (_n, asset, amount) => {
    const r = rawPayment(asset, amount);
    expect(r.uncovered).toEqual([{ index: 0, reason: "invalid_operation" }]);
    expect(r.effects).toEqual([eff(S, "native", -100n, 0n)]);
  });

  // The SDK will not build these, but a dApp can still hand over such bytes.
  // Build a valid "USD" payment, then patch the code bytes in the XDR.
  it.each([
    ["punctuation", [0x55, 0x24, 0x44, 0]],
    ["all zero bytes", [0, 0, 0, 0]],
    ["control character", [0x55, 0x0a, 0x44, 0]],
  ])("asset code with %s never yields a clean effect", (_n, code) => {
    const op = new xdr.Operation({
      sourceAccount: null,
      body: xdr.OperationBody.payment(
        new xdr.PaymentOp({ destination: decodeAddressToMuxedAccount(OTHER), asset: credit4("USD"), amount: 1n }),
      ),
    });
    const tx = new TransactionBuilder(new Account(S, "1"), { fee: "100", networkPassphrase: Networks.TESTNET })
      .setTimebounds(0, 1)
      .addOperation(op)
      .build();
    const bytes = Uint8Array.from(atob(tx.toXDR()), (c) => c.charCodeAt(0));
    const at = bytes.findIndex((_, i) => bytes[i] === 0x55 && bytes[i + 1] === 0x53 && bytes[i + 2] === 0x44 && bytes[i + 3] === 0);
    expect(at).toBeGreaterThan(0);
    bytes.set(code, at);
    const res = decodeForAnalysis(btoa(String.fromCharCode(...bytes)), Networks.TESTNET);
    if (res.ok) {
      expect(deriveEffects(res.input).uncovered).toEqual([{ index: 0, reason: "invalid_operation" }]);
    } else {
      expect(res.reason).toBe("decode_failed");
    }
  });

  it("accepts a short zero-padded code", () => {
    expect(rawPayment(credit4("USD"), 7n).effects.map((e) => e.asset)).toContain(`USD:${ISSUER}`);
  });
});
