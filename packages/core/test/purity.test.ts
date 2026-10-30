import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { analyze, decodeForAnalysis } from "../src/index.ts";
import type { AnalysisInput, AnalysisResult, AnalyzeContext } from "../src/index.ts";
import { deriveEffects } from "../src/effects/derive.ts";
import type { ContractEffects } from "../src/effects/contract.ts";
import type { EffectsResult } from "../src/index.ts";

/**
 * Guards against the aliasing class the JS SDK's `txnbuild` is built on: there,
 * `Operation.toXDR()` writes back into the operation and `fromXDR` merges into
 * the receiver, so a second use of an object sees the first use's leftovers.
 * Guard must never do that, because a wallet analyzes a transaction, then
 * re-analyzes what comes back signed, and both readings have to be independent.
 */

const FIXTURES = new URL("../../../fixtures/tx/", import.meta.url);

const ENVELOPES = [
  "benign/payment_native.json",
  "benign/set_options_add_signer.json",
  "benign/change_trust.json",
  "benign/path_payment_strict_receive.json",
  // A decode-only operation: the fixture that populates `uncovered`.
  "benign/decode_only_bump_sequence.json",
  "hostile/fee_bump.json",
  "hostile/op_source_other_account.json",
  // The fixture for the SDK's own failure mode: SetOptions fields buried in padding.
  "hostile/padding_buried_set_options.json",
];

function fixture(name: string): { xdr: string; network_passphrase: string } {
  return JSON.parse(readFileSync(new URL(name, FIXTURES), "utf8")) as { xdr: string; network_passphrase: string };
}

function inputOf(name: string): AnalysisInput {
  const f = fixture(name);
  const res = decodeForAnalysis(f.xdr, f.network_passphrase);
  if (!res.ok) throw new Error(`${name}: ${res.reason}`);
  return res.input;
}

/**
 * Freezes a value recursively so that any write to it throws. Applied to the
 * plain objects Guard itself built (`tx`, `ContractEffects`): js-xdr owns how
 * `xdr.Operation` instances are populated, and its buffers cannot be frozen.
 */
function freezeDeep<T>(value: unknown): T {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value)) freezeDeep(child);
  }
  return Object.freeze(value) as T;
}

/** A frozen input whose decoded side cannot accept writes without throwing. */
function frozenInput(name: string): AnalysisInput {
  const input = inputOf(name);
  freezeDeep(input.tx);
  return Object.freeze({ operations: input.operations, tx: input.tx });
}

describe("decode and effects do not reuse or mutate the objects they are given", () => {
  it.each(ENVELOPES)("decoding %s twice describes the same transaction", (name) => {
    const f = fixture(name);
    const first = decodeForAnalysis(f.xdr, f.network_passphrase);
    const second = decodeForAnalysis(f.xdr, f.network_passphrase);
    if (!first.ok || !second.ok) throw new Error("fixture did not decode");
    expect(second.input.tx).toEqual(first.input.tx);
    // A fresh object per call: one caller's result must not be another's alias.
    expect(second.input.tx).not.toBe(first.input.tx);
    expect(second.input.operations).not.toBe(first.input.operations);
  });

  it.each(ENVELOPES)("deriving effects for %s does not write into its input", (name) => {
    const input = frozenInput(name);
    expect(() => deriveEffects(input)).not.toThrow();
  });

  it.each(ENVELOPES)("deriving effects for %s twice gives the same effects, as fresh objects", (name) => {
    const input = inputOf(name);
    const first = deriveEffects(input);
    const second = deriveEffects(input);
    expect(second).toEqual(first);
    expect(second.effects).not.toBe(first.effects);
    expect(second.effects[0]).not.toBe(first.effects[0]);
    expect(second.accountEffects).not.toBe(first.accountEffects);
    expect(second.uncovered).not.toBe(first.uncovered);
    expect(second.uncovered.length > 0 || second.effects.length > 0).toBe(true);
  });

  it("aggregating a contract delta does not rewrite the contract effects it came from", () => {
    // Only an invokeHostFunction consumes `contract`, so the fixture must have one.
    const input = inputOf("benign/invoke_contract.json");
    const source = input.tx.source.account;
    // One aggregation key (account, asset, assurance) for both, so the second
    // delta is merged into the first: exactly where a shared object gets rewritten.
    const contract = freezeDeep<ContractEffects>({
      complete: true,
      deltas: [
        { account: source, asset: "native", min: -500n, max: -500n, assurance: "contract_reported" },
        { account: source, asset: "native", min: 1_000n, max: null, assurance: "contract_reported" },
      ],
    });
    const pristine = structuredClone(contract);

    const first = deriveEffects(input, contract);
    expect(contract).toEqual(pristine);
    expect(deriveEffects(input, contract)).toEqual(first);
  });

  it("analyze twice on one context returns the same result and leaves the context alone", () => {
    const f = fixture("benign/set_options_add_signer.json");
    const ctx = freezeDeep<AnalyzeContext>({ networkPassphrase: f.network_passphrase, asOf: new Date(0) });
    const first = analyze(f.xdr, ctx);
    const second = analyze(f.xdr, ctx);
    expect(second).toEqual(first);
    expect(second).not.toBe(first);
  });

  it("effects derived after another transaction do not inherit its operations", () => {
    // The receiver-reuse failure shows up as one transaction's operations
    // surviving into the next, so the pair must stay distinct in both directions.
    const payment = inputOf("benign/payment_native.json");
    const setOptions = inputOf("benign/set_options_add_signer.json");
    const before: EffectsResult = deriveEffects(payment);
    deriveEffects(setOptions);
    expect(deriveEffects(payment)).toEqual(before);
    const beforeOptions: EffectsResult = deriveEffects(setOptions);
    deriveEffects(payment);
    expect(deriveEffects(setOptions)).toEqual(beforeOptions);
    expect(before.accountEffects).toEqual([]);
    expect(beforeOptions.accountEffects.length).toBeGreaterThan(0);
  });

  it("an AnalysisResult is not shared between two envelopes", () => {
    const a = fixture("benign/payment_native.json");
    const b = fixture("benign/account_merge.json");
    const first: AnalysisResult = analyze(a.xdr, { networkPassphrase: a.network_passphrase });
    const second: AnalysisResult = analyze(b.xdr, { networkPassphrase: b.network_passphrase });
    expect(second.txHash).not.toBe(first.txHash);
    analyze(a.xdr, { networkPassphrase: a.network_passphrase });
    expect(second.txHash).not.toBe(first.txHash);
  });
});
