import { readFileSync } from "node:fs";

import { Account, Keypair, Networks, Operation, TransactionBuilder } from "@stellar/stellar-sdk/base";
import { describe, expect, it } from "vitest";

import { analyze } from "../src/index.ts";
import type { AnalysisResult, Finding } from "../src/index.ts";
import { FAR_FUTURE_SECONDS } from "../src/rules/no-expiry.ts";

const FIXTURES = new URL("../../../fixtures/tx/", import.meta.url);
const key = (b: number) => Keypair.fromRawEd25519Seed(new Uint8Array(32).fill(b));
const S = key(1).publicKey();
const OTHER = key(2).publicKey();
const MIN_TIME = 1_793_059_200; // fixture bounds: MIN_TIME .. MIN_TIME + 300

function load(fixture: string) {
  return JSON.parse(readFileSync(new URL(fixture, FIXTURES), "utf8")) as { xdr: string; network_passphrase: string };
}

function run(fixture: string, asOf?: Date): AnalysisResult {
  const f = load(fixture);
  return analyze(f.xdr, asOf === undefined ? { networkPassphrase: f.network_passphrase } : { networkPassphrase: f.network_passphrase, asOf });
}

const codes = (r: AnalysisResult) => r.findings.map((f) => `${f.code}:${f.severity}`);

describe("G-SIGNER-ADDED", () => {
  it("an added ed25519 signer is high", () => {
    expect(run("benign/set_options_add_signer.json").findings).toEqual<Finding[]>([
      {
        code: "G-SIGNER-ADDED",
        severity: "high",
        operationIndex: 0,
        facts: { account: S, signer: OTHER, signer_type: "ed25519", weight: "1" },
        statement: null,
      },
    ]);
  });

  it("a hash(x) signer is critical", () => {
    const [f] = run("hostile/hashx_signer.json").findings;
    expect(f).toMatchObject({ code: "G-SIGNER-ADDED", severity: "critical", facts: { signer_type: "hash_x" } });
  });
});

describe("G-ACCOUNT-CONTROL", () => {
  it("the buried takeover is reported, most severe first, at its real operation index", () => {
    const r = run("hostile/padding_buried_set_options.json");
    expect(codes(r)).toEqual(["G-ACCOUNT-CONTROL:critical", "G-SIGNER-ADDED:high"]);
    expect(r.findings[0]).toMatchObject({ operationIndex: 49, facts: { account: S, master_weight: "0" } });
    expect(r.operationCount).toBe(50);
  });

  it("removing a signer is account control, not signer added", () => {
    const tx = new TransactionBuilder(new Account(S, "1"), { fee: "100", networkPassphrase: Networks.TESTNET })
      .setTimebounds(MIN_TIME, MIN_TIME + 300)
      .addOperation(Operation.setOptions({ signer: { ed25519PublicKey: OTHER, weight: 0 } }))
      .build();
    const r = analyze(tx.toXDR(), { networkPassphrase: Networks.TESTNET });
    expect(r.findings).toEqual<Finding[]>([
      {
        code: "G-ACCOUNT-CONTROL",
        severity: "critical",
        operationIndex: 0,
        facts: { account: S, removed_signer: OTHER, signer_type: "ed25519" },
        statement: null,
      },
    ]);
  });

  it("plain payments and trustlines raise no control findings", () => {
    for (const f of ["benign/payment_native.json", "benign/change_trust.json", "benign/account_merge.json"]) {
      expect(codes(run(f)).filter((c) => !c.startsWith("G-NO-EXPIRY")), f).toEqual([]);
    }
  });
});

describe("G-NO-EXPIRY", () => {
  it("no upper time bound is medium", () => {
    expect(run("hostile/no_time_bounds.json").findings).toEqual<Finding[]>([
      { code: "G-NO-EXPIRY", severity: "medium", operationIndex: null, facts: { max_time: "none" }, statement: null },
    ]);
  });

  it("a short window raises nothing, with or without asOf", () => {
    expect(run("benign/payment_native.json").findings).toEqual([]);
    expect(run("benign/payment_native.json", new Date(MIN_TIME * 1000)).findings).toEqual([]);
  });

  it("a bound more than seven days after asOf counts as no expiry", () => {
    const asOf = BigInt(MIN_TIME + 300) - FAR_FUTURE_SECONDS - 1n;
    const r = run("benign/payment_native.json", new Date(Number(asOf) * 1000));
    expect(r.findings).toEqual<Finding[]>([
      {
        code: "G-NO-EXPIRY",
        severity: "medium",
        operationIndex: null,
        facts: { max_time: String(MIN_TIME + 300), as_of: asOf.toString() },
        statement: null,
      },
    ]);
    // Exactly at the limit is not flagged.
    expect(run("benign/payment_native.json", new Date(Number(asOf + 1n) * 1000)).findings).toEqual([]);
  });

  it("an invalid asOf is ignored, not treated as epoch zero", () => {
    expect(run("benign/payment_native.json", new Date(Number.NaN)).findings).toEqual([]);
  });
});

describe("findings never imply a clean result", () => {
  it("critical findings still report partial while counterparties are unchecked", () => {
    const r = run("hostile/padding_buried_set_options.json");
    expect(r.status).toBe("partial");
    expect(r.findings.every((f) => f.statement === null)).toBe(true);
  });
});
