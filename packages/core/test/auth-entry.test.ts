import { readdirSync, readFileSync } from "node:fs";

import { Contract, Keypair, StrKey, xdr } from "@stellar/stellar-sdk/base";
import { describe, expect, it } from "vitest";

import {
  MAX_AUTH_ENTRY_BASE64_LENGTH,
  MAX_DELEGATE_SIGNATURES,
  MAX_INVOCATION_DEPTH,
  MAX_INVOCATION_NODES,
  analyzeAuthEntry,
  canonicalKey,
  decodeAuthEntry,
  isAuthEntry,
  isSignatureLength,
  sameAuthEntry,
  sameTransactionPayload,
  snapshotHash,
  snapshotPayload,
  type AnalyzeContext,
  type AuthEntryAnalysisResult,
  type DecodedAuthEntry,
  type Snapshot,
} from "../src/index.ts";

const FIXTURES = new URL("../../../fixtures/auth_entry/", import.meta.url);
const TX_FIXTURES = new URL("../../../fixtures/tx/", import.meta.url);

// Fixture keys (scripts/gen-fixtures.ts) and Intel's test snapshot key (seed 0x07 x32).
const key = (b: number) => Keypair.fromRawEd25519Seed(new Uint8Array(32).fill(b));
const CONTRACT = StrKey.encodeContract(new Uint8Array(32).fill(7));
const SNAPSHOT_KEY = key(7);
const PINNED = { "test-key-1": SNAPSHOT_KEY.rawPublicKey() };

const MIN_TIME = 1_793_059_200;
const GENERATED = new Date(MIN_TIME * 1000);
const AS_OF = new Date(MIN_TIME * 1000 + 60_000);
const TESTNET = "Test SDF Network ; September 2015";
const PUBLIC = "Public Global Stellar Network ; September 2015";

interface EntryExpected {
  credential: string;
  address: DecodedAuthEntry["address"];
  nonce: string | null;
  signature_expiration_ledger: number | null;
  delegate_signatures: number;
  invocation_nodes: number;
  contracts: string[];
  contracts_unchecked: boolean;
}

interface EntryFixture {
  name: string;
  network_passphrase: string;
  xdr: string;
  expected: { unanalyzable: string } | EntryExpected;
}

function load(dir: "benign" | "hostile"): EntryFixture[] {
  const base = new URL(`${dir}/`, FIXTURES);
  return readdirSync(base)
    .filter((f) => f.endsWith(".json"))
    .sort()
    .map((f) => JSON.parse(readFileSync(new URL(f, base), "utf8")) as EntryFixture);
}

const isExpected = (e: EntryFixture["expected"]): e is EntryExpected => !("unanalyzable" in e);

const benign = load("benign");
const hostile = load("hostile");
const fixtures = [...benign, ...hostile];

/** The fixtures Guard refuses to analyze, with the reason each one must report. */
const unanalyzable = hostile.flatMap((f): { name: string; xdr: string; networkPassphrase: string; reason: string }[] =>
  isExpected(f.expected) ? [] : [{ name: f.name, xdr: f.xdr, networkPassphrase: f.network_passphrase, reason: f.expected.unanalyzable }]);

/** Reads a fixture's entry XDR. */
function entryXdr(dir: "benign" | "hostile", name: string): string {
  const f = JSON.parse(readFileSync(new URL(`${dir}/${name}.json`, FIXTURES), "utf8")) as { xdr: string };
  return f.xdr;
}

/** Reports the decoded entry with the fixture's field names, so a comparison is a full check. */
function reported(entry: DecodedAuthEntry) {
  return {
    credential: entry.credential,
    address: entry.address,
    nonce: entry.nonce,
    signature_expiration_ledger: entry.signatureExpirationLedger,
    delegate_signatures: entry.delegateSignatures,
    invocation_nodes: entry.invocationNodes,
    contracts: entry.contracts,
    contracts_unchecked: entry.contractsUnchecked,
  };
}

describe("auth entry fixtures", () => {
  it("covers every credential arm", () => {
    const credentials = benign.flatMap((f) => (isExpected(f.expected) ? [f.expected.credential] : []));
    expect([...new Set(credentials)].sort()).toEqual([
      "sorobanCredentialsAddress",
      "sorobanCredentialsAddressV2",
      "sorobanCredentialsAddressWithDelegates",
      "sorobanCredentialsSourceAccount",
    ]);
  });

  it("covers every address kind an entry can name", () => {
    const kinds = benign.map((f) => (isExpected(f.expected) ? (f.expected.address?.kind ?? "none") : "unreadable"));
    expect([...new Set(kinds)].sort()).toEqual(["account", "claimable_balance", "contract", "liquidity_pool", "none"]);
  });

  it.each(fixtures.map((f) => [f.name, f] as const))("decodes %s", (_name, f) => {
    const res = decodeAuthEntry(f.xdr, f.network_passphrase);
    if (!isExpected(f.expected)) {
      expect(res).toEqual({ ok: false, reason: f.expected.unanalyzable });
      return;
    }
    if (!res.ok) throw new Error(`unexpected unanalyzable: ${res.reason}`);
    expect(reported(res.entry)).toEqual(f.expected);
  });

});

// Builds an entry with a controllable tree, for the caps no fixture carries.
function callNode(): xdr.SorobanAuthorizedInvocation {
  const call = new Contract(CONTRACT).call("transfer");
  const body = call.body;
  if (body.type !== "invokeHostFunction" || body.invokeHostFunctionOp.hostFunction.type !== "hostFunctionTypeInvokeContract") {
    throw new Error("unexpected contract call shape");
  }
  return new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(body.invokeHostFunctionOp.hostFunction.invokeContract),
    subInvocations: [],
  });
}

/** `levels` tall, each node with `branching` children. */
function tree(levels: number, branching: number): xdr.SorobanAuthorizedInvocation {
  const node = callNode();
  return new xdr.SorobanAuthorizedInvocation({
    function: node.function,
    subInvocations: levels > 1 ? Array.from({ length: branching }, () => tree(levels - 1, branching)) : [],
  });
}

function entrySourceAccount(root: xdr.SorobanAuthorizedInvocation): string {
  return new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),
    rootInvocation: root,
  }).toXDR("base64");
}

describe("auth entry caps", () => {
  it("refuses input over the size ceiling before decoding", () => {
    expect(decodeAuthEntry("A".repeat(MAX_AUTH_ENTRY_BASE64_LENGTH + 1), PUBLIC)).toEqual({ ok: false, reason: "input_too_large" });
  });

  it.each(["", "x".repeat(257)])("refuses a passphrase of length %#", (pp) => {
    expect(decodeAuthEntry(entrySourceAccount(tree(1, 0)), pp)).toEqual({ ok: false, reason: "invalid_network_passphrase" });
  });

  it("refuses a tree deeper than the cap and accepts one at the cap", () => {
    expect(decodeAuthEntry(entrySourceAccount(tree(MAX_INVOCATION_DEPTH + 1, 1)), PUBLIC)).toEqual({ ok: false, reason: "input_too_large" });
    const atCap = decodeAuthEntry(entrySourceAccount(tree(MAX_INVOCATION_DEPTH, 1)), PUBLIC);
    expect(atCap.ok && reported(atCap.entry).invocation_nodes).toBe(MAX_INVOCATION_DEPTH);
  });

  it("refuses a tree with more nodes than the cap", () => {
    // 6 levels, branching 4: 1 + 4 + 16 + 64 + 256 + 1024 nodes, well past the cap
    // and still inside the size ceiling, so this is the node cap refusing it.
    const wide = entrySourceAccount(tree(6, 4));
    expect(wide.length).toBeLessThan(MAX_AUTH_ENTRY_BASE64_LENGTH);
    expect(MAX_INVOCATION_NODES).toBeLessThan(1 + 4 + 16 + 64 + 256 + 1024);
    expect(decodeAuthEntry(wide, PUBLIC)).toEqual({ ok: false, reason: "input_too_large" });
  });

  it("refuses more delegate signatures than the cap", () => {
    const address = xdr.ScAddress.scAddressTypeAccount(xdr.PublicKey.publicKeyTypeEd25519(new Uint8Array(32).fill(2)));
    const creds = new xdr.SorobanAddressCredentials({ address, nonce: 1n, signatureExpirationLedger: 10, signature: xdr.ScVal.scvVoid() });
    const leaf = new xdr.SorobanDelegateSignature({ address, signature: xdr.ScVal.scvVoid(), nestedDelegates: [] });
    const many = new xdr.SorobanAuthorizationEntry({
      credentials: xdr.SorobanCredentials.sorobanCredentialsAddressWithDelegates(
        new xdr.SorobanAddressCredentialsWithDelegates({
          addressCredentials: creds,
          delegates: Array.from({ length: MAX_DELEGATE_SIGNATURES + 1 }, () => leaf),
        }),
      ),
      rootInvocation: callNode(),
    }).toXDR("base64");
    expect(decodeAuthEntry(many, PUBLIC)).toEqual({ ok: false, reason: "input_too_large" });
  });

  it("counts a tree inside both caps", () => {
    // 3 levels, branching 2: 1 + 2 + 4 nodes.
    const res = decodeAuthEntry(entrySourceAccount(tree(3, 2)), PUBLIC);
    expect(res.ok && reported(res.entry).invocation_nodes).toBe(7);
  });

  it("never throws on byte-level mutations of a valid entry", () => {
    const bytes = Uint8Array.from(atob(entrySourceAccount(tree(2, 1))), (c) => c.charCodeAt(0));
    let decoded = 0;
    for (let i = 0; i < bytes.length; i++) {
      for (const flip of [0x01, 0x80, 0xff]) {
        const mutated = bytes.slice();
        const byte = mutated[i];
        if (byte === undefined) continue;
        mutated[i] = byte ^ flip;
        const res = decodeAuthEntry(btoa(String.fromCharCode(...mutated)), PUBLIC);
        if (res.ok) decoded++;
      }
    }
    // Some mutations must still decode (the point is that none of them throw).
    expect(decoded).toBeGreaterThan(0);
  });
});

describe("analyzeAuthEntry", () => {
  function snapshot(flagged: [string, string][], network: "public" | "testnet" = "testnet"): Snapshot {
    const entries = [...new Set(flagged.map(([t, k]) => snapshotHash(canonicalKey(network, t, k))))].sort();
    const s: Snapshot = {
      format_version: 1,
      network,
      version: 1,
      generated_at: GENERATED.toISOString().replace(".000Z", "Z"),
      ruleset_version: "2026.10.1",
      key_id: "test-key-1",
      entries,
      signature: "",
    };
    s.signature = btoa(String.fromCharCode(...SNAPSHOT_KEY.sign(snapshotPayload(s))));
    return s;
  }

  const verified = (flagged: [string, string][]): Pick<AnalyzeContext, "asOf" | "snapshot"> => ({
    asOf: AS_OF,
    snapshot: { data: snapshot(flagged), pinnedKeys: PINNED },
  });

  const run = (name: string, extra: Partial<AnalyzeContext> = {}): AuthEntryAnalysisResult => {
    const ctx: AnalyzeContext = { networkPassphrase: TESTNET, ...extra };
    return analyzeAuthEntry(entryXdr("benign", name), ctx);
  };

  it("an entry is never a complete check, whatever the snapshot says", () => {
    const r = run("credential_address", verified([]));
    expect(r.status).toBe("partial");
    expect(r.notChecked).toEqual(["NC-EXECUTION-TIME", "NC-OPERATION-EFFECTS", "NC-SIMULATION"]);
  });

  it("without a snapshot the counterparties are unchecked", () => {
    const r = run("credential_address");
    expect(r.snapshotStatus).toBe("not_provided");
    expect(r.notChecked).toContain("NC-COUNTERPARTY-SIGNALS");
    expect(r.findings).toEqual([]);
  });

  it("a flagged contract the entry authorizes raises G-CONTRACT-FLAGGED", () => {
    const r = run("credential_address", verified([["contract", CONTRACT]]));
    expect(r.snapshotStatus).toBe("verified");
    expect(r.notChecked).not.toContain("NC-COUNTERPARTY-SIGNALS");
    expect(r.findings).toEqual([
      { code: "G-CONTRACT-FLAGGED", severity: "high", operationIndex: null, facts: { entity_type: "contract", key: CONTRACT, roles: "invoked" }, statement: null },
    ]);
  });

  it("the signing address is reported as data, not as a finding", () => {
    const decoded = decodeAuthEntry(entryXdr("benign", "credential_address"), TESTNET);
    if (!decoded.ok || decoded.entry.address?.kind !== "account") throw new Error("fixture must name an account");
    const signer = decoded.entry.address.account;
    const r = run("credential_address", verified([["account", signer]]));
    // Guard has no finding code for a flagged signing account (AGENTS.md §10); the address is returned so the integrator can decide.
    expect(r.address).toEqual({ kind: "account", account: signer, muxedId: null });
    expect(r.findings).toEqual([]);
  });

  it("reports the credential fields an integrator needs", () => {
    const r = run("credential_address_with_delegates", verified([]));
    expect(r.credential).toBe("sorobanCredentialsAddressWithDelegates");
    expect(r.nonce).not.toBeNull();
    expect(r.signatureExpirationLedger).not.toBeNull();
    expect(r.delegateSignatures).toBeGreaterThan(0);
  });

  it("a tree that creates a contract keeps the counterparty check unchecked", () => {
    const decoded = decodeAuthEntry(entryXdr("benign", "invocation_creates_contract"), TESTNET);
    if (!decoded.ok) throw new Error("fixture must decode");
    expect(decoded.entry.contractsUnchecked).toBe(true);
    const r = run("invocation_creates_contract", verified([]));
    expect(r.contracts).toEqual([]);
    expect(r.notChecked).toContain("NC-COUNTERPARTY-SIGNALS");
  });

  it("an unknown network adds G-NETWORK-UNKNOWN and NC-NETWORK-COVERAGE", () => {
    const ctx: AnalyzeContext = { networkPassphrase: "Standalone Network ; February 2017", ...verified([]) };
    const r = analyzeAuthEntry(entryXdr("benign", "credential_address"), ctx);
    expect(r.network).toBe("unknown");
    expect(r.findings.map((f) => f.code)).toEqual(["G-NETWORK-UNKNOWN"]);
    expect(r.notChecked).toContain("NC-NETWORK-COVERAGE");
    // A snapshot exists but covers no unknown network, so nothing was checked.
    expect(r.snapshotStatus).toBe("not_applicable");
    expect(r.notChecked).toContain("NC-COUNTERPARTY-SIGNALS");
  });

  it("an entry that will not decode is unanalyzable, never clean", () => {
    for (const input of ["", "AAAA", "not base64!"]) {
      const r = analyzeAuthEntry(input, { networkPassphrase: TESTNET });
      expect(r.status).toBe("unanalyzable");
      expect(r.unanalyzableReason).toBe("decode_failed");
      expect(r.credential).toBeNull();
      expect(r.notChecked).toEqual(["NC-DECODE"]);
    }
  });

  it.each(unanalyzable.map((f) => [f.name, f] as const))("hostile fixture %s is unanalyzable with its reason", (_name, f) => {
    const r = analyzeAuthEntry(f.xdr, { networkPassphrase: f.networkPassphrase });
    expect(r.status).toBe("unanalyzable");
    expect(r.unanalyzableReason).toBe(f.reason);
  });
});

describe("signing-payload fidelity: transactions", () => {
  const txFixture = (path: string) =>
    JSON.parse(readFileSync(new URL(path, TX_FIXTURES), "utf8")) as { xdr: string };

  const signed = (name: string) => txFixture(name).xdr;

  /** What a wallet does to the bytes it was shown: add one decorated signature. */
  function addSignature(envelopeBase64: string): string {
    const env = xdr.TransactionEnvelope.fromXdr(envelopeBase64, "base64");
    if (env.type !== "envelopeTypeTx") throw new Error("fixture is not a v1 envelope");
    const extra = new xdr.DecoratedSignature({ hint: new Uint8Array(4).fill(9), signature: new Uint8Array(64).fill(8) });
    return xdr.TransactionEnvelope.envelopeTypeTx(
      new xdr.TransactionV1Envelope({ tx: env.v1.tx, signatures: [...env.v1.signatures, extra] }),
    ).toXDR("base64");
  }

  /** Re-encodes a v1 fixture as the older v0 envelope form, which signs different bytes. */
  function asV0(envelopeBase64: string): string {
    const env = xdr.TransactionEnvelope.fromXdr(envelopeBase64, "base64");
    if (env.type !== "envelopeTypeTx") throw new Error("fixture is not a v1 envelope");
    const t = env.v1.tx;
    if (t.sourceAccount.type !== "keyTypeEd25519") throw new Error("v0 needs a plain source account");
    const timeBounds = t.cond.type === "precondTime" ? t.cond.timeBounds : t.cond.type === "precondV2" ? t.cond.v2.timeBounds : null;
    const v0 = new xdr.TransactionV0({
      sourceAccountEd25519: t.sourceAccount.ed25519.toBytes(),
      fee: t.fee,
      seqNum: t.seqNum,
      timeBounds,
      memo: t.memo,
      operations: t.operations,
      ext: xdr.TransactionV0Ext.v0(),
    });
    return xdr.TransactionEnvelope.envelopeTypeTxV0(new xdr.TransactionV0Envelope({ tx: v0, signatures: env.v1.signatures })).toXDR("base64");
  }

  it("a signature added to the analyzed envelope still matches", () => {
    const f = signed("benign/payment_native.json");
    expect(sameTransactionPayload(f, addSignature(f))).toBe(true);
  });

  it("a different transaction does not match", () => {
    expect(sameTransactionPayload(signed("benign/payment_native.json"), signed("benign/create_account.json"))).toBe(false);
  });

  it("a fee bump is not its own inner transaction", () => {
    expect(sameTransactionPayload(signed("benign/payment_native.json"), signed("hostile/fee_bump.json"))).toBe(false);
  });

  it("a v0 envelope matches itself, not the v1 form of the same transaction", () => {
    const f = signed("benign/payment_native.json");
    const v0 = asV0(f);
    expect(sameTransactionPayload(v0, v0)).toBe(true);
    expect(sameTransactionPayload(f, v0)).toBe(false);
  });

  it("unreadable input is a mismatch, never a match", () => {
    const f = signed("benign/payment_native.json");
    for (const bad of ["", "AAAA", "%%%%", f.slice(0, 20)]) {
      expect(sameTransactionPayload(f, bad)).toBe(false);
      expect(sameTransactionPayload(bad, f)).toBe(false);
    }
  });
});

describe("signing-payload fidelity: auth entries", () => {
  const analyzed = entryXdr("benign", "credential_address");

  it("an entry still matches once the wallet fills in its signature", () => {
    expect(sameAuthEntry(analyzed, entryXdr("hostile", "signature_prefilled"))).toBe(true);
  });

  it("an entry that differs in address, credential arm, nonce or tree does not match", () => {
    for (const name of ["credential_address_v2", "credential_source_account", "address_is_contract", "address_is_muxed", "invocations_nested"]) {
      expect(sameAuthEntry(analyzed, entryXdr("benign", name))).toBe(false);
    }
  });

  it("a signature inside the delegated credentials is normalized too", () => {
    const base = entryXdr("benign", "credential_address_with_delegates");
    const entry = xdr.SorobanAuthorizationEntry.fromXdr(base, "base64");
    if (entry.credentials.type !== "sorobanCredentialsAddressWithDelegates") throw new Error("fixture lost its delegates arm");
    const withDelegates = entry.credentials.addressWithDelegates;
    const sign = (d: xdr.SorobanDelegateSignature): xdr.SorobanDelegateSignature =>
      new xdr.SorobanDelegateSignature({ address: d.address, signature: xdr.ScVal.scvBytes(new Uint8Array(64)), nestedDelegates: d.nestedDelegates.map(sign) });
    const creds = withDelegates.addressCredentials;
    const filled = new xdr.SorobanAuthorizationEntry({
      credentials: xdr.SorobanCredentials.sorobanCredentialsAddressWithDelegates(
        new xdr.SorobanAddressCredentialsWithDelegates({
          addressCredentials: new xdr.SorobanAddressCredentials({
            address: creds.address,
            nonce: creds.nonce,
            signatureExpirationLedger: creds.signatureExpirationLedger,
            signature: xdr.ScVal.scvBytes(new Uint8Array(64)),
          }),
          delegates: withDelegates.delegates.map(sign),
        }),
      ),
      rootInvocation: entry.rootInvocation,
    }).toXDR("base64");
    expect(sameAuthEntry(base, filled)).toBe(true);
  });

  it("unreadable entries are a mismatch", () => {
    for (const bad of ["", "AAAA", analyzed.slice(0, 10)]) {
      expect(sameAuthEntry(analyzed, bad)).toBe(false);
      expect(sameAuthEntry(bad, analyzed)).toBe(false);
    }
  });
});

/**
 * SEP-43 has two readings of what `signAuthEntry` takes and returns, and
 * wallets ship both; the adapter must tell "a different entry" apart from "not
 * an entry at all" rather than accuse a compliant wallet of the first.
 */
describe("signing-payload classification of a wallet's reply", () => {
  const analyzed = entryXdr("benign", "credential_address");

  /** Base64 of `n` bytes, the shape Freighter returns for a signed preimage. */
  const rawBase64 = (n: number): string => btoa(String.fromCharCode(...new Uint8Array(n).fill(8)));

  it("a signature is not an entry", () => {
    const signature = rawBase64(64);
    expect(isAuthEntry(signature)).toBe(false);
    expect(isSignatureLength(signature)).toBe(true);
  });

  it("an entry is not a signature", () => {
    expect(isSignatureLength(analyzed)).toBe(false);
    expect(isAuthEntry(analyzed)).toBe(true);
    expect(isAuthEntry(entryXdr("hostile", "signature_prefilled"))).toBe(true);
  });

  it("only 64-byte encodings read as a signature", () => {
    for (const n of [0, 1, 31, 32, 33, 63, 65, 68, 128]) expect(isSignatureLength(rawBase64(n))).toBe(false);
    expect(isSignatureLength(rawBase64(64))).toBe(true);
    // Padding is optional in the alphabet, so it must not shift the length.
    expect(isSignatureLength(rawBase64(64).replace(/=+$/, ""))).toBe(true);
  });

  it("hostile strings classify as neither, never as a signature", () => {
    for (const bad of ["", "=", "AAAA%%", "----", "A".repeat(85), "A".repeat(87), "-A".repeat(43)]) {
      expect(isAuthEntry(bad)).toBe(false);
      expect(isSignatureLength(bad)).toBe(false);
    }
  });

  it("malformed or padded-out padding does not read as a signature", () => {
    // Canonical base64 pads with at most two '=' and only to a multiple of four.
    // A wallet could send anything here, and the shape label must not overclaim.
    // The two guards are independent: six pads on 86 chars lands on a multiple of
    // four, so only `pads > 2` rejects it, while one pad on 86 chars decodes to a
    // plausible 64 bytes, so only the modulo check rejects that.
    for (const bad of ["A".repeat(86) + "=", "A".repeat(86) + "===", "A".repeat(84) + "===", "A".repeat(86) + "=".repeat(6), "A".repeat(86) + "=".repeat(50_002), "A".repeat(87) + "=", "A=".repeat(43), "=".repeat(50_000)]) {
      expect(isSignatureLength(bad)).toBe(false);
    }
    // A '=' anywhere but at the end is not the standard alphabet.
    expect(isSignatureLength("A".repeat(43) + "=" + "A".repeat(42) + "==")).toBe(false);
    expect(isSignatureLength(rawBase64(64))).toBe(true);
  });
});
