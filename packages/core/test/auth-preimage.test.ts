import { Address, Contract, Keypair, StrKey, hash, xdr } from "@stellar/stellar-sdk/base";
import { describe, expect, it } from "vitest";

import { MAX_AUTH_ENTRY_BASE64_LENGTH, verifyAuthEntrySignature } from "../src/index.ts";

const TESTNET = "Test SDF Network ; September 2015";
const PUBLIC = "Public Global Stellar Network ; September 2015";
const CONTRACT = StrKey.encodeContract(new Uint8Array(32).fill(7));
const NONCE = 7n;
const EXPIRY = 5_000_000;

// The fixture addresses are synthetic public keys (gen-fixtures.ts fills the 32
// bytes), so no secret matches them and they cannot sign anything. These tests
// build their entries around keypairs whose seeds they hold.
const key = (b: number) => Keypair.fromRawEd25519Seed(new Uint8Array(32).fill(b));
const signer = key(3);
const delegate = key(4);

type Arm = "address" | "addressV2" | "delegates";

interface Shape {
  arm: Arm;
  address: xdr.ScAddress;
  nonce: bigint;
  expiry: number;
  root: xdr.SorobanAuthorizedInvocation;
}

function callNode(contract: string = CONTRACT, ...args: xdr.ScVal[]): xdr.SorobanAuthorizedInvocation {
  const call = new Contract(contract).call("transfer", ...args);
  const body = call.body;
  if (body.type !== "invokeHostFunction" || body.invokeHostFunctionOp.hostFunction.type !== "hostFunctionTypeInvokeContract") {
    throw new Error("unexpected contract call shape");
  }
  return new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(body.invokeHostFunctionOp.hostFunction.invokeContract),
    subInvocations: [],
  });
}

const account = (k: Keypair) => new Address(k.publicKey()).toScAddress();

/** An `M…` address wrapping `signer`'s key under a sub-id. */
const muxed = (id: bigint): xdr.ScAddress => xdr.ScAddress.scAddressTypeMuxedAccount(new xdr.MuxedEd25519Account({ id, ed25519: signer.rawPublicKey() }));

function shape(over: Partial<Shape> = {}): Shape {
  return { arm: "address", address: account(signer), nonce: NONCE, expiry: EXPIRY, root: callNode(), ...over };
}

/** An entry of the given shape, with an empty signature: what a dApp asks a wallet to authorize. */
function entryOf(s: Shape): string {
  const creds = new xdr.SorobanAddressCredentials({ address: s.address, nonce: s.nonce, signatureExpirationLedger: s.expiry, signature: xdr.ScVal.scvVoid() });
  const credentials =
    s.arm === "address"
      ? xdr.SorobanCredentials.sorobanCredentialsAddress(creds)
      : s.arm === "addressV2"
        ? xdr.SorobanCredentials.sorobanCredentialsAddressV2(creds)
        : xdr.SorobanCredentials.sorobanCredentialsAddressWithDelegates(
            new xdr.SorobanAddressCredentialsWithDelegates({
              addressCredentials: creds,
              delegates: [new xdr.SorobanDelegateSignature({ address: account(delegate), signature: xdr.ScVal.scvVoid(), nestedDelegates: [] })],
            }),
          );
  return new xdr.SorobanAuthorizationEntry({ credentials, rootInvocation: s.root }).toXDR("base64");
}

/**
 * The payload the protocol says this entry's signer signs, written from the CAPs'
 * field lists rather than from the SDK's builder, so the builder is checked against
 * the rule and not merely against itself: CAP-0046-11 "Soroban Authorization
 * Signature Payload" for the unbound legacy arm, CAP-0071-01/-02 for the
 * address-bound arm that V2 and delegated credentials must use.
 */
function payloadOf(s: Shape, passphrase: string): Uint8Array {
  const networkId = hash(passphrase);
  if (s.arm === "address") {
    return hash(
      xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
        new xdr.HashIdPreimageSorobanAuthorization({ networkId, nonce: s.nonce, invocation: s.root, signatureExpirationLedger: s.expiry }),
      ).toXdr(),
    );
  }
  return hash(
    xdr.HashIdPreimage.envelopeTypeSorobanAuthorizationWithAddress(
      new xdr.HashIdPreimageSorobanAuthorizationWithAddress({
        networkId,
        nonce: s.nonce,
        invocation: s.root,
        address: s.address,
        signatureExpirationLedger: s.expiry,
      }),
    ).toXdr(),
  );
}

const b64 = (bytes: Uint8Array): string => btoa(String.fromCharCode(...bytes));

/** What a preimage-reading wallet returns: the signature, and nothing else. */
function signEntry(s: Shape, over: { passphrase?: string; by?: Keypair } = {}): string {
  return b64((over.by ?? signer).sign(payloadOf(s, over.passphrase ?? TESTNET)));
}

const ARMS = ["address", "addressV2", "delegates"] as const;

describe("verifyAuthEntrySignature", () => {
  it.each(ARMS)("verifies a real keypair's signature over the %s payload", (arm) => {
    const s = shape({ arm });
    expect(verifyAuthEntrySignature(entryOf(s), signEntry(s), TESTNET)).toEqual({ verdict: "verified", authorizedBy: signer.publicKey() });
  });

  it("names the credential address as the authorizer, not the wallet's claim", () => {
    const s = { ...shape(), arm: "addressV2" as Arm, address: muxed(42n) };
    expect(verifyAuthEntrySignature(entryOf(s), signEntry(s), TESTNET)).toEqual({ verdict: "verified", authorizedBy: signer.publicKey() });
  });

  it("binds the top-level address for delegated credentials, so a delegate's own signature is not it", () => {
    const s = shape({ arm: "delegates" });
    expect(verifyAuthEntrySignature(entryOf(s), signEntry(s), TESTNET).verdict).toBe("verified");
    // CAP-0071-01 has every delegate sign the same payload, but the entry's
    // credentials name the top-level address, and that is the key the network checks.
    expect(verifyAuthEntrySignature(entryOf(s), signEntry(s, { by: delegate }), TESTNET)).toEqual({ verdict: "mismatch", authorizedBy: signer.publicKey() });
  });

  it("does not carry a signature between the unbound and the address-bound payload", () => {
    const legacy = shape();
    const v2 = shape({ arm: "addressV2" });
    expect(verifyAuthEntrySignature(entryOf(v2), signEntry(legacy), TESTNET).verdict).toBe("mismatch");
    expect(verifyAuthEntrySignature(entryOf(legacy), signEntry(v2), TESTNET).verdict).toBe("mismatch");
  });

  it("binds the muxed id only in the address-bound payload, which is what CAP-0071-02 says", () => {
    const muxedV2 = (id: bigint): Shape => shape({ arm: "addressV2", address: muxed(id) });
    const from42 = signEntry(muxedV2(42n));
    expect(verifyAuthEntrySignature(entryOf(muxedV2(42n)), from42, TESTNET).verdict).toBe("verified");
    expect(verifyAuthEntrySignature(entryOf(muxedV2(43n)), from42, TESTNET).verdict).toBe("mismatch");

    // The legacy arm's payload has no address at all, so the id is not bound and
    // the same signature authorizes both. Pinned so a change here is a decision.
    const legacy = (id: bigint): Shape => shape({ address: muxed(id) });
    expect(verifyAuthEntrySignature(entryOf(legacy(43n)), signEntry(legacy(42n)), TESTNET).verdict).toBe("verified");
  });

  const mutations: [string, (s: Shape) => Shape][] = [
    ["a different nonce", (s) => ({ ...s, nonce: s.nonce + 1n })],
    ["a different expiration ledger", (s) => ({ ...s, expiry: s.expiry + 1 })],
    ["a different credential address", (s) => ({ ...s, address: account(delegate) })],
    ["a different contract", (s) => ({ ...s, root: callNode(StrKey.encodeContract(new Uint8Array(32).fill(8))) })],
    ["an extra sub-invocation", (s) => ({ ...s, root: new xdr.SorobanAuthorizedInvocation({ function: s.root.function, subInvocations: [callNode(CONTRACT)] }) })],
  ];

  it.each(mutations)("%s makes the signature a mismatch, never a clean read", (name, mutate) => {
    for (const arm of ARMS) {
      const signed = shape({ arm });
      const mutated = mutate(signed);
      expect(verifyAuthEntrySignature(entryOf(mutated), signEntry(signed), TESTNET), `${name} on ${arm}`).toEqual({
        verdict: "mismatch",
        authorizedBy: name === "a different credential address" ? delegate.publicKey() : signer.publicKey(),
      });
    }
  });

  it("a signature made for another network is a mismatch", () => {
    for (const arm of ARMS) {
      const s = shape({ arm });
      expect(verifyAuthEntrySignature(entryOf(s), signEntry(s, { passphrase: PUBLIC }), TESTNET).verdict).toBe("mismatch");
      expect(verifyAuthEntrySignature(entryOf(s), signEntry(s, { passphrase: "Standalone Network ; February 2017" }), TESTNET).verdict).toBe("mismatch");
    }
  });

  it("a signature over any other 32-byte payload is a mismatch", () => {
    const s = shape();
    const notAPreimage = b64(signer.sign(hash("something else entirely")));
    expect(verifyAuthEntrySignature(entryOf(s), notAPreimage, TESTNET).verdict).toBe("mismatch");
  });

  describe("reports what it cannot check instead of guessing", () => {
    const sourceAccountEntry = new xdr.SorobanAuthorizationEntry({
      credentials: xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),
      rootInvocation: callNode(),
    }).toXDR("base64");

    const nonKeyAddress = (a: xdr.ScAddress): string =>
      new xdr.SorobanAuthorizationEntry({
        credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
          new xdr.SorobanAddressCredentials({ address: a, nonce: NONCE, signatureExpirationLedger: EXPIRY, signature: xdr.ScVal.scvVoid() }),
        ),
        rootInvocation: callNode(),
      }).toXDR("base64");

    const CONTRACT_ADDRESS = new Address(CONTRACT).toScAddress();
    const BALANCE_ADDRESS = xdr.ScAddress.scAddressTypeClaimableBalance(
      xdr.ClaimableBalanceId.claimableBalanceIdTypeV0(new xdr.Hash(new Uint8Array(32).fill(3))),
    );
    const POOL_ADDRESS = xdr.ScAddress.scAddressTypeLiquidityPool(new xdr.PoolId(new Uint8Array(32).fill(4)));

    it("source-account credentials carry no signature", () => {
      expect(verifyAuthEntrySignature(sourceAccountEntry, b64(new Uint8Array(64).fill(8)), TESTNET)).toEqual({
        verdict: "unverifiable",
        reason: "credential_has_no_signature",
      });
    });

    it("an entry whose credentials name no ed25519 key is judged only by that address's own __check_auth", () => {
      // The bytes are a valid signature by a real key, which is exactly why the
      // credential address has to be the one checked: verifying against whatever
      // key the reply happens to come from would call this authorized.
      const s = shape({ address: CONTRACT_ADDRESS });
      for (const address of [CONTRACT_ADDRESS, BALANCE_ADDRESS, POOL_ADDRESS]) {
        expect(verifyAuthEntrySignature(nonKeyAddress(address), signEntry(s), TESTNET)).toEqual({
          verdict: "unverifiable",
          reason: "credential_not_ed25519",
        });
      }
    });

    it("a reply that is not 64 bytes is not a signature", () => {
      const s = shape();
      for (const junk of ["", "AAAA", b64(new Uint8Array(63)), b64(new Uint8Array(65)), b64(new Uint8Array(64).fill(8)) + "=", "not base64 %%%%"]) {
        expect(verifyAuthEntrySignature(entryOf(s), junk, TESTNET)).toEqual({ verdict: "unverifiable", reason: "reply_not_a_signature" });
      }
    });

    it("an entry that does not decode is not checkable", () => {
      const signature = b64(new Uint8Array(64).fill(8));
      for (const junk of ["", "not base64 %%%%", b64(new Uint8Array(100))]) {
        expect(verifyAuthEntrySignature(junk, signature, TESTNET)).toEqual({ verdict: "unverifiable", reason: "entry_undecodable" });
      }
    });

    it("the size ceiling bites before decoding, not after", () => {
      // The cap is what keeps a megabyte of wallet output away from the XDR
      // decoder, so an oversized entry must be refused even when it would decode
      // and its signature would verify: dropping the check would read "verified"
      // for bytes this build is not willing to parse.
      const huge = shape({ root: callNode(CONTRACT, xdr.ScVal.scvBytes(new Uint8Array(MAX_AUTH_ENTRY_BASE64_LENGTH))) });
      const entryXdr = entryOf(huge);
      expect(entryXdr.length).toBeGreaterThan(MAX_AUTH_ENTRY_BASE64_LENGTH);
      expect(xdr.SorobanAuthorizationEntry.fromXDR(entryXdr, "base64").rootInvocation.function.type).toBe("sorobanAuthorizedFunctionTypeContractFn");
      expect(verifyAuthEntrySignature(entryXdr, signEntry(huge), TESTNET)).toEqual({ verdict: "unverifiable", reason: "entry_undecodable" });
    });

    it("the reply is checked first, so a junk entry with a junk reply says nothing about the entry", () => {
      expect(verifyAuthEntrySignature("not base64 %%%%", "AAAA", TESTNET)).toEqual({ verdict: "unverifiable", reason: "reply_not_a_signature" });
    });

    it("no input makes it throw, or claim more than it checked", () => {
      const hostile = ["", "=", "AAAA%%", "A".repeat(85), "not base64 %%", b64(new Uint8Array(64)), sourceAccountEntry];
      const s = shape();
      for (const entry of [...hostile, entryOf(s), "A".repeat(MAX_AUTH_ENTRY_BASE64_LENGTH + 1)]) {
        for (const reply of hostile) {
          for (const passphrase of [TESTNET, PUBLIC, "", "x".repeat(300)]) {
            const v = verifyAuthEntrySignature(entry, reply, passphrase);
            expect(["verified", "mismatch", "unverifiable"]).toContain(v.verdict);
            if (v.verdict !== "verified") continue;
            // A clean claim requires the entry to decode and name an ed25519 key.
            expect(entry).toBe(entryOf(s));
          }
        }
      }
    });
  });
});
