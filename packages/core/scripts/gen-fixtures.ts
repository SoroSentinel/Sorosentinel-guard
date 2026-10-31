// Regenerates fixtures/tx/** and fixtures/auth_entry/**. Deterministic: fixed
// test seeds, fixed time bounds.
// Run: node packages/core/scripts/gen-fixtures.ts
//
// TEST KEYS ONLY. Seeds are constant byte patterns, never valid for real funds,
// and are not written to fixtures (fixtures hold public keys and signatures).
import { mkdirSync, writeFileSync } from "node:fs";

import {
  Account,
  Asset,
  Contract,
  Keypair,
  Address,
  Claimant,
  Memo,
  xdr,
  MuxedAccount,
  Networks,
  Operation,
  StrKey,
  TimeoutInfinite,
  TransactionBuilder,
  type Transaction,
  type FeeBumpTransaction,
} from "@stellar/stellar-sdk/base";

import type { AuthEntryAddress } from "../src/decode/auth-entry.ts";

const OUT = new URL("../../../fixtures/tx/", import.meta.url);

const testKey = (byte: number) => Keypair.fromRawEd25519Seed(new Uint8Array(32).fill(byte));
const signer = testKey(1);
const other = testKey(2);
const issuer = testKey(3);
const feePayer = testKey(4);
// Stands in for a custodial account; tests give it the SEP-29 data entry through a fake RPC.
const custodian = testKey(5);
const usdc = new Asset("USDC", issuer.publicKey());
const contractId = StrKey.encodeContract(new Uint8Array(32).fill(7));

// Fixed bounds: 2026-10-27T00:00:00Z .. +5 minutes.
const MIN_TIME = 1_793_059_200;
const MAX_TIME = MIN_TIME + 300;

interface Expected {
  envelope: "tx_v0" | "tx" | "fee_bump";
  network: "public" | "testnet" | "unknown";
  tx_hash: string;
  source: string;
  source_muxed_id?: string;
  fee_source?: string;
  time_bounds: { min: string; max: string } | null;
  memo_type: string;
  operations: { type: string; source: string; has_own_source: boolean }[];
  /** Auth entries of the (single) invokeHostFunction operation, when present. */
  auth?: { credential: string; signatureExpirationLedger?: number }[];
}

type Built = Transaction | FeeBumpTransaction;

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

function builder(passphrase: string, source: string | MuxedAccount = signer.publicKey(), timebounds = true) {
  const account = typeof source === "string" ? new Account(source, "123456789") : source;
  const b = new TransactionBuilder(account, { fee: "100", networkPassphrase: passphrase });
  return timebounds ? b.setTimebounds(MIN_TIME, MAX_TIME) : b.setTimeout(TimeoutInfinite);
}

function write(dir: "benign" | "hostile", name: string, description: string, passphrase: string, tx: Built, expected: Omit<Expected, "tx_hash">) {
  const dirUrl = new URL(`${dir}/`, OUT);
  mkdirSync(dirUrl, { recursive: true });
  const file = new URL(`${name}.json`, dirUrl);
  const body = {
    name,
    description,
    network_passphrase: passphrase,
    xdr: tx.toXDR(),
    expected: { ...expected, tx_hash: hex(tx.hash()) },
  };
  writeFileSync(file, JSON.stringify(body, null, 2) + "\n");
}

function writeUnanalyzable(name: string, description: string, passphrase: string, xdr: string, reason: string) {
  const file = new URL(`hostile/${name}.json`, OUT);
  writeFileSync(file, JSON.stringify({ name, description, network_passphrase: passphrase, xdr, expected: { unanalyzable: reason } }, null, 2) + "\n");
}

// ---- standalone Soroban authorization entries (SEP-43 signAuthEntry) ----
const OUT_ENTRY = new URL("../../../fixtures/auth_entry/", import.meta.url);

interface ExpectedEntry {
  credential: string;
  /** The key exactly as Guard reports it: StrKey for accounts and contracts, hex where there is no codec. */
  address: AuthEntryAddress | null;
  nonce: string | null;
  signature_expiration_ledger: number | null;
  delegate_signatures: number;
  invocation_nodes: number;
  contracts: string[];
  contracts_unchecked: boolean;
}

function writeEntry(dir: "benign" | "hostile", name: string, description: string, passphrase: string, entry: xdr.SorobanAuthorizationEntry, expected: ExpectedEntry) {
  const dirUrl = new URL(`${dir}/`, OUT_ENTRY);
  mkdirSync(dirUrl, { recursive: true });
  writeFileSync(new URL(`${name}.json`, dirUrl), JSON.stringify({ name, description, network_passphrase: passphrase, xdr: entry.toXDR("base64"), expected }, null, 2) + "\n");
}

function writeEntryUnanalyzable(name: string, description: string, passphrase: string, xdr: string, reason: string) {
  const file = new URL(`hostile/${name}.json`, OUT_ENTRY);
  writeFileSync(file, JSON.stringify({ name, description, network_passphrase: passphrase, xdr, expected: { unanalyzable: reason } }, null, 2) + "\n");
}

/** An invocation of an existing contract; `Contract(...).call` builds the argument types. */
function callNode(contract: string, subs: xdr.SorobanAuthorizedInvocation[] = []): xdr.SorobanAuthorizedInvocation {
  const call = new Contract(contract).call("transfer");
  if (call.body.type !== "invokeHostFunction" || call.body.invokeHostFunctionOp.hostFunction.type !== "hostFunctionTypeInvokeContract") {
    throw new Error("unexpected contract call shape");
  }
  return new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(call.body.invokeHostFunctionOp.hostFunction.invokeContract),
    subInvocations: subs,
  });
}

function createNode(): xdr.SorobanAuthorizedInvocation {
  return new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeCreateContractHostFn(
      new xdr.CreateContractArgs({
        contractIdPreimage: xdr.ContractIdPreimage.contractIdPreimageFromAddress(
          new xdr.ContractIdPreimageFromAddress({ address: new Address(S).toScAddress(), salt: new Uint8Array(32).fill(9) }),
        ),
        executable: xdr.ContractExecutable.contractExecutableWasm(new Uint8Array(32).fill(8)),
      }),
    ),
    subInvocations: [],
  });
}

const entry = (credentials: xdr.SorobanCredentials, root: xdr.SorobanAuthorizedInvocation) =>
  new xdr.SorobanAuthorizationEntry({ credentials, rootInvocation: root });

const addressCredsFor = (address: xdr.ScAddress, expiry: number) =>
  new xdr.SorobanAddressCredentials({ address, nonce: 7n, signatureExpirationLedger: expiry, signature: xdr.ScVal.scvVoid() });

const g1 = StrKey.encodeEd25519PublicKey(new Uint8Array(32).fill(1));
const other1 = StrKey.encodeEd25519PublicKey(new Uint8Array(32).fill(2));
const contract2 = StrKey.encodeContract(new Uint8Array(32).fill(8));

/** Defaults for an address-credential entry calling `contractId` once; each write names what differs. */
function exp(over: Partial<ExpectedEntry>): ExpectedEntry {
  return {
    credential: "sorobanCredentialsAddress",
    address: { kind: "account", account: other1, muxedId: null },
    nonce: "7",
    signature_expiration_ledger: 5_000_000,
    delegate_signatures: 0,
    invocation_nodes: 1,
    contracts: [contractId],
    contracts_unchecked: false,
    ...over,
  };
}

const S = signer.publicKey();
const bounds = { min: String(MIN_TIME), max: String(MAX_TIME) };
const one = (type: string, source = S, has_own_source = false) => [{ type, source, has_own_source }];
const v1 = (network: Expected["network"], operations: Expected["operations"], extra: Partial<Expected> = {}): Omit<Expected, "tx_hash"> => ({
  envelope: "tx",
  network,
  source: S,
  time_bounds: bounds,
  memo_type: "none",
  operations,
  ...extra,
});

function signed<T extends Built>(tx: T, ...kps: Keypair[]): T {
  kps.forEach((kp) => tx.sign(kp));
  return tx;
}

const P = Networks.PUBLIC;
const T = Networks.TESTNET;

// ---- benign: one per v1 effect operation ----
write("benign", "payment_native", "Native XLM payment", P,
  signed(builder(P).addOperation(Operation.payment({ destination: other.publicKey(), asset: Asset.native(), amount: "12.5" })).build(), signer),
  v1("public", one("payment")));

write("benign", "create_account", "Create and fund a new account", P,
  signed(builder(P).addOperation(Operation.createAccount({ destination: other.publicKey(), startingBalance: "2" })).build(), signer),
  v1("public", one("createAccount")));

write("benign", "path_payment_strict_receive", "Path payment with a send maximum", P,
  signed(builder(P).addOperation(Operation.pathPaymentStrictReceive({
    sendAsset: Asset.native(), sendMax: "100", destination: other.publicKey(), destAsset: usdc, destAmount: "10", path: [],
  })).build(), signer),
  v1("public", one("pathPaymentStrictReceive")));

write("benign", "path_payment_strict_send", "Path payment with a destination minimum", P,
  signed(builder(P).addOperation(Operation.pathPaymentStrictSend({
    sendAsset: usdc, sendAmount: "10", destination: other.publicKey(), destAsset: Asset.native(), destMin: "50", path: [],
  })).build(), signer),
  v1("public", one("pathPaymentStrictSend")));

write("benign", "change_trust", "Add a trustline", T,
  signed(builder(T).addOperation(Operation.changeTrust({ asset: usdc })).build(), signer),
  v1("testnet", one("changeTrust")));

write("benign", "set_options_add_signer", "Add an ed25519 signer", P,
  signed(builder(P).addOperation(Operation.setOptions({ signer: { ed25519PublicKey: other.publicKey(), weight: 1 } })).build(), signer),
  v1("public", one("setOptions")));

write("benign", "account_merge", "Merge the account into another", P,
  signed(builder(P).addOperation(Operation.accountMerge({ destination: other.publicKey() })).build(), signer),
  v1("public", one("accountMerge")));

write("benign", "invoke_contract", "Invoke a contract function (no auth entries)", T,
  signed(builder(T).addOperation(new Contract(contractId).call("hello")).build(), signer),
  v1("testnet", one("invokeHostFunction")));

write("benign", "manage_data_decode_only", "Decode-only operation (no v1 effects)", P,
  signed(builder(P).addOperation(Operation.manageData({ name: "k", value: "v" })).build(), signer),
  v1("public", one("manageData")));

write("benign", "memo_id", "Payment with an ID memo", P,
  signed(builder(P).addMemo(Memo.id("42")).addOperation(Operation.payment({ destination: other.publicKey(), asset: Asset.native(), amount: "1" })).build(), signer),
  v1("public", one("payment"), { memo_type: "id" }));

// ---- benign: one per decode-only operation (no v1 effects) ----
{
  const balanceId = "00000000" + "11".repeat(32);
  const poolId = "22".repeat(32);
  const decodeOnly: [string, string, xdr.Operation][] = [
    ["manageSellOffer", "Sell offer on the DEX", Operation.manageSellOffer({ selling: Asset.native(), buying: usdc, amount: "10", price: "0.5" })],
    ["createPassiveSellOffer", "Passive sell offer", Operation.createPassiveSellOffer({ selling: usdc, buying: Asset.native(), amount: "10", price: "2" })],
    ["allowTrust", "Issuer authorizes a trustline (deprecated op)", Operation.allowTrust({ trustor: other.publicKey(), assetCode: "USDC", authorize: true })],
    ["inflation", "Inflation (disabled on the network since protocol 12)", Operation.inflation({})],
    ["bumpSequence", "Bump the sequence number", Operation.bumpSequence({ bumpTo: "123456800" })],
    ["manageBuyOffer", "Buy offer on the DEX", Operation.manageBuyOffer({ selling: Asset.native(), buying: usdc, buyAmount: "5", price: "0.5" })],
    ["createClaimableBalance", "Create a claimable balance", Operation.createClaimableBalance({ asset: Asset.native(), amount: "3", claimants: [new Claimant(other.publicKey())] })],
    ["claimClaimableBalance", "Claim a claimable balance", Operation.claimClaimableBalance({ balanceId })],
    ["beginSponsoringFutureReserves", "Start sponsoring another account's reserves", Operation.beginSponsoringFutureReserves({ sponsoredId: other.publicKey() })],
    ["endSponsoringFutureReserves", "End a sponsorship block", Operation.endSponsoringFutureReserves({})],
    ["revokeSponsorship", "Revoke sponsorship of an account entry", Operation.revokeAccountSponsorship({ account: other.publicKey() })],
    ["clawback", "Issuer claws back an asset", Operation.clawback({ asset: usdc, amount: "1", from: other.publicKey() })],
    ["clawbackClaimableBalance", "Issuer claws back a claimable balance", Operation.clawbackClaimableBalance({ balanceId })],
    ["setTrustLineFlags", "Issuer changes trustline flags", Operation.setTrustLineFlags({ trustor: other.publicKey(), asset: usdc, flags: { authorized: true } })],
    ["liquidityPoolDeposit", "Deposit into a liquidity pool", Operation.liquidityPoolDeposit({ liquidityPoolId: poolId, maxAmountA: "10", maxAmountB: "10", minPrice: "0.9", maxPrice: "1.1" })],
    ["liquidityPoolWithdraw", "Withdraw from a liquidity pool", Operation.liquidityPoolWithdraw({ liquidityPoolId: poolId, amount: "1", minAmountA: "0.5", minAmountB: "0.5" })],
    ["extendFootprintTtl", "Extend Soroban state TTL", Operation.extendFootprintTtl({ extendTo: 100_000 })],
    ["restoreFootprint", "Restore archived Soroban state", Operation.restoreFootprint({})],
  ];
  for (const [type, description, op] of decodeOnly) {
    const snake = type.replace(/[A-Z]/g, (c) => "_" + c.toLowerCase());
    write("benign", `decode_only_${snake}`, description, P, signed(builder(P).addOperation(op).build(), signer), v1("public", one(type)));
  }
}

// ---- Soroban authorization entries ----
{
  const call = new Contract(contractId).call("transfer");
  if (call.body.type !== "invokeHostFunction" || call.body.invokeHostFunctionOp.hostFunction.type !== "hostFunctionTypeInvokeContract") {
    throw new Error("unexpected contract call shape");
  }
  const invocation = new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(call.body.invokeHostFunctionOp.hostFunction.invokeContract),
    subInvocations: [],
  });
  const addressCreds = (expiry: number) =>
    new xdr.SorobanAddressCredentials({ address: new Address(other.publicKey()).toScAddress(), nonce: 7n, signatureExpirationLedger: expiry, signature: xdr.ScVal.scvVoid() });
  const auth = [
    new xdr.SorobanAuthorizationEntry({ credentials: xdr.SorobanCredentials.sorobanCredentialsSourceAccount(), rootInvocation: invocation }),
    new xdr.SorobanAuthorizationEntry({ credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(addressCreds(5_000_000)), rootInvocation: invocation }),
    new xdr.SorobanAuthorizationEntry({ credentials: xdr.SorobanCredentials.sorobanCredentialsAddressV2(addressCreds(5_000_001)), rootInvocation: invocation }),
    new xdr.SorobanAuthorizationEntry({
      credentials: xdr.SorobanCredentials.sorobanCredentialsAddressWithDelegates(new xdr.SorobanAddressCredentialsWithDelegates({
        addressCredentials: addressCreds(5_000_002),
        delegates: [new xdr.SorobanDelegateSignature({ address: new Address(other.publicKey()).toScAddress(), signature: xdr.ScVal.scvVoid(), nestedDelegates: [] })],
      })),
      rootInvocation: invocation,
    }),
  ];
  const op = Operation.invokeHostFunction({ func: call.body.invokeHostFunctionOp.hostFunction, auth });
  write("hostile", "auth_entries_address_credentials", "Contract call carrying one auth entry per Soroban credential arm (another account signs)", T,
    signed(builder(T).addOperation(op).build(), signer),
    v1("testnet", one("invokeHostFunction"), {
      auth: [
        { credential: "sorobanCredentialsSourceAccount" },
        { credential: "sorobanCredentialsAddress", signatureExpirationLedger: 5_000_000 },
        { credential: "sorobanCredentialsAddressV2", signatureExpirationLedger: 5_000_001 },
        { credential: "sorobanCredentialsAddressWithDelegates" },
      ],
    }));
}

// ---- standalone entries: one per credential arm, one per address kind ----
const balIdHex = hex(xdr.ClaimableBalanceId.claimableBalanceIdTypeV0(new xdr.Hash(new Uint8Array(32).fill(3))).toXdr());
const poolHex = hex(new xdr.Hash(new Uint8Array(32).fill(4)).toBytes());
const muxedScAddress = xdr.ScAddress.scAddressTypeMuxedAccount(new xdr.MuxedEd25519Account({ id: 42n, ed25519: new Uint8Array(32).fill(2) }));
const scAddress = (key: string) => new Address(key).toScAddress();

writeEntry("benign", "credential_source_account", "Source-account credentials: the transaction's source signs, so the entry names no address", T,
  entry(xdr.SorobanCredentials.sorobanCredentialsSourceAccount(), callNode(contractId)),
  exp({ credential: "sorobanCredentialsSourceAccount", address: null, nonce: null, signature_expiration_ledger: null }));

writeEntry("benign", "credential_address", "Address credentials signing for a G… account", T,
  entry(xdr.SorobanCredentials.sorobanCredentialsAddress(addressCredsFor(scAddress(other1), 5_000_000)), callNode(contractId)),
  exp({}));

// The same arm for a key whose seed this script documents: `other1` is a
// synthetic public key with no secret behind it, so nothing can sign for it, and
// the preimage-verification tests need an entry a real keypair does authorize.
writeEntry("benign", "credential_address_test_key", "Address credentials for a key the test seeds can sign (testKey(1))", T,
  entry(xdr.SorobanCredentials.sorobanCredentialsAddress(addressCredsFor(scAddress(S), 5_000_000)), callNode(contractId)),
  exp({ address: { kind: "account", account: S, muxedId: null } }));

writeEntry("benign", "credential_address_v2", "Address V2 credentials (CAP-71 address binding)", T,
  entry(xdr.SorobanCredentials.sorobanCredentialsAddressV2(addressCredsFor(scAddress(other1), 5_000_000)), callNode(contractId)),
  exp({ credential: "sorobanCredentialsAddressV2" }));

writeEntry("benign", "credential_address_with_delegates", "Delegated credentials: two more signatures, one of them nested", T,
  entry(xdr.SorobanCredentials.sorobanCredentialsAddressWithDelegates(new xdr.SorobanAddressCredentialsWithDelegates({
    addressCredentials: addressCredsFor(scAddress(other1), 5_000_000),
    delegates: [
      new xdr.SorobanDelegateSignature({ address: scAddress(g1), signature: xdr.ScVal.scvVoid(), nestedDelegates: [
        new xdr.SorobanDelegateSignature({ address: scAddress(other1), signature: xdr.ScVal.scvVoid(), nestedDelegates: [] }),
      ] }),
    ],
  })), callNode(contractId)),
  exp({ credential: "sorobanCredentialsAddressWithDelegates", delegate_signatures: 2 }));

writeEntry("benign", "address_is_contract", "Credentials attached to a contract address rather than an account", T,
  entry(xdr.SorobanCredentials.sorobanCredentialsAddress(addressCredsFor(scAddress(contractId), 5_000_000)), callNode(contractId)),
  exp({ address: { kind: "contract", contract: contractId } }));

writeEntry("benign", "address_is_muxed", "Credentials on an M… address: reported as its G… key and id", T,
  entry(xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({ address: muxedScAddress, nonce: 7n, signatureExpirationLedger: 5_000_000, signature: xdr.ScVal.scvVoid() })), callNode(contractId)),
  exp({ address: { kind: "account", account: other1, muxedId: "42" } }));

writeEntry("benign", "address_is_claimable_balance", "Credentials on a claimable-balance address: no StrKey codec, reported as hex", T,
  entry(xdr.SorobanCredentials.sorobanCredentialsAddress(addressCredsFor(xdr.ScAddress.scAddressTypeClaimableBalance(xdr.ClaimableBalanceId.claimableBalanceIdTypeV0(new xdr.Hash(new Uint8Array(32).fill(3)))), 5_000_000)), callNode(contractId)),
  exp({ address: { kind: "claimable_balance", idHex: balIdHex } }));

writeEntry("benign", "address_is_liquidity_pool", "Credentials on a liquidity-pool address: reported as hex", T,
  entry(xdr.SorobanCredentials.sorobanCredentialsAddress(addressCredsFor(xdr.ScAddress.scAddressTypeLiquidityPool(new xdr.PoolId(new Uint8Array(32).fill(4))), 5_000_000)), callNode(contractId)),
  exp({ address: { kind: "liquidity_pool", poolHex } }));

writeEntry("benign", "invocations_nested", "A tree that authorizes a call, and inside it a second contract", T,
  entry(xdr.SorobanCredentials.sorobanCredentialsSourceAccount(), callNode(contractId, [callNode(contract2)])),
  exp({ credential: "sorobanCredentialsSourceAccount", address: null, nonce: null, signature_expiration_ledger: null, invocation_nodes: 2, contracts: [contractId, contract2].sort() }));

writeEntry("benign", "invocation_creates_contract", "The tree creates a contract, so there is no existing address to look up", T,
  entry(xdr.SorobanCredentials.sorobanCredentialsSourceAccount(), createNode()),
  exp({ credential: "sorobanCredentialsSourceAccount", address: null, nonce: null, signature_expiration_ledger: null, contracts: [], contracts_unchecked: true }));

// A wallet returns its entry with the signature field filled in; that field is
// not part of what Guard analyzes, and `sameAuthEntry` ignores it.
writeEntry("hostile", "signature_prefilled", "Entry whose signature field is already populated", T,
  entry(xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({
    address: scAddress(other1), nonce: 7n, signatureExpirationLedger: 5_000_000,
    signature: xdr.ScVal.scvMap([new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol("hashSig"), val: xdr.ScVal.scvBytes(new Uint8Array(64)) })]),
  })), callNode(contractId)),
  exp({}));

writeEntryUnanalyzable("malformed_base64", "Not base64", P, "AAAA%%%not-base64", "decode_failed");
{
  const good = entry(xdr.SorobanCredentials.sorobanCredentialsSourceAccount(), callNode(contractId)).toXDR("base64");
  writeEntryUnanalyzable("truncated_xdr", "Valid entry truncated mid-invocation", P, good.slice(0, Math.floor(good.length / 2)), "decode_failed");
}
writeEntryUnanalyzable("oversized", "Base64 longer than Guard's entry ceiling", P, "A".repeat(256 * 1024 + 1), "input_too_large");
writeEntryUnanalyzable("empty_passphrase", "An entry carries no network, so the passphrase is required", "", entry(xdr.SorobanCredentials.sorobanCredentialsSourceAccount(), callNode(contractId)).toXDR("base64"), "invalid_network_passphrase");

// ---- hostile / edge cases ----
{
  const inner = signed(builder(P).addOperation(Operation.payment({ destination: other.publicKey(), asset: Asset.native(), amount: "1" })).build(), signer);
  write("hostile", "fee_bump", "Fee bump: outer fee payer differs from inner source", P,
    signed(TransactionBuilder.buildFeeBumpTransaction(feePayer, "200", inner, P), feePayer),
    { ...v1("public", one("payment")), envelope: "fee_bump", fee_source: feePayer.publicKey() });
}

write("hostile", "no_time_bounds", "No upper time bound: valid until its sequence number is used", P,
  signed(builder(P, S, false).addOperation(Operation.payment({ destination: other.publicKey(), asset: Asset.native(), amount: "1" })).build(), signer),
  v1("public", one("payment"), { time_bounds: { min: "0", max: "0" } }));

{
  const b = builder(P);
  for (let i = 0; i < 49; i++) b.addOperation(Operation.payment({ destination: other.publicKey(), asset: Asset.native(), amount: "0.0000001" }));
  b.addOperation(Operation.setOptions({ signer: { ed25519PublicKey: other.publicKey(), weight: 255 }, masterWeight: 0 }));
  const ops = [...Array.from({ length: 49 }, () => ({ type: "payment", source: S, has_own_source: false })), { type: "setOptions", source: S, has_own_source: false }];
  write("hostile", "padding_buried_set_options", "One account-control change hidden after 49 dust payments", P, signed(b.build(), signer), v1("public", ops));
}

write("hostile", "hashx_signer", "SetOptions adds a hash(x) signer (no visible owner key)", P,
  signed(builder(P).addOperation(Operation.setOptions({ signer: { sha256Hash: new Uint8Array(32).fill(9), weight: 1 } })).build(), signer),
  v1("public", one("setOptions")));

write("hostile", "op_source_other_account", "Operation moves another account's funds (own source account)", P,
  signed(builder(P).addOperation(Operation.payment({ source: issuer.publicKey(), destination: other.publicKey(), asset: usdc, amount: "5" })).build(), signer, issuer),
  v1("public", one("payment", issuer.publicKey(), true)));

{
  const muxed = new MuxedAccount(new Account(S, "123456789"), "1234");
  write("hostile", "muxed_source", "Transaction source is a muxed M... account", P,
    signed(builder(P, muxed).addOperation(Operation.payment({ destination: other.publicKey(), asset: Asset.native(), amount: "1" })).build(), signer),
    v1("public", one("payment"), { source_muxed_id: "1234" }));
}

// SEP-29: no memo, so each destination's `config.memo_required` entry decides.
write("hostile", "memo_required_destination", "Payment without a memo to an account that may require one (SEP-29)", P,
  signed(builder(P).addOperation(Operation.payment({ destination: custodian.publicKey(), asset: Asset.native(), amount: "100" })).build(), signer),
  v1("public", one("payment")));

{
  const muxed = new MuxedAccount(new Account(custodian.publicKey(), "0"), "42").accountId();
  write("hostile", "muxed_destination", "Payment without a memo to a muxed M... destination (SEP-29 exempts it)", P,
    signed(builder(P).addOperation(Operation.payment({ destination: muxed, asset: Asset.native(), amount: "100" })).build(), signer),
    v1("public", one("payment")));
}

{
  const muxed = new MuxedAccount(new Account(custodian.publicKey(), "0"), "42").accountId();
  const b = builder(P)
    .addOperation(Operation.payment({ destination: custodian.publicKey(), asset: Asset.native(), amount: "1" }))
    .addOperation(Operation.pathPaymentStrictReceive({ sendAsset: Asset.native(), sendMax: "10", destination: other.publicKey(), destAsset: usdc, destAmount: "1", path: [] }))
    .addOperation(Operation.pathPaymentStrictSend({ sendAsset: Asset.native(), sendAmount: "10", destination: custodian.publicKey(), destAsset: usdc, destMin: "1", path: [] }))
    .addOperation(Operation.manageData({ name: "note", value: "x" }))
    .addOperation(Operation.createAccount({ destination: testKey(6).publicKey(), startingBalance: "2" }))
    .addOperation(Operation.payment({ destination: muxed, asset: Asset.native(), amount: "1" }))
    .addOperation(Operation.accountMerge({ destination: other.publicKey() }));
  const types = ["payment", "pathPaymentStrictReceive", "pathPaymentStrictSend", "manageData", "createAccount", "payment", "accountMerge"];
  write("hostile", "memo_required_operations", "No memo; SEP-29 operations to plain, repeated and muxed destinations mixed with others", P,
    signed(b.build(), signer), v1("public", types.map((type) => ({ type, source: S, has_own_source: false }))));
}

write("hostile", "unknown_network", "Signed for a passphrase with no Intel coverage", "Standalone Network ; February 2017",
  signed(builder("Standalone Network ; February 2017").addOperation(Operation.payment({ destination: other.publicKey(), asset: Asset.native(), amount: "1" })).build(), signer),
  v1("unknown", one("payment")));

writeUnanalyzable("malformed_base64", "Not base64", P, "AAAA%%%not-base64", "decode_failed");
{
  const good = builder(P).addOperation(Operation.payment({ destination: other.publicKey(), asset: Asset.native(), amount: "1" })).build().toXDR();
  writeUnanalyzable("truncated_xdr", "Valid envelope truncated mid-operation", P, good.slice(0, Math.floor(good.length / 2)), "decode_failed");
}

console.log("fixtures written to", OUT.pathname);
