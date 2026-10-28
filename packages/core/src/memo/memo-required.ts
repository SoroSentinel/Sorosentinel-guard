import { StrKey, xdr } from "@stellar/stellar-sdk/base";
import type { Api } from "@stellar/stellar-sdk/rpc";

import { assertNever } from "../assert-never.ts";
import type { AnalysisInput } from "../decode/envelope.ts";
import { accountRef } from "../decode/account.ts";
import { accountId } from "../effects/asset.ts";
import { callRpc, isLedger, isRecord, type RpcConfig } from "../rpc/transport.ts";
import { MAX_SIMULATION_RESPONSE_BYTES } from "../simulate/simulate.ts";

// SEP-29 v0.5.0, "Account Memo Requirements"
// (github.com/stellar/stellar-protocol, ecosystem/sep-0029.md):
// - An account requires a memo when it has the data entry named
//   `config.memo_required` with value `1` (the single ASCII character "1",
//   0x31). Any other value, or no entry, does not mark the account.
// - The check applies to PAYMENT, PATH_PAYMENT_STRICT_SEND,
//   PATH_PAYMENT_STRICT_RECEIVE and MERGE_ACCOUNT operations, for each
//   operation of the transaction, and only when the destination is not a
//   multiplexed (`M…`) account: a muxed destination already carries its ID.
// - The transaction memo must be set (any type).
// The pinned SDK's Horizon `checkMemoRequired` (17.2.1) matches: same
// operations, muxed destinations skipped, data value "MQ==" (base64 of "1").
export const MEMO_REQUIRED_DATA_NAME = "config.memo_required";
const MEMO_REQUIRED_VALUE = 0x31;

// getLedgerEntries accepts at most 200 keys (Stellar RPC API reference). A
// transaction has at most 100 operations, so one request covers it.
const MAX_LEDGER_KEYS = 200;

/** An operation SEP-29 applies to, sending to a plain `G…` account. */
export interface MemoDestination {
  operationIndex: number;
  account: string;
}

/**
 * Destinations SEP-29 asks the sender to check, one per operation. Muxed
 * destinations are left out, as SEP-29 specifies. Operations outside SEP-29
 * (including contract transfers and claimable balances) are not covered.
 */
export function memoDestinations(input: AnalysisInput): MemoDestination[] {
  const out: MemoDestination[] = [];
  input.operations.forEach((op, operationIndex) => {
    const destination = sep29Destination(op.body);
    if (destination === null) return;
    const ref = accountRef(destination);
    if (ref.muxedId === undefined) out.push({ operationIndex, account: ref.account });
  });
  return out;
}

function sep29Destination(body: xdr.OperationBody): xdr.MuxedAccount | null {
  switch (body.type) {
    case "payment":
      return body.paymentOp.destination;
    case "pathPaymentStrictReceive":
      return body.pathPaymentStrictReceiveOp.destination;
    case "pathPaymentStrictSend":
      return body.pathPaymentStrictSendOp.destination;
    case "accountMerge":
      return body.destination;
    // Creates the destination, so it has no data entries yet.
    case "createAccount":
    case "changeTrust":
    case "setOptions":
    case "invokeHostFunction":
    case "manageSellOffer":
    case "createPassiveSellOffer":
    case "allowTrust":
    case "inflation":
    case "manageData":
    case "bumpSequence":
    case "manageBuyOffer":
    case "createClaimableBalance":
    case "claimClaimableBalance":
    case "beginSponsoringFutureReserves":
    case "endSponsoringFutureReserves":
    case "revokeSponsorship":
    case "clawback":
    case "clawbackClaimableBalance":
    case "setTrustLineFlags":
    case "liquidityPoolDeposit":
    case "liquidityPoolWithdraw":
    case "extendFootprintTtl":
    case "restoreFootprint":
      return null;
    default:
      return assertNever(body);
  }
}

/** Accounts whose SEP-29 data entry was read. `ok: false` means they were not checked. */
export type MemoLookup = { ok: true; required: ReadonlySet<string> } | { ok: false };

const NOT_CHECKED: MemoLookup = { ok: false };

/**
 * Reads the SEP-29 data entry of each account in one `getLedgerEntries`
 * request, and confirms with `getNetwork` that the endpoint serves the
 * network the transaction is signed for (another network's ledger says
 * nothing about these accounts). Sends only the ledger keys. Never throws;
 * any failure or unexpected response leaves every account unchecked.
 */
export async function lookupMemoRequired(accounts: readonly string[], rpc: RpcConfig, networkPassphrase: string): Promise<MemoLookup> {
  const unique = [...new Set(accounts)].sort();
  if (unique.length === 0) return { ok: true, required: new Set() };
  if (unique.length > MAX_LEDGER_KEYS || !unique.every((a) => StrKey.isValidEd25519PublicKey(a))) return NOT_CHECKED;

  const keys = new Map(unique.map((a) => [dataKey(a).toXdr("base64"), a]));
  const [entries, network] = await Promise.all([
    callRpc(rpc, "getLedgerEntries", { keys: [...keys.keys()] }, MAX_SIMULATION_RESPONSE_BYTES),
    callRpc(rpc, "getNetwork", {}, MAX_SIMULATION_RESPONSE_BYTES),
  ]);
  if (!network.ok || networkField(network.result, "passphrase") !== networkPassphrase) return NOT_CHECKED;
  if (!entries.ok) return NOT_CHECKED;
  return parseEntries(entries.result, keys);
}

function dataKey(account: string): xdr.LedgerKey {
  return xdr.LedgerKey.data(
    new xdr.LedgerKeyData({
      accountId: xdr.PublicKey.publicKeyTypeEd25519(StrKey.decodeEd25519PublicKey(account)),
      dataName: MEMO_REQUIRED_DATA_NAME,
    }),
  );
}

// Absent `entries` means none of the keys exist (no account, or no entry).
function parseEntries(result: Record<string, unknown>, keys: ReadonlyMap<string, string>): MemoLookup {
  const raw = entriesField(result, "entries") ?? [];
  if (!isLedger(entriesField(result, "latestLedger")) || !Array.isArray(raw) || raw.length > keys.size) return NOT_CHECKED;
  const required = new Set<string>();
  const seen = new Set<string>();
  for (const e of raw) {
    if (!isRecord(e) || typeof e["key"] !== "string" || typeof e["xdr"] !== "string") return NOT_CHECKED;
    const account = keys.get(e["key"]);
    if (account === undefined || seen.has(e["key"])) return NOT_CHECKED;
    seen.add(e["key"]);
    let data: xdr.LedgerEntryData;
    try {
      data = xdr.LedgerEntryData.fromXdr(e["xdr"], "base64");
    } catch {
      return NOT_CHECKED;
    }
    // The entry must be the one asked for: this account's SEP-29 data entry.
    if (data.type !== "data") return NOT_CHECKED;
    const entry = data.data;
    if (accountId(entry.accountId) !== account || !sameBytes(entry.dataName.bytes, MEMO_REQUIRED_DATA_NAME)) return NOT_CHECKED;
    const value = entry.dataValue.toBytes();
    if (value.length === 1 && value[0] === MEMO_REQUIRED_VALUE) required.add(account);
  }
  return { ok: true, required };
}

function sameBytes(bytes: Uint8Array, ascii: string): boolean {
  return bytes.length === ascii.length && bytes.every((b, i) => b === ascii.charCodeAt(i));
}

function entriesField<K extends keyof Api.RawGetLedgerEntriesResponse>(result: Record<string, unknown>, key: K): unknown {
  return Object.hasOwn(result, key) ? result[key] : undefined;
}

function networkField<K extends keyof Api.GetNetworkResponse>(result: Record<string, unknown>, key: K): unknown {
  return Object.hasOwn(result, key) ? result[key] : undefined;
}
