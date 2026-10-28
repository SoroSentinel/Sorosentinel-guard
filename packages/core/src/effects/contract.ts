import { Asset, StrKey, type xdr } from "@stellar/stellar-sdk/base";

import { assertNever } from "../assert-never.ts";
import type { SimulationTrace, StateChange } from "../simulate/simulate.ts";
import { InvalidOperation, accountId, creditKey } from "./asset.ts";
import type { Assurance, UncoveredReason } from "./types.ts";

/** A balance change before aggregation. Shared with derive.ts. */
export interface Delta {
  account: string;
  asset: string;
  min: bigint;
  max: bigint | null;
  assurance: Assurance;
}

/**
 * Balance changes of one simulated invocation. `complete` only when every
 * change the invocation makes is accounted for; otherwise the operation stays
 * uncovered and the deltas are what could be read.
 */
export type ContractEffects =
  | { complete: true; deltas: Delta[] }
  | { complete: false; reason: Extract<UncoveredReason, "contract_events_malformed" | "contract_effects_incomplete">; deltas: Delta[] };

/** SEP-41 / CAP-46-6 events that move balances, and how many address topics each carries. */
type BalanceEvent = "transfer" | "mint" | "burn" | "clawback";
const ADDRESS_TOPICS: Record<BalanceEvent, readonly number[]> = {
  transfer: [2], // from, to
  // CAP-67 dropped the admin topic; the pre-CAP-67 form (admin first) is still read.
  mint: [1, 2], // [admin,] to
  burn: [1], // from
  clawback: [1, 2], // [admin,] from
};

interface Movement {
  /** Address of the contract that emitted the event (`C…`). */
  contract: string;
  /** Canonical classic asset key when the emitter is that asset's Stellar Asset Contract. */
  sacAsset: string | null;
  account: string;
  amount: bigint;
}

class Malformed extends Error {}

/**
 * Derives balance effects from a successful simulation.
 *
 * Events are what a contract says it did (ARCHITECTURE §17 EC11), so every
 * event-derived delta starts as `contract_reported`. An event is attributed to
 * a Stellar Asset Contract (SAC) only when its emitting contract is the SAC
 * address derived from the SEP-11 asset string in its topics: events carry the
 * emitter's address set by the host, and SAC addresses are reserved for the
 * built-in contract (CAP-46-6, CAP-67). Even then, `ledger` is used only for
 * `G…` balances whose account and trustline entry diffs in `stateChanges`
 * match the SAC events exactly.
 */
export function contractEffects(trace: SimulationTrace, networkPassphrase: string): ContractEffects {
  if (!trace.ok) return { complete: false, reason: "contract_events_malformed", deltas: [] };
  try {
    return derive(trace.events, trace.stateChanges, networkPassphrase);
  } catch (err) {
    if (err instanceof Malformed || err instanceof InvalidOperation) {
      return { complete: false, reason: "contract_events_malformed", deltas: [] };
    }
    throw err;
  }
}

function derive(events: readonly xdr.DiagnosticEvent[], stateChanges: readonly StateChange[] | null, networkPassphrase: string): ContractEffects {
  const movements: Movement[] = [];
  let unrecognized = false;
  for (const e of events) {
    // Events from calls that failed were rolled back.
    if (!e.inSuccessfulContractCall) continue;
    const m = contractEvent(e.event, networkPassphrase);
    if (m === null) unrecognized = true;
    else movements.push(...m);
  }

  const sac = movements.filter((m) => m.sacAsset !== null);
  const ledger = stateChanges === null ? null : ledgerDiffs(stateChanges, new Set(sac.map((m) => m.contract)));
  const confirmed = ledger !== null && sameDeltas(netByKey(sac.filter((m) => isAccount(m.account))), ledger.balances);

  const deltas = movements.map((m): Delta => {
    const asset = m.sacAsset ?? m.contract;
    const assurance: Assurance = m.sacAsset !== null && confirmed && isAccount(m.account) ? "ledger" : "contract_reported";
    return { account: m.account, asset, min: m.amount, max: m.amount, assurance };
  });

  // Custom tokens and other contracts can change state without events, so an
  // invocation is complete only when it moved nothing but confirmed SAC balances.
  const complete = !unrecognized && confirmed && ledger !== null && ledger.onlySac && sac.length === movements.length;
  return complete ? { complete, deltas } : { complete: false, reason: "contract_effects_incomplete", deltas };
}

/** Movements from one contract event; null when it is not a balance event Guard reads. */
function contractEvent(event: xdr.ContractEvent, networkPassphrase: string): Movement[] | null {
  switch (event.type.name) {
    case "system":
    case "diagnostic":
      return [];
    case "contract":
      break;
    default:
      return assertNever(event.type.name);
  }
  if (event.contractId === null) throw new Malformed("contract event without a contract");
  const contract = StrKey.encodeContract(event.contractId.toBytes());
  switch (event.body.type) {
    case "v0":
      return balanceEvent(contract, event.body.v0.topics, event.body.v0.data, networkPassphrase);
    default:
      return assertNever(event.body.type);
  }
}

function balanceEvent(contract: string, topics: readonly xdr.ScVal[], data: xdr.ScVal, networkPassphrase: string): Movement[] | null {
  const head = topics[0];
  const name = head === undefined ? null : symbol(head);
  if (name === null || !isBalanceEvent(name)) return null;

  // Address topics, then optionally the SEP-11 asset string.
  const rest = topics.slice(1);
  const last = rest[rest.length - 1];
  const assetString = last !== undefined && last.type === "scvString" ? ascii(last.str.bytes) : null;
  const addresses = (last !== undefined && last.type === "scvString" ? rest.slice(0, -1) : rest).map(address);
  if (!ADDRESS_TOPICS[name].includes(addresses.length)) throw new Malformed(`${name}: topic count`);

  const amount = eventAmount(name, data);
  const sacAsset = assetString === null ? null : sacAssetKey(assetString, contract, networkPassphrase);
  const move = (account: string, signed: bigint): Movement => ({ contract, sacAsset, account, amount: signed });
  const lastAddress = addresses[addresses.length - 1] ?? "";
  switch (name) {
    case "transfer":
      return [move(addresses[0] ?? "", -amount), move(lastAddress, amount)];
    case "mint":
      return [move(lastAddress, amount)];
    case "burn":
    case "clawback":
      return [move(lastAddress, -amount)];
    default:
      return assertNever(name);
  }
}

function isBalanceEvent(name: string): name is BalanceEvent {
  return Object.hasOwn(ADDRESS_TOPICS, name);
}

/**
 * The amount is an i128, or for transfer and mint (CAP-67) a map with
 * `amount` and an optional `to_muxed_id`. Negative amounts are malformed.
 */
function eventAmount(name: BalanceEvent, data: xdr.ScVal): bigint {
  let value: xdr.ScVal = data;
  if (data.type === "scvMap" && (name === "transfer" || name === "mint")) {
    const entries = data.map ?? [];
    const keys = entries.map((e) => symbol(e.key));
    const amount = entries[keys.indexOf("amount")];
    if (amount === undefined || keys.some((k) => k !== "amount" && k !== "to_muxed_id") || new Set(keys).size !== keys.length) {
      throw new Malformed(`${name}: data map`);
    }
    value = amount.val;
  }
  if (value.type !== "scvI128") throw new Malformed(`${name}: amount type`);
  const amount = (value.i128.hi << 64n) | value.i128.lo;
  if (amount < 0n) throw new Malformed(`${name}: negative amount`);
  return amount;
}

/**
 * Canonical asset key when `assetString` is a SEP-11 asset whose SAC address is
 * `contract`; null otherwise (the string is then an untrusted claim).
 */
function sacAssetKey(assetString: string, contract: string, networkPassphrase: string): string | null {
  let asset: Asset;
  if (assetString === "native") {
    asset = Asset.native();
  } else {
    const parts = assetString.split(":");
    const [code, issuer] = parts;
    if (parts.length !== 2 || code === undefined || issuer === undefined || !/^[A-Za-z0-9]{1,12}$/.test(code) || !StrKey.isValidEd25519PublicKey(issuer)) {
      return null;
    }
    asset = new Asset(code, issuer);
  }
  if (asset.contractId(networkPassphrase) !== contract) return null;
  return asset.isNative() ? "native" : `${asset.getCode()}:${asset.getIssuer()}`;
}

/** Strkey of an address that can hold a token balance. Muxed accounts are normalized to `G…`. */
function address(v: xdr.ScVal): string {
  if (v.type !== "scvAddress") throw new Malformed("topic is not an address");
  const a = v.address;
  switch (a.type) {
    case "scAddressTypeAccount":
      return accountId(a.accountId);
    case "scAddressTypeContract":
      return StrKey.encodeContract(a.contractId.toBytes());
    case "scAddressTypeMuxedAccount":
      return StrKey.encodeEd25519PublicKey(a.muxedAccount.ed25519.toBytes());
    case "scAddressTypeClaimableBalance":
    case "scAddressTypeLiquidityPool":
      // Not token holders a contract invocation can pay (CAP-67 uses them for classic events only).
      throw new Malformed("unsupported address type");
    default:
      return assertNever(a);
  }
}

interface LedgerDiffs {
  /** Net native and trustline balance changes of `G…` accounts, keyed "account|asset". */
  balances: Map<string, bigint>;
  /** Every change is a balance, a TTL, or storage of a SAC that emitted events. */
  onlySac: boolean;
}

function ledgerDiffs(changes: readonly StateChange[], sacContracts: ReadonlySet<string>): LedgerDiffs {
  const balances = new Map<string, bigint>();
  const add = (key: string, d: bigint) => balances.set(key, (balances.get(key) ?? 0n) + d);
  let onlySac = true;
  for (const c of changes) {
    switch (c.key.type) {
      case "account": {
        const [before, after] = [c.before, c.after].map((e) => (e === null ? null : asAccount(e)));
        const account = accountId(c.key.account.accountId);
        if ((before && accountId(before.accountId) !== account) || (after && accountId(after.accountId) !== account)) {
          throw new Malformed("account entry does not match its key");
        }
        add(`${account}|native`, (after?.balance ?? 0n) - (before?.balance ?? 0n));
        break;
      }
      case "trustline": {
        const [before, after] = [c.before, c.after].map((e) => (e === null ? null : asTrustline(e)));
        const account = accountId(c.key.trustLine.accountId);
        const asset = trustlineAsset(c.key.trustLine.asset);
        for (const e of [before, after]) {
          if (e && (accountId(e.accountId) !== account || trustlineAsset(e.asset) !== asset)) {
            throw new Malformed("trustline entry does not match its key");
          }
        }
        if (asset === null) onlySac = false;
        else add(`${account}|${asset}`, (after?.balance ?? 0n) - (before?.balance ?? 0n));
        break;
      }
      case "ttl":
        // Lifetime extensions move no value.
        break;
      case "contractData": {
        // TODO(verify): SAC balance storage layout for contract holders; not
        // decoded, so `C…` SAC balances stay contract_reported.
        const owner = c.key.contractData.contract;
        if (owner.type !== "scAddressTypeContract" || !sacContracts.has(StrKey.encodeContract(owner.contractId.toBytes()))) onlySac = false;
        break;
      }
      case "offer":
      case "data":
      case "claimableBalance":
      case "liquidityPool":
      case "contractCode":
      case "configSetting":
        onlySac = false;
        break;
      default:
        return assertNever(c.key);
    }
  }
  return { balances, onlySac };
}

function asAccount(e: xdr.LedgerEntry): xdr.AccountEntry {
  if (e.data.type !== "account") throw new Malformed("entry type does not match its key");
  return e.data.account;
}

function asTrustline(e: xdr.LedgerEntry): xdr.TrustLineEntry {
  if (e.data.type !== "trustline") throw new Malformed("entry type does not match its key");
  return e.data.trustLine;
}

/** Canonical key of a trustline's asset; null for pool shares (no canonical key yet). */
function trustlineAsset(asset: xdr.TrustLineAsset): string | null {
  switch (asset.type) {
    case "assetTypeNative":
      throw new Malformed("trustline to the native asset");
    case "assetTypeCreditAlphanum4":
      return creditKey(asset.alphaNum4.assetCode.toBytes(), asset.alphaNum4.issuer);
    case "assetTypeCreditAlphanum12":
      return creditKey(asset.alphaNum12.assetCode.toBytes(), asset.alphaNum12.issuer);
    case "assetTypePoolShare":
      return null;
    default:
      return assertNever(asset);
  }
}

function netByKey(movements: readonly Movement[]): Map<string, bigint> {
  const out = new Map<string, bigint>();
  for (const m of movements) {
    const key = `${m.account}|${m.sacAsset ?? m.contract}`;
    out.set(key, (out.get(key) ?? 0n) + m.amount);
  }
  return out;
}

/** Equal after dropping zero nets. */
function sameDeltas(a: ReadonlyMap<string, bigint>, b: ReadonlyMap<string, bigint>): boolean {
  const nonZero = (m: ReadonlyMap<string, bigint>) => [...m].filter(([, v]) => v !== 0n);
  const x = nonZero(a);
  const y = new Map(nonZero(b));
  return x.length === y.size && x.every(([k, v]) => y.get(k) === v);
}

function isAccount(address: string): boolean {
  return address.startsWith("G");
}

function symbol(v: xdr.ScVal): string | null {
  return v.type === "scvSymbol" ? ascii(v.sym.bytes) : null;
}

/** Printable ASCII only; anything else is not a name or asset string Guard reads. */
function ascii(bytes: Uint8Array): string | null {
  let s = "";
  for (const b of bytes) {
    if (b < 0x20 || b > 0x7e) return null;
    s += String.fromCharCode(b);
  }
  return s;
}
