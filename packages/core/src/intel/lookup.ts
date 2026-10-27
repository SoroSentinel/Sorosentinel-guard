import { canonicalKey, snapshotHash } from "../canonical/key.ts";
import type { AnalysisInput } from "../decode/envelope.ts";
import type { EffectsResult } from "../effects/types.ts";

export type AccountRole = "source" | "fee_source" | "balance" | "signer" | "merge_destination" | "inflation_destination";
export type AssetRole = "balance" | "trustline";

/** An entity in the transaction that appears in the verified snapshot. */
export type CounterpartyHit =
  | { type: "account"; key: string; roles: AccountRole[] }
  | { type: "asset"; key: string; roles: AssetRole[] };

export interface Entities {
  accounts: Map<string, Set<AccountRole>>;
  assets: Map<string, Set<AssetRole>>;
  /** Contract addresses are not extracted yet, so contract calls are not looked up. */
  contractsUnchecked: boolean;
}

/** Every account and asset the transaction touches, with the roles it plays. */
export function collectEntities(input: AnalysisInput, effects: EffectsResult): Entities {
  const accounts = new Map<string, Set<AccountRole>>();
  const assets = new Map<string, Set<AssetRole>>();
  const addAccount = (k: string, r: AccountRole) => (accounts.get(k) ?? accounts.set(k, new Set()).get(k))?.add(r);
  const addAsset = (k: string, r: AssetRole) => {
    if (k !== "native") (assets.get(k) ?? assets.set(k, new Set()).get(k))?.add(r);
  };

  addAccount(input.tx.source.account, "source");
  if (input.tx.feeSource) addAccount(input.tx.feeSource.account, "fee_source");
  for (const op of input.tx.operations) addAccount(op.source.account, "source");
  for (const e of effects.effects) {
    addAccount(e.account, "balance");
    addAsset(e.asset, "balance");
  }
  for (const e of effects.accountEffects) {
    switch (e.kind) {
      case "trustline":
        addAsset(e.asset, "trustline");
        break;
      case "signer":
        // Only ed25519 signers are accounts; hash(x), pre-auth and payload signers are not.
        if (e.signerType === "ed25519") addAccount(e.signer, "signer");
        break;
      case "merge":
        addAccount(e.destination, "merge_destination");
        break;
      case "inflation_destination":
        addAccount(e.destination, "inflation_destination");
        break;
      case "thresholds":
      case "flags":
      case "home_domain":
        break;
      default: {
        const never: never = e;
        throw new Error(`unhandled account effect: ${String(never)}`);
      }
    }
  }
  return {
    accounts,
    assets,
    contractsUnchecked: input.tx.operations.some((op) => op.type === "invokeHostFunction"),
  };
}

/**
 * Looks every entity up in the snapshot entries. Entities whose key cannot be
 * canonicalized are reported as hits-unknown by the caller via `unresolved`.
 */
export function lookup(
  entities: Entities,
  network: "public" | "testnet",
  entries: ReadonlySet<string>,
): { hits: CounterpartyHit[]; unresolved: number } {
  const hits: CounterpartyHit[] = [];
  let unresolved = 0;
  const check = (type: "account" | "asset", key: string): boolean | null => {
    try {
      return entries.has(snapshotHash(canonicalKey(network, type, key)));
    } catch {
      unresolved++;
      return null;
    }
  };
  for (const [key, roles] of [...entities.accounts].sort(([a], [b]) => (a < b ? -1 : 1))) {
    if (check("account", key)) hits.push({ type: "account", key, roles: [...roles].sort() });
  }
  for (const [key, roles] of [...entities.assets].sort(([a], [b]) => (a < b ? -1 : 1))) {
    if (check("asset", key)) hits.push({ type: "asset", key, roles: [...roles].sort() });
  }
  return { hits, unresolved };
}
