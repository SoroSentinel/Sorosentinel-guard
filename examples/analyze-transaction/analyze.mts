// Minimal usage sample: analyze a base64 transaction envelope before signing,
// with an Intel snapshot file and a pinned snapshot public key, and print the
// structured result. See README.md next to this file.
//
//   node examples/analyze-transaction/analyze.mts --network testnet \
//     --snapshot snapshot-testnet-latest.json --key-id <id> --public-key <hex> \
//     --xdr-file tx.b64
//
// It prints codes and facts only. Public prose comes from the wording
// renderer, which this sample does not call.
import { readFileSync } from "node:fs";
import { analyze, sanitizeUntrusted } from "../../packages/core/src/index.ts";
import type { AnalysisResult } from "../../packages/core/src/index.ts";

const PASSPHRASES = {
  testnet: "Test SDF Network ; September 2015",
  public: "Public Global Stellar Network ; September 2015",
} as const;

interface Args {
  network: keyof typeof PASSPHRASES;
  snapshot: string;
  keyId: string;
  publicKey: Uint8Array;
  xdr: string;
  asOf: Date;
  json: boolean;
}

function usage(msg: string): never {
  throw new Error(
    `${msg}\nusage: analyze.mts --network testnet|public --snapshot <file> --key-id <id> --public-key <64 hex> ` +
      `(--xdr <base64> | --xdr-file <file>) [--as-of <ISO time>] [--json]`,
  );
}

function parseArgs(argv: string[]): Args {
  const v: Record<string, string> = {};
  let json = false;
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--json") {
      json = true;
      continue;
    }
    const value = argv[i + 1];
    if (flag === undefined || !flag.startsWith("--") || value === undefined) usage(`bad argument ${flag ?? ""}`);
    v[flag.slice(2)] = value;
    i++;
  }
  const network = v["network"];
  if (network !== "testnet" && network !== "public") usage("--network must be testnet or public");
  const hex = v["public-key"] ?? "";
  if (!/^[0-9a-f]{64}$/.test(hex)) usage("--public-key must be 32 bytes of lowercase hex");
  const publicKey = new Uint8Array(32);
  for (let i = 0; i < 32; i++) publicKey[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  const xdr = v["xdr"] ?? (v["xdr-file"] !== undefined ? readFileSync(v["xdr-file"], "utf8").trim() : undefined);
  if (xdr === undefined) usage("--xdr or --xdr-file is required");
  const snapshot = v["snapshot"];
  const keyId = v["key-id"];
  if (snapshot === undefined || keyId === undefined) usage("--snapshot and --key-id are required");
  // The caller supplies the reference time; Guard itself never reads the clock.
  const asOf = v["as-of"] !== undefined ? new Date(v["as-of"]) : new Date();
  if (Number.isNaN(asOf.getTime())) usage("--as-of must be an ISO time");
  return { network, snapshot, keyId, publicKey, xdr, asOf, json };
}

// Amounts are bigint stroops (7-decimal fixed point); JSON.stringify needs help.
const bigintAsString = (_k: string, v: unknown): unknown => (typeof v === "bigint" ? v.toString() : v);

// Facts and asset codes can carry attacker-chosen text: strip control and
// bidi characters before they reach a terminal.
function print(r: AnalysisResult): void {
  console.log(`status: ${r.status}`);
  console.log(`tx_hash: ${r.txHash ?? "none"}`);
  console.log(`network: ${r.network}`);
  console.log(`operations: ${r.operationCount}`);
  console.log(`snapshot: ${r.snapshotStatus}`);
  if (r.unanalyzableReason !== undefined) console.log(`unanalyzable_reason: ${r.unanalyzableReason}`);
  console.log(`effects: ${r.effects.length}`);
  for (const e of r.effects) {
    const max = e.deltaMax === null ? "unbounded" : e.deltaMax.toString();
    console.log(`  ${e.account} ${sanitizeUntrusted(e.asset)} delta_min=${e.deltaMin} delta_max=${max} assurance=${e.assurance}`);
  }
  console.log(`findings: ${r.findings.length}`);
  for (const f of r.findings) {
    const op = f.operationIndex === null ? "" : ` op=${f.operationIndex}`;
    const facts = Object.entries(f.facts).map(([k, val]) => `${k}=${sanitizeUntrusted(val)}`).join(" ");
    console.log(`  ${f.severity} ${f.code}${op}${facts === "" ? "" : ` ${facts}`}`);
  }
  console.log(`not_checked: ${r.notChecked.length === 0 ? "none" : r.notChecked.join(", ")}`);
}

try {
  const args = parseArgs(process.argv.slice(2));
  const result = analyze(args.xdr, {
    networkPassphrase: PASSPHRASES[args.network],
    asOf: args.asOf,
    snapshot: {
      data: JSON.parse(readFileSync(args.snapshot, "utf8")),
      pinnedKeys: { [args.keyId]: args.publicKey },
    },
  });
  if (args.json) console.log(JSON.stringify(result, bigintAsString, 2));
  else print(result);
} catch (err) {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 2;
}
