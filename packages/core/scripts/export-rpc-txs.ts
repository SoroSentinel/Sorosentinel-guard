// Experiment E2 input: export recent transactions from a configured Stellar RPC
// endpoint into the JSON Lines file `make replay` consumes.
// Run: node packages/core/scripts/export-rpc-txs.ts --url https://soroban-testnet.stellar.org
//
// Writes public envelope XDR only. The default path is gitignored and no
// transaction file is ever committed. The summary prints counts and a network
// label, never the passphrase, addresses, hashes or transaction content.
import { mkdirSync, writeFileSync } from "node:fs";

import { Server } from "@stellar/stellar-sdk/rpc";

const DEFAULT_OUT = new URL("../../../replay/rpc-txs.jsonl", import.meta.url);
const PAGE_LIMIT = 100;
const MAX_PAGES = 500;
const MAX_TOTAL_BYTES = 256 << 20;

interface Options {
  url: string;
  out: string | URL;
  count: number;
  ledgers: number;
  fromLedger?: number;
}

interface Summary {
  /** Which network the export came from, named rather than echoed: the
   *  passphrase itself never goes to stdout. */
  network: NetworkLabel;
  requested: number;
  written: number;
  ledgerRange: [number, number];
  pages: number;
  bytes: number;
  stopped: "count" | "exhausted" | "max_pages" | "max_bytes";
}

type NetworkLabel = "testnet" | "public" | "unknown";

export function networkLabel(passphrase: string): NetworkLabel {
  if (passphrase === "Test SDF Network ; September 2015") return "testnet";
  if (passphrase === "Public Global Stellar Network ; September 2015") return "public";
  return "unknown";
}

const USAGE =
  "usage: export-rpc-txs.ts --url <https rpc endpoint> [--count 10000] [--ledgers 500] [--from-ledger N] [--out replay/rpc-txs.jsonl]";

export function parseArgs(argv: readonly string[]): Options | null {
  const opts: Partial<Options> = { count: 10_000, ledgers: 500, out: DEFAULT_OUT };
  for (let i = 0; i < argv.length; i += 2) {
    const flag = argv[i];
    const value = argv[i + 1];
    if (flag === undefined || value === undefined || !flag.startsWith("--")) return null;
    switch (flag) {
      case "--url":
        opts.url = value;
        break;
      case "--out":
        opts.out = value;
        break;
      case "--count":
        opts.count = positiveInt(value);
        break;
      case "--ledgers":
        opts.ledgers = positiveInt(value);
        break;
      case "--from-ledger":
        opts.fromLedger = positiveInt(value);
        break;
      default:
        return null;
    }
  }
  if (opts.url === undefined || !/^https:\/\//.test(opts.url)) return null;
  if (opts.count === undefined || opts.ledgers === undefined || opts.out === undefined) return null;
  return opts as Options;
}

function positiveInt(value: string): number {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n <= 0) throw new Error(`expected a positive integer, got ${value}`);
  return n;
}

function parentOf(out: string | URL): string | URL {
  if (out instanceof URL) return new URL(".", out);
  const i = out.lastIndexOf("/");
  return i <= 0 ? "." : out.slice(0, i);
}

async function main(argv: readonly string[]): Promise<void> {
  const opts = parseArgs(argv);
  if (opts === null) {
    console.error(USAGE);
    process.exitCode = 2;
    return;
  }

  const server = new Server(opts.url);
  const { passphrase } = await server.getNetwork();
  const latest = (await server.getLatestLedger()).sequence;
  const start = opts.fromLedger ?? Math.max(1, latest - opts.ledgers);

  const lines: string[] = [];
  let bytes = 0;
  let pages = 0;
  let low = start;
  let high = start;
  let cursor: string | undefined;
  let stopped: Summary["stopped"] = "exhausted";

  for (; pages < MAX_PAGES && lines.length < opts.count; pages++) {
    const res =
      cursor === undefined
        ? await server.getTransactions({ startLedger: start, pagination: { limit: PAGE_LIMIT } })
        : await server.getTransactions({ pagination: { cursor, limit: PAGE_LIMIT } });
    if (res.transactions.length === 0) {
      stopped = "exhausted";
      break;
    }
    for (const tx of res.transactions) {
      if (lines.length >= opts.count) {
        stopped = "count";
        break;
      }
      const line = `${JSON.stringify({ xdr: tx.envelopeXdr.toXdr("base64"), network_passphrase: passphrase })}\n`;
      if (bytes + line.length > MAX_TOTAL_BYTES) {
        stopped = "max_bytes";
        break;
      }
      lines.push(line);
      bytes += line.length;
      low = Math.min(low, tx.ledger);
      high = Math.max(high, tx.ledger);
    }
    if (res.cursor === "") {
      stopped = lines.length >= opts.count ? "count" : "exhausted";
      break;
    }
    cursor = res.cursor;
    if (lines.length >= opts.count) stopped = "count";
  }
  if (pages >= MAX_PAGES && stopped !== "count") stopped = "max_pages";

  mkdirSync(parentOf(opts.out), { recursive: true });
  writeFileSync(opts.out, lines.join(""));
  const summary: Summary = {
    network: networkLabel(passphrase),
    requested: opts.count,
    written: lines.length,
    ledgerRange: [low, high],
    pages,
    bytes,
    stopped,
  };
  console.log(JSON.stringify(summary, null, 2));
  if (summary.network === "unknown") {
    console.error("export-rpc-txs: endpoint reported a network this repo does not know; check it before trusting the sample");
  }
  if (lines.length === 0) {
    console.error("export-rpc-txs: no transactions exported");
    process.exitCode = 1;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2)).catch((err: unknown) => {
    console.error(`export-rpc-txs: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
  });
}
