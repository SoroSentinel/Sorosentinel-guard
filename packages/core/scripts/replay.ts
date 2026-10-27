// Experiment E2: replay historical transactions through the decoder.
// Run: node packages/core/scripts/replay.ts <file.jsonl> [--max-unanalyzable-rate 0.02]
//
// Input: JSON Lines, one {"xdr": "<base64 envelope>", "network_passphrase": "..."} per line.
// Output: aggregate statistics only. Raw XDR, hashes and addresses are never printed.
import { readFileSync } from "node:fs";

import { decodeEnvelope } from "../src/index.ts";
import type { OperationType, UnanalyzableReason } from "../src/index.ts";

export interface ReplayStats {
  total: number;
  decoded: number;
  unanalyzable: number;
  unanalyzableRate: number;
  unanalyzableByReason: Partial<Record<UnanalyzableReason | "bad_input_line", number>>;
  /** 1-based input line numbers of the first failures (no content). */
  firstFailureLines: number[];
  envelopes: Record<string, number>;
  networks: Record<string, number>;
  operations: Partial<Record<OperationType, number>>;
  /** Decoded transactions containing at least one decode-only operation (effects partial). */
  txWithDecodeOnlyOps: number;
  /** Requires effects and rules; reported once those exist. */
  benignWarningRate: "not_measured";
}

const MAX_FAILURE_LINES = 20;

export function replay(lines: Iterable<string>): ReplayStats {
  const s: ReplayStats = {
    total: 0, decoded: 0, unanalyzable: 0, unanalyzableRate: 0, unanalyzableByReason: {},
    firstFailureLines: [], envelopes: {}, networks: {}, operations: {}, txWithDecodeOnlyOps: 0,
    benignWarningRate: "not_measured",
  };
  let lineNo = 0;
  for (const raw of lines) {
    lineNo++;
    const line = raw.trim();
    if (line === "") continue;
    s.total++;
    const input = parseLine(line);
    const res = input ? decodeEnvelope(input.xdr, input.passphrase) : null;
    if (!res || !res.ok) {
      const reason = res ? res.reason : "bad_input_line";
      s.unanalyzable++;
      s.unanalyzableByReason[reason] = (s.unanalyzableByReason[reason] ?? 0) + 1;
      if (s.firstFailureLines.length < MAX_FAILURE_LINES) s.firstFailureLines.push(lineNo);
      continue;
    }
    s.decoded++;
    bump(s.envelopes, res.tx.envelope);
    bump(s.networks, res.tx.network);
    for (const op of res.tx.operations) bump(s.operations, op.type);
    if (res.tx.operations.some((op) => op.support === "decode_only")) s.txWithDecodeOnlyOps++;
  }
  s.unanalyzableRate = s.total === 0 ? 0 : s.unanalyzable / s.total;
  return s;
}

function parseLine(line: string): { xdr: string; passphrase: string } | null {
  try {
    const v: unknown = JSON.parse(line);
    if (typeof v !== "object" || v === null) return null;
    const { xdr, network_passphrase } = v as Record<string, unknown>;
    return typeof xdr === "string" && typeof network_passphrase === "string" ? { xdr, passphrase: network_passphrase } : null;
  } catch {
    return null;
  }
}

function bump<K extends string>(m: Partial<Record<K, number>>, k: K): void {
  m[k] = (m[k] ?? 0) + 1;
}

function main(argv: string[]): void {
  const [file, flag, value] = argv;
  if (!file || (flag !== undefined && flag !== "--max-unanalyzable-rate")) {
    console.error("usage: replay.ts <file.jsonl> [--max-unanalyzable-rate <0..1>]");
    process.exitCode = 2;
    return;
  }
  const stats = replay(readFileSync(file, "utf8").split("\n"));
  console.log(JSON.stringify(stats, null, 2));
  const limit = value === undefined ? undefined : Number(value);
  if (limit !== undefined && (!Number.isFinite(limit) || stats.unanalyzableRate > limit)) {
    console.error(`unanalyzable rate ${stats.unanalyzableRate.toFixed(4)} exceeds ${value}`);
    process.exitCode = 1;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2));
}
