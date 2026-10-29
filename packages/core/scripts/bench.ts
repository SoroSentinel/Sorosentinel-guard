// Guard latency benchmark (PRD §7 target, issue #47).
//
//   node packages/core/scripts/bench.ts [--n <reps>] [--warmup <reps>] [--rpc <https url>] [--json]
//
// Times `analyze` over the committed fixtures with Intel's pinned signing
// vector as the local snapshot, and — with --rpc — `analyzeAsync` over the
// fixtures that carry a Soroban invocation, which is the end-to-end path an
// integrator feels (decode, effects, rules, simulation round trip).
//
// Output is aggregate timings, fixture names and status counts. Transaction
// XDR, hashes and addresses never appear (AGENTS.md §6).
import { readFileSync, readdirSync } from "node:fs";
import { arch, cpus, platform } from "node:os";

import { analyze, analyzeAsync } from "../src/index.ts";
import type { AnalysisResult, AnalyzeContext, Snapshot } from "../src/index.ts";

/** PRD §7: p95 < 800 ms end-to-end with RPC simulation; local path < 100 ms. */
export const PRD_TARGETS_MS = { local: 100, withSimulation: 800 } as const;

/** Below this many samples a p95 is an anecdote, so it is not called a result. */
export const MIN_P95_SAMPLES = 20;

const MAX_REPS = 100_000;
const FIXTURES = new URL("../../../fixtures/tx/", import.meta.url);
/** Signed snapshot from Intel's pinned signing vector (test key, real format). */
const SIGNING_VECTOR = new URL("../../../intel-schemas/snapshot_signing.json", import.meta.url);

export interface Timings {
  case: string;
  samples: number;
  p50Ms: number;
  p95Ms: number;
  maxMs: number;
  /** Status counts ride along, so a fast wrong answer is not read as a pass. */
  statuses: Record<string, number>;
  /** Whether the pinned snapshot actually verified: the claim being measured. */
  snapshotStatuses: Record<string, number>;
}

export interface BenchRecord {
  ran_at: string;
  guard_commit: string;
  node: string;
  machine: { platform: string; arch: string; cpu: string };
  sdk_version: string;
  rpc_endpoint: string | null;
  reps: number;
  warmup: number;
  snapshot_source: string;
  cases: Timings[];
  verdict: Record<string, string>;
}

interface FixtureCase {
  name: string;
  xdr: string;
  passphrase: string;
  invokesContract: boolean;
}

/** Nearest-rank percentile over an unsorted sample; NaN on an empty sample. */
export function percentile(samples: readonly number[], q: number): number {
  if (samples.length === 0) return Number.NaN;
  const sorted = [...samples].sort((a, b) => a - b);
  const rank = Math.max(1, Math.ceil((q / 100) * sorted.length));
  return sorted[rank - 1] ?? Number.NaN;
}

export function loadCases(): FixtureCase[] {
  const out: FixtureCase[] = [];
  for (const dir of ["benign", "hostile"]) {
    for (const file of readdirSync(new URL(`${dir}/`, FIXTURES)).sort()) {
      if (!file.endsWith(".json")) continue;
      const parsed = JSON.parse(readFileSync(new URL(`${dir}/${file}`, FIXTURES), "utf8")) as {
        xdr?: unknown;
        network_passphrase?: unknown;
      };
      if (typeof parsed.xdr !== "string" || typeof parsed.network_passphrase !== "string") continue;
      out.push({
        name: `${dir}/${file.slice(0, -".json".length)}`,
        xdr: parsed.xdr,
        passphrase: parsed.network_passphrase,
        invokesContract: file.startsWith("invoke_contract"),
      });
    }
  }
  return out;
}

/** Intel's pinned vector as a snapshot context, or null if it cannot be read. */
export function pinnedSnapshot(): { data: Snapshot; pinnedKeys: Record<string, Uint8Array>; asOf: Date } | null {
  try {
    const vector = JSON.parse(readFileSync(SIGNING_VECTOR, "utf8")) as {
      public_key_hex: string;
      snapshot: Snapshot;
    };
    const key = Uint8Array.from(vector.public_key_hex.match(/../g) ?? [], (b) => Number.parseInt(b, 16));
    const generated = Date.parse(vector.snapshot.generated_at);
    if (!Number.isFinite(generated) || key.length !== 32) return null;
    // Pinned under the id the snapshot itself claims; a made-up id would verify
    // as `unknown_key` and the run would silently measure the no-snapshot path.
    return { data: vector.snapshot, pinnedKeys: { [vector.snapshot.key_id]: key }, asOf: new Date(generated + 60_000) };
  } catch {
    return null;
  }
}

function collect(name: string, samples: number[], statuses: Record<string, number>, snapshots: Record<string, number>): Timings {
  return {
    case: name,
    samples: samples.length,
    p50Ms: round(percentile(samples, 50)),
    p95Ms: round(percentile(samples, 95)),
    maxMs: round(samples.length === 0 ? Number.NaN : Math.max(...samples)),
    statuses: { ...statuses },
    snapshotStatuses: { ...snapshots },
  };
}

/** The two fields the timing loop reads; a full AnalysisResult satisfies this. */
export type Sampled = Pick<AnalysisResult, "status" | "snapshotStatus">;

/** Warmup runs are called but not sampled, so JIT cost is not reported as latency. */
export function timeCase(name: string, fn: () => Sampled, reps: number, warmup: number): Timings {
  const samples: number[] = [];
  const statuses: Record<string, number> = {};
  const snapshots: Record<string, number> = {};
  for (let i = 0; i < reps + warmup; i++) {
    const started = performance.now();
    const r = fn();
    const elapsed = performance.now() - started;
    // Counted only for timed samples, so the status distribution always sums
    // to `samples` and a reader can reconcile the two.
    if (i >= warmup) {
      samples.push(elapsed);
      statuses[r.status] = (statuses[r.status] ?? 0) + 1;
      snapshots[r.snapshotStatus] = (snapshots[r.snapshotStatus] ?? 0) + 1;
    }
  }
  return collect(name, samples, statuses, snapshots);
}

export async function timeCaseAsync(name: string, fn: () => Promise<Sampled>, reps: number, warmup: number): Promise<Timings> {
  const samples: number[] = [];
  const statuses: Record<string, number> = {};
  const snapshots: Record<string, number> = {};
  for (let i = 0; i < reps + warmup; i++) {
    const started = performance.now();
    const r = await fn();
    const elapsed = performance.now() - started;
    if (i >= warmup) {
      samples.push(elapsed);
      statuses[r.status] = (statuses[r.status] ?? 0) + 1;
      snapshots[r.snapshotStatus] = (snapshots[r.snapshotStatus] ?? 0) + 1;
    }
  }
  return collect(name, samples, statuses, snapshots);
}

function round(n: number): number {
  return Number.isFinite(n) ? Math.round(n * 1000) / 1000 : Number.NaN;
}

/** The PRD §7 verdict for one aggregate, with the sample floor applied. */
export function verdict(c: Timings, targetMs: number): string {
  if (c.samples < MIN_P95_SAMPLES) return `not measurable: n=${c.samples}, needs ${MIN_P95_SAMPLES}`;
  if (!Number.isFinite(c.p95Ms)) return "no samples";
  if ("unanalyzable" in c.statuses) return `fast but unanalyzable (${c.statuses["unanalyzable"]} samples): not a pass`;
  return c.p95Ms < targetMs ? `met (p95 ${c.p95Ms} ms < ${targetMs} ms)` : `not met (p95 ${c.p95Ms} ms >= ${targetMs} ms)`;
}

/**
 * Aggregate across a workload. p95 takes the worst per-case p95 rather than
 * pooling samples: an integrator ships the slowest fixture a wallet signs, and
 * pooling a 30-fixture set would bury it under the fast ones.
 */
export function aggregate(name: string, parts: readonly Timings[]): Timings {
  const statuses: Record<string, number> = {};
  const snapshots: Record<string, number> = {};
  for (const p of parts) {
    for (const [k, v] of Object.entries(p.statuses)) statuses[k] = (statuses[k] ?? 0) + v;
    for (const [k, v] of Object.entries(p.snapshotStatuses)) snapshots[k] = (snapshots[k] ?? 0) + v;
  }
  const finite = (xs: number[]): number => (xs.every(Number.isNaN) ? Number.NaN : Math.max(...xs.filter(Number.isFinite)));
  return {
    case: name,
    samples: parts.reduce((a, p) => a + p.samples, 0),
    p50Ms: round(finite(parts.map((p) => p.p50Ms))),
    p95Ms: round(finite(parts.map((p) => p.p95Ms))),
    maxMs: round(finite(parts.map((p) => p.maxMs))),
    statuses,
    snapshotStatuses: snapshots,
  };
}

export interface Options {
  reps: number;
  warmup: number;
  rpcUrl: string | null;
  commit: string;
}

export async function run(opts: Options): Promise<BenchRecord> {
  const cases = loadCases();
  const snap = pinnedSnapshot();
  const startedAt = new Date();
  // `asOf` is required for a snapshot to be consulted at all (Guard reads no
  // clock), so both ride together or neither does.
  const ctxBase: Pick<AnalyzeContext, "snapshot" | "asOf"> =
    snap !== null
      ? { snapshot: { data: snap.data, pinnedKeys: snap.pinnedKeys }, asOf: snap.asOf }
      : {};
  const localTimings: Timings[] = [];
  const rpcTimings: Timings[] = [];

  for (const c of cases) {
    const ctx: AnalyzeContext = { ...ctxBase, networkPassphrase: c.passphrase };
    localTimings.push(timeCase(`local ${c.name}`, () => analyze(c.xdr, ctx), opts.reps, opts.warmup));
  }
  // A fixture designed to fail decoding (truncated or malformed input) is a
  // correctness case, not a latency case: it must stay `unanalyzable`, and its
  // microseconds must not be averaged into a path claim.
  const analyzedCases = localTimings.filter((t) => !("unanalyzable" in t.statuses));
  const rejectedCases = localTimings.filter((t) => "unanalyzable" in t.statuses);
  // The PRD's "local-snapshot path" is the lookup that only runs when the
  // snapshot verifies. The pinned vector is signed for `public`, so the two
  // testnet fixtures are rejected as network_mismatch and never look anything
  // up; counting them would report a lookup that did not happen.
  const verifiedCases = analyzedCases.filter((t) => "verified" in t.snapshotStatuses);
  const localAll = aggregate("local: analyzable fixtures", analyzedCases);
  const verifiedAll = verifiedCases.length > 0 ? aggregate("local: snapshot-verified fixtures (PRD local path)", verifiedCases) : null;
  const rejectedAll = rejectedCases.length > 0 ? aggregate("local: rejected input (must stay unanalyzable)", rejectedCases) : null;

  if (opts.rpcUrl !== null) {
    for (const c of cases.filter((x) => x.invokesContract)) {
      const ctx: AnalyzeContext = { ...ctxBase, networkPassphrase: c.passphrase, rpc: { url: opts.rpcUrl } };
      rpcTimings.push(await timeCaseAsync(`rpc ${c.name}`, () => analyzeAsync(c.xdr, ctx), opts.reps, opts.warmup));
    }
  }

  const rpcAll = rpcTimings.length > 0 ? aggregate("rpc: all contract calls", rpcTimings) : null;
  const verdicts: Record<string, string> = {
    local_snapshot_path:
      verifiedAll === null ? "no fixture reached a verified snapshot: the local path was not measured"
        : verdict(verifiedAll, PRD_TARGETS_MS.local),
    rejected_input_stays_unanalyzable:
      rejectedAll !== null ? `${rejectedAll.samples} samples across ${rejectedCases.length} fixture(s), all unanalyzable` : "no fixture was rejected by the decoder",
    with_rpc_simulation:
      opts.rpcUrl === null ? "not run: pass --rpc <https endpoint> (needs network)"
        : rpcAll !== null ? verdict(rpcAll, PRD_TARGETS_MS.withSimulation)
          : "no contract-invocation fixture found",
  };

  return {
    ran_at: startedAt.toISOString(),
    guard_commit: opts.commit,
    node: process.version,
    machine: { platform: platform(), arch: arch(), cpu: cpus()[0]?.model ?? "unknown" },
    sdk_version: sdkVersion(),
    rpc_endpoint: opts.rpcUrl,
    reps: opts.reps,
    warmup: opts.warmup,
    snapshot_source: snap !== null ? "intel-schemas/snapshot_signing.json (pinned vector, network public)" : "none: vector unreadable",
    cases: [
      ...localTimings, localAll,
      ...(verifiedAll !== null ? [verifiedAll] : []),
      ...(rejectedAll !== null ? [rejectedAll] : []),
      ...rpcTimings, ...(rpcAll !== null ? [rpcAll] : []),
    ],
    verdict: verdicts,
  };
}

function sdkVersion(): string {
  try {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
      dependencies?: Record<string, string>;
    };
    return pkg.dependencies?.["@stellar/stellar-sdk"] ?? "unknown";
  } catch {
    return "unknown";
  }
}

/** Bad operator input. Thrown, not exited, so the CLI layer owns the exit code. */
export class UsageError extends Error {}

function usage(msg: string): never {
  throw new UsageError(`${msg}\nusage: bench.ts [--n <reps>] [--warmup <reps>] [--rpc <https endpoint>] [--json]`);
}

export function parseArgs(argv: readonly string[]): { opts: Options; json: boolean } {
  const opts: Options = { reps: 200, warmup: 20, rpcUrl: null, commit: process.env["GIT_SHA"] ?? "unknown" };
  let json = false;
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i], value = argv[i + 1];
    if (flag === "--json") json = true;
    else if (flag === "--n") {
      const n = Number(value);
      if (!Number.isInteger(n) || n < 1 || n > MAX_REPS) usage(`--n must be an integer in 1..${MAX_REPS}`);
      opts.reps = n;
      i++;
    } else if (flag === "--warmup") {
      // Kept below MIN_P95_SAMPLES: a run whose warmups outnumber its samples is
      // mostly warmup, so the samples are not a measurement.
      const w = Number(value);
      if (!Number.isInteger(w) || w < 0 || w > Math.min(MAX_REPS, MIN_P95_SAMPLES - 1)) {
        usage(`--warmup must be an integer in 0..${MIN_P95_SAMPLES - 1}`);
      }
      opts.warmup = w;
      i++;
    } else if (flag === "--rpc") {
      if (typeof value !== "string" || !value.startsWith("https://")) usage("--rpc needs an https endpoint");
      opts.rpcUrl = value;
      i++;
    } else usage(`unknown argument ${String(flag)}`);
  }
  return { opts, json };
}

export function format(rec: BenchRecord): string {
  const lines = [
    `Guard latency benchmark (PRD §7)   run ${rec.ran_at}`,
    `commit ${rec.guard_commit}   sdk ${rec.sdk_version}   ${rec.machine.platform}/${rec.machine.arch} ${rec.machine.cpu}   node ${rec.node}`,
    `reps ${rec.reps} per case (${rec.warmup} warmup dropped)   snapshot ${rec.snapshot_source}`,
    `rpc ${rec.rpc_endpoint ?? "none (local path only)"}`,
    "",
  ];
  for (const c of rec.cases) {
    const p95 = c.samples < MIN_P95_SAMPLES ? `${c.p95Ms} ms (n=${c.samples} < ${MIN_P95_SAMPLES})` : `${c.p95Ms} ms`;
    const snap = Object.entries(c.snapshotStatuses).map(([k, v]) => `snapshot=${k}:${v}`).join(" ");
    lines.push(
      `${c.case.padEnd(46)} p50 ${pad(c.p50Ms)} ms   p95 ${p95.padStart(22)}   max ${String(c.maxMs).padStart(8)} ms   ` +
        Object.entries(c.statuses).map(([k, v]) => `${k}:${v}`).join(" ") + (snap !== "" ? `   ${snap}` : ""),
    );
  }
  lines.push("");
  for (const [k, v] of Object.entries(rec.verdict)) lines.push(`${k}: ${v}`);
  lines.push("");
  lines.push(`A p95 is reported as a result only from ${MIN_P95_SAMPLES} samples up.`);
  if (rec.rpc_endpoint === null) lines.push("The < 800 ms target covers the RPC-simulated path; it was not measured in this run.");
  return lines.join("\n");
}

function pad(ms: number): string {
  return (Number.isFinite(ms) ? ms.toFixed(3) : "n/a").padStart(9);
}

async function main(argv: readonly string[]): Promise<void> {
  let opts: Options;
  let json: boolean;
  try {
    ({ opts, json } = parseArgs(argv));
  } catch (err) {
    if (err instanceof UsageError) {
      console.error(err.message);
      process.exit(2);
    }
    throw err;
  }
  const rec = await run(opts);
  console.log(json ? JSON.stringify(rec, null, 2) : format(rec));
  const failed = Object.values(rec.verdict).some((v) => v.startsWith("not met") || v.startsWith("fast but"));
  if (failed && !json) process.exitCode = 1;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  void main(process.argv.slice(2));
}
