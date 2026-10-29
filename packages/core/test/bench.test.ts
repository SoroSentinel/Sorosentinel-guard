import { describe, expect, it } from "vitest";

import { Networks } from "@stellar/stellar-sdk/base";

import { analyze } from "../src/index.ts";
import { checkSnapshot } from "../src/intel/snapshot.ts";

import {
  UsageError,
  MIN_P95_SAMPLES,
  PRD_TARGETS_MS,
  aggregate,
  loadCases,
  parseArgs,
  percentile,
  pinnedSnapshot,
  timeCase,
  verdict,
  type Sampled,
  type Timings,
} from "../scripts/bench.ts";

const PUBLIC = Networks.PUBLIC;

const resultOf = (status: string, snapshotStatus: string) => ({ status, snapshotStatus }) as Sampled;

const timings = (over: Partial<Timings> = {}): Timings => ({
  case: "x",
  samples: 100,
  p50Ms: 1,
  p95Ms: 2,
  maxMs: 3,
  statuses: { partial: 100 },
  snapshotStatuses: { verified: 100 },
  ...over,
});

describe("percentile (nearest rank)", () => {
  it("is empty-safe and order-independent", () => {
    expect(Number.isNaN(percentile([], 95))).toBe(true);
    expect(percentile([5, 1, 3], 50)).toBe(3);
    expect(percentile([1, 2, 3, 4], 95)).toBe(4);
    expect(percentile([4, 1, 3, 2], 95)).toBe(4);
  });

  it("never returns a value below the q percentile mass", () => {
    const s = Array.from({ length: 100 }, (_, i) => i + 1);
    expect(percentile(s, 95)).toBe(95);
    expect(percentile(s, 1)).toBe(1);
  });
});

describe("verdict applies the PRD target and the sample floor", () => {
  it("passes a fast verified snapshot path and fails a slow one", () => {
    expect(verdict(timings({ p95Ms: PRD_TARGETS_MS.local - 1 }), PRD_TARGETS_MS.local)).toContain("met (");
    expect(verdict(timings({ p95Ms: PRD_TARGETS_MS.local }), PRD_TARGETS_MS.local)).toContain("not met");
  });

  it("refuses a p95 built from too few samples", () => {
    expect(verdict(timings({ samples: MIN_P95_SAMPLES - 1 }), 100)).toContain("not measurable");
  });

  it("never calls an unanalyzable workload a pass, however fast", () => {
    expect(verdict(timings({ p95Ms: 0.1, statuses: { unanalyzable: 100 } }), 100)).toContain("not a pass");
  });

  it("reports no-samples", () => {
    expect(verdict(timings({ p95Ms: Number.NaN }), 100)).toBe("no samples");
  });
});

describe("aggregate takes the worst per-case latency", () => {
  it("does not bury the slow fixture under the fast ones", () => {
    const a = aggregate("a", [timings({ case: "fast", p50Ms: 1, p95Ms: 2, maxMs: 3, samples: 100 }), timings({ case: "slow", p50Ms: 9, p95Ms: 50, maxMs: 99, samples: 100 })]);
    expect(a.p95Ms).toBe(50);
    expect(a.maxMs).toBe(99);
    expect(a.samples).toBe(200);
  });

  it("sums status and snapshot counts across cases", () => {
    const a = aggregate("a", [
      timings({ statuses: { partial: 10 }, snapshotStatuses: { verified: 10 } }),
      timings({ statuses: { partial: 4, findings_present: 1 }, snapshotStatuses: { network_mismatch: 5 } }),
    ]);
    expect(a.statuses).toEqual({ partial: 14, findings_present: 1 });
    expect(a.snapshotStatuses).toEqual({ verified: 10, network_mismatch: 5 });
  });

  it("is NaN on an empty part set rather than a fake zero", () => {
    const a = aggregate("empty", []);
    expect(Number.isNaN(a.p50Ms)).toBe(true);
    expect(a.samples).toBe(0);
  });
});

describe("fixture and vector loading", () => {
  it("loads committed fixtures with their passphrase", () => {
    const cases = loadCases();
    expect(cases.length).toBeGreaterThan(0);
    expect(cases.every((c) => c.name.includes("/") && c.xdr.length > 0 && c.passphrase.length > 0)).toBe(true);
    expect(cases.some((c) => c.invokesContract)).toBe(true);
  });

  it("pins the snapshot under the key id the snapshot itself claims", () => {
    const snap = pinnedSnapshot();
    expect(snap).not.toBeNull();
    if (snap === null) return;
    const data = snap.data;
    expect(Object.keys(snap.pinnedKeys)).toEqual([data.key_id]);
    expect(snap.pinnedKeys[data.key_id]?.length).toBe(32);
    // The vector is signed for `public`; the local-path claim is bound to that
    // network, and asOf sits inside max age of generated_at.
    expect(data.network).toBe("public");
    const generated = Date.parse(data.generated_at);
    expect(snap.asOf.getTime()).toBeGreaterThan(generated);
    expect(snap.asOf.getTime() - generated).toBeLessThanOrEqual(60 * 60 * 1000);
  });

  // Regression: pinning under a made-up key id verified as `unknown_key`, so
  // the benchmark quietly measured the no-snapshot path while claiming the
  // local-snapshot one. The context must produce a real verification.
  it("the pinned context verifies instead of rejecting the key", () => {
    const snap = pinnedSnapshot();
    expect(snap).not.toBeNull();
    if (snap === null) return;
    expect(checkSnapshot(snap.data, { pinnedKeys: snap.pinnedKeys, network: "public", asOf: snap.asOf }).ok).toBe(true);
    expect(checkSnapshot(snap.data, { pinnedKeys: snap.pinnedKeys, network: "testnet", asOf: snap.asOf })).toEqual({
      ok: false,
      reason: "network_mismatch",
    });
  });

  it("reaches `verified` on pubnet fixtures through analyze", () => {
    const snap = pinnedSnapshot();
    expect(snap).not.toBeNull();
    if (snap === null) return;
    const statuses = loadCases()
      .filter((c) => c.passphrase === PUBLIC)
      .map((c) => analyze(c.xdr, { networkPassphrase: c.passphrase, snapshot: { data: snap.data, pinnedKeys: snap.pinnedKeys }, asOf: snap.asOf }).snapshotStatus);
    expect(statuses.length).toBeGreaterThan(0);
    expect(statuses).not.toContain("unknown_key");
    expect(statuses).not.toContain("bad_signature");
    expect(statuses.every((s) => s === "verified" || s === "not_applicable")).toBe(true);
  });
});

describe("timing loop", () => {
  it("reports a distribution that sums to the timed sample count", () => {
    const r = timeCase("x", () => resultOf("partial", "verified"), 7, 3);
    expect(r.samples).toBe(7);
    expect(Object.values(r.statuses).reduce((a, b) => a + b, 0)).toBe(7);
    expect(Object.values(r.snapshotStatuses).reduce((a, b) => a + b, 0)).toBe(7);
  });

  it("excludes warmups from a percentile, so a slow first call is not latency", () => {
    let n = 0;
    const r = timeCase("x", () => {
      n++;
      return resultOf("partial", "verified");
    }, 5, 3);
    expect(r.samples).toBe(5);
    expect(n).toBe(8);
  });
});

describe("argument parsing", () => {
  it("accepts the documented flags", () => {
    const { opts, json } = parseArgs(["--n", "50", "--warmup", "5", "--rpc", "https://soroban-testnet.stellar.org", "--json"]);
    expect(opts.reps).toBe(50);
    expect(opts.warmup).toBe(5);
    expect(opts.rpcUrl).toBe("https://soroban-testnet.stellar.org");
    expect(json).toBe(true);
  });

  it("refuses an http (non-TLS) RPC and an oversized warmup", () => {
    for (const bad of [["--rpc", "http://host"], ["--warmup", String(MIN_P95_SAMPLES)], ["--n", "0"], ["--bogus"], ["--n", "1.5"], ["--warmup", "-1"]]) {
      expect(() => parseArgs(bad), bad.join(" ")).toThrow(UsageError);
    }
  });
});
