import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";

import { Keypair } from "@stellar/stellar-sdk/base";
import { describe, expect, it } from "vitest";

import { canonicalKey, snapshotHash, snapshotPayload } from "../src/index.ts";
import type { Snapshot } from "../src/index.ts";

// Runs examples/analyze-transaction the way the Intel local demo does: plain
// Node (type stripping), a snapshot file and a pinned public key.
const EXAMPLE = new URL("../../../examples/analyze-transaction/analyze.mts", import.meta.url).pathname;
const FIXTURE = new URL("../../../fixtures/tx/benign/change_trust.json", import.meta.url);

const key = (b: number) => Keypair.fromRawEd25519Seed(new Uint8Array(32).fill(b));
const ISSUER = key(3).publicKey(); // the fixture's USDC issuer (scripts/gen-fixtures.ts)
const SNAPSHOT_KEY = key(7);
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

const MIN_TIME = 1_793_059_200; // fixture time bounds start here
const GENERATED = new Date(MIN_TIME * 1000);
const AS_OF = new Date(MIN_TIME * 1000 + 60_000).toISOString();

function snapshotFile(entries: string[]): string {
  const s: Snapshot = {
    format_version: 1,
    network: "testnet",
    version: 1,
    generated_at: GENERATED.toISOString().replace(".000Z", "Z"),
    ruleset_version: "2026.10.1",
    key_id: "test-key-1",
    entries,
    signature: "",
  };
  s.signature = btoa(String.fromCharCode(...SNAPSHOT_KEY.sign(snapshotPayload(s))));
  const path = `${mkdtempSync(`${tmpdir()}/guard-example-`)}/snapshot.json`;
  writeFileSync(path, JSON.stringify(s));
  return path;
}

function runExample(snapshot: string, publicKey: string, extra: string[] = []) {
  const { xdr } = JSON.parse(readFileSync(FIXTURE, "utf8")) as { xdr: string };
  return spawnSync(
    process.execPath,
    [EXAMPLE, "--network", "testnet", "--snapshot", snapshot, "--key-id", "test-key-1", "--public-key", publicKey,
      "--xdr", xdr, "--as-of", AS_OF, ...extra],
    { encoding: "utf8" },
  );
}

describe("examples/analyze-transaction", () => {
  const flagged = snapshotFile([snapshotHash(canonicalKey("testnet", "asset", `USDC:${ISSUER}`))]);

  it("prints a verified snapshot hit on a trustline to a flagged asset", () => {
    const r = runExample(flagged, hex(SNAPSHOT_KEY.rawPublicKey()));
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toContain("status: findings_present");
    expect(r.stdout).toContain("snapshot: verified");
    expect(r.stdout).toMatch(/^ {2}\S+ G-TRUST-FLAGGED/m);
    expect(r.stdout).toMatch(/^operations: 1$/m);
  });

  it("with the wrong pinned key the snapshot is not used and nothing reads as clean", () => {
    const r = runExample(flagged, hex(key(8).rawPublicKey()));
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).not.toContain("snapshot: verified");
    expect(r.stdout).not.toContain("no_issues_found");
    expect(r.stdout).toContain("NC-COUNTERPARTY-SIGNALS");
  });

  it("--json keeps amounts as strings", () => {
    const r = runExample(flagged, hex(SNAPSHOT_KEY.rawPublicKey()), ["--json"]);
    expect(r.status, r.stderr).toBe(0);
    const out = JSON.parse(r.stdout) as { findings: { code: string }[]; effects: { deltaMin: unknown }[] };
    expect(out.findings.map((f) => f.code)).toContain("G-TRUST-FLAGGED");
    expect(typeof out.effects[0]?.deltaMin).toBe("string");
  });

  it("rejects bad arguments with exit code 2", () => {
    for (const pub of ["", "zz".repeat(32), "AB".repeat(32), "00".repeat(31)]) {
      const r = runExample(flagged, pub);
      expect(r.status).toBe(2);
      expect(r.stdout).toBe("");
    }
    expect(runExample(flagged, hex(SNAPSHOT_KEY.rawPublicKey()), ["--as-of", "not-a-time"]).status).toBe(2);
  });
});
