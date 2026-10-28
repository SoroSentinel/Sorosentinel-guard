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

/** Another fixture, by directory and name, for the states the contract covers. */
const other = (dir: "benign" | "hostile", name: string) =>
  new URL(`../../../fixtures/tx/${dir}/${name}.json`, import.meta.url).pathname;

const key = (b: number) => Keypair.fromRawEd25519Seed(new Uint8Array(32).fill(b));
const ISSUER = key(3).publicKey(); // the fixture's USDC issuer (scripts/gen-fixtures.ts)
const SNAPSHOT_KEY = key(7);
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

const MIN_TIME = 1_793_059_200; // fixture time bounds start here
const GENERATED = new Date(MIN_TIME * 1000);
const AS_OF = new Date(MIN_TIME * 1000 + 60_000).toISOString();

function snapshotFile(entries: string[], generatedAt: Date = GENERATED): string {
  const s: Snapshot = {
    format_version: 1,
    network: "testnet",
    version: 1,
    generated_at: generatedAt.toISOString().replace(".000Z", "Z"),
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

function runExample(
  snapshot: string,
  publicKey: string,
  extra: string[] = [],
  fixture: string = FIXTURE.pathname,
) {
  const { xdr } = JSON.parse(readFileSync(fixture, "utf8")) as { xdr: string };
  return spawnSync(
    process.execPath,
    [EXAMPLE, "--network", "testnet", "--snapshot", snapshot, "--key-id", "test-key-1", "--public-key", publicKey,
      "--xdr", xdr, "--as-of", AS_OF, ...extra],
    { encoding: "utf8" },
  );
}

/** The `findings:` block of the human output, in the order it was printed. */
function printedFindings(stdout: string): string[] {
  const lines = stdout.split("\n");
  const start = lines.findIndex((l) => l.startsWith("findings:"));
  if (start === -1) throw new Error(`no findings block in:\n${stdout}`);
  return lines.slice(start + 1).filter((l) => l.startsWith("  ")).map((l) => l.trim().split(" ")[1] as string);
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

  // ADR 0005 (#38): these are the states a host must not be able to drop. The
  // reference integrator prints all of them, so a wallet team is pointed at an
  // executable example rather than a paragraph, and CI fails if the example
  // ever learns to render only the tidy case.
  describe("states the integrator contract makes non-suppressible", () => {
    const pub = () => hex(SNAPSHOT_KEY.rawPublicKey());
    const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

    it("an aged-out snapshot reads as stale and never as a clean result", () => {
      const stale = snapshotFile(
        [snapshotHash(canonicalKey("testnet", "asset", `USDC:${ISSUER}`))],
        new Date(GENERATED.getTime() - 3 * 60 * 60 * 1000),
      );
      const r = runExample(stale, pub());
      expect(r.status, r.stderr).toBe(0);
      expect(r.stdout).toContain("snapshot: stale");
      expect(r.stdout).toContain("NC-COUNTERPARTY-SIGNALS");
      expect(r.stdout).not.toMatch(/status: (no_issues_found|findings_present)$/m);
    });

    it("an operation Guard only decodes keeps its partial status", () => {
      const r = runExample(flagged, pub(), [], other("benign", "decode_only_clawback"));
      expect(r.status, r.stderr).toBe(0);
      expect(r.stdout).toContain("status: partial");
      expect(r.stdout).toMatch(/^operations: 1$/m);
    });

    it("an undecodable transaction says so and still exits 0", () => {
      const r = runExample(flagged, pub(), [], other("hostile", "truncated_xdr"));
      expect(r.status, r.stderr).toBe(0);
      expect(r.stdout).toContain("status: unanalyzable");
      expect(r.stdout).toContain("unanalyzable_reason:");
      expect(r.stdout).toContain("not_checked:");
    });

    it("refuses a network it does not know rather than guessing one", () => {
      // The library's unknown-passphrase path (partial + G-NETWORK-UNKNOWN) is
      // covered in analyze.test.ts; here the point is that the host cannot even
      // ask: --network is validated before anything is decoded.
      const { xdr } = JSON.parse(readFileSync(other("hostile", "unknown_network"), "utf8")) as { xdr: string };
      const r = spawnSync(
        process.execPath,
        [EXAMPLE, "--network", "arbitrary", "--snapshot", flagged, "--key-id", "test-key-1", "--public-key", pub(),
          "--xdr", xdr, "--as-of", AS_OF],
        { encoding: "utf8" },
      );
      expect(r.status).toBe(2);
      expect(r.stdout).toBe("");
      expect(r.stderr).toContain("--network must be testnet or public");
    });

    it("prints every finding, most severe first", () => {
      const fixture = other("hostile", "padding_buried_set_options");
      const human = runExample(flagged, pub(), [], fixture);
      expect(human.status, human.stderr).toBe(0);
      const machine = JSON.parse(runExample(flagged, pub(), ["--json"], fixture).stdout) as {
        findings: { code: string; severity: string }[];
      };
      expect(machine.findings.length).toBeGreaterThan(1);
      expect(printedFindings(human.stdout)).toEqual(machine.findings.map((f) => f.code));
      const ranks = machine.findings.map((f) => SEVERITY_RANK[f.severity] as number);
      expect(ranks).toEqual([...ranks].sort((a, b) => a - b));
    });

    it("shows the hash and the operation count for a fee-bump", () => {
      const r = runExample(flagged, pub(), [], other("hostile", "fee_bump"));
      expect(r.status, r.stderr).toBe(0);
      expect(r.stdout).toMatch(/^tx_hash: [0-9a-f]{64}$/m);
      expect(r.stdout).toMatch(/^operations: \d+$/m);
    });
  });
});
