import { describe, expect, it } from "vitest";

import { networkLabel, parseArgs } from "../scripts/export-rpc-txs.ts";

const URL_OK = "https://soroban-testnet.stellar.org";

describe("export-rpc-txs (E2 input)", () => {
  it("names the two known networks and nothing else", () => {
    expect(networkLabel("Test SDF Network ; September 2015")).toBe("testnet");
    expect(networkLabel("Public Global Stellar Network ; September 2015")).toBe("public");
    // A futurenet or self-hosted passphrase must not be reported as one of the two.
    expect(networkLabel("Test SDF Network ; September 2022")).toBe("unknown");
    expect(networkLabel("")).toBe("unknown");
  });

  it("requires an https url", () => {
    expect(parseArgs(["--url", URL_OK, "--count", "10"])).not.toBeNull();
    expect(parseArgs(["--url", "http://soroban-testnet.stellar.org", "--count", "10"])).toBeNull();
    expect(parseArgs(["--url", "soroban-testnet.stellar.org"])).toBeNull();
    expect(parseArgs([])).toBeNull();
  });

  it("refuses unknown flags and dangling values", () => {
    expect(parseArgs(["--url", URL_OK, "--page-size", "10"])).toBeNull();
    expect(parseArgs(["--url", URL_OK, "--count"])).toBeNull();
    expect(parseArgs(["--count", "10", "--url"])).toBeNull();
  });

  it("refuses counts and ledger windows that are not positive integers", () => {
    for (const bad of ["0", "-1", "1.5", "abc", "1e999"]) {
      expect(() => parseArgs(["--url", URL_OK, "--count", bad])).toThrow(/positive integer/);
      expect(() => parseArgs(["--url", URL_OK, "--ledgers", bad])).toThrow(/positive integer/);
    }
  });

  it("defaults the output under the gitignored replay directory", () => {
    const opts = parseArgs(["--url", URL_OK]);
    const out = typeof opts?.out === "string" ? opts.out : opts!.out.pathname;
    expect(out).toMatch(/replay\/rpc-txs\.jsonl$/);
  });
});
