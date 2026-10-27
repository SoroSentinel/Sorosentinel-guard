import { readdirSync, readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { replay } from "../scripts/replay.ts";

const FIXTURES = new URL("../../../fixtures/tx/", import.meta.url);

function fixtureLines(dir: "benign" | "hostile"): string[] {
  const base = new URL(`${dir}/`, FIXTURES);
  return readdirSync(base)
    .filter((f) => f.endsWith(".json"))
    .sort()
    .map((f) => {
      const { xdr, network_passphrase } = JSON.parse(readFileSync(new URL(f, base), "utf8")) as { xdr: string; network_passphrase: string };
      return JSON.stringify({ xdr, network_passphrase });
    });
}

describe("replay harness (E2)", () => {
  it("decodes every benign fixture", () => {
    const lines = fixtureLines("benign");
    const s = replay(lines);
    expect(s.total).toBe(lines.length);
    expect(s.unanalyzable).toBe(0);
    expect(s.unanalyzableRate).toBe(0);
    expect(Object.keys(s.operations)).toHaveLength(27);
    expect(s.benignWarningRate).toBe("not_measured");
  });

  it("counts failures by reason and reports line numbers only", () => {
    const lines = [...fixtureLines("hostile"), "", "not json", JSON.stringify({ xdr: 1 })];
    const s = replay(lines);
    expect(s.total).toBe(lines.length - 1); // blank line skipped
    expect(s.unanalyzableByReason).toEqual({ decode_failed: 2, bad_input_line: 2 });
    expect(s.unanalyzable).toBe(4);
    expect(s.networks.unknown).toBe(1);
    expect(s.envelopes.fee_bump).toBe(1);
    expect(s.firstFailureLines.every((n) => Number.isInteger(n) && n > 0)).toBe(true);
  });

  it("never emits raw XDR or account keys", () => {
    const lines = fixtureLines("benign");
    const out = JSON.stringify(replay(lines));
    expect(out).not.toMatch(/\bG[A-Z2-7]{55}\b/);
    expect(out).not.toMatch(/AAAA[A-Za-z0-9+/]{40,}/);
  });

  it("handles empty input", () => {
    expect(replay([]).unanalyzableRate).toBe(0);
  });
});
