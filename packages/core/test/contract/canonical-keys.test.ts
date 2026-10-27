import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { KeyError, canonicalKey, snapshotHash } from "../../src/canonical/key.ts";

// Pinned from sorosentinel-intel (intel-schemas/PINNED); never edited here.
const vectors = JSON.parse(readFileSync(new URL("../../../../intel-schemas/canonical_keys.json", import.meta.url), "utf8")) as {
  cases: { name: string; input: { network: string; type: string; key: string }; canonical?: string; hash128?: string; error?: string }[];
};

describe("canonical keys match Intel's vectors", () => {
  it("has cases", () => {
    expect(vectors.cases.length).toBeGreaterThan(0);
  });

  it.each(vectors.cases.map((c) => [c.name, c] as const))("%s", (_name, c) => {
    if (c.error !== undefined) {
      expect(() => canonicalKey(c.input.network, c.input.type, c.input.key)).toThrowError(KeyError);
      try {
        canonicalKey(c.input.network, c.input.type, c.input.key);
      } catch (e) {
        expect((e as KeyError).code).toBe(c.error);
      }
      return;
    }
    const got = canonicalKey(c.input.network, c.input.type, c.input.key);
    expect(got).toBe(c.canonical);
    expect(snapshotHash(got)).toBe(c.hash128);
  });
});
