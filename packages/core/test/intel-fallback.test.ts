import { readFileSync } from "node:fs";

import { Keypair } from "@stellar/stellar-sdk/base";
import { describe, expect, it } from "vitest";

import { analyze, analyzeAsync, canonicalKey, snapshotHash, snapshotPayload } from "../src/index.ts";
import type { AnalysisResult, AnalyzeContext, IntelApiConfig, Snapshot } from "../src/index.ts";

const FIXTURES = new URL("../../../fixtures/tx/", import.meta.url);
const BASE = "https://intel.example.test";

// Fixture accounts (scripts/gen-fixtures.ts) and Intel's test snapshot key.
const key = (b: number) => Keypair.fromRawEd25519Seed(new Uint8Array(32).fill(b));
const SOURCE = key(1).publicKey();
const DESTINATION = key(2).publicKey();
const SNAPSHOT_KEY = key(7);
const PINNED = { "test-key-1": SNAPSHOT_KEY.rawPublicKey() };

const MIN_TIME = 1_793_059_200;
const AS_OF = new Date(MIN_TIME * 1000 + 60_000);
const AS_OF_ISO = new Date(MIN_TIME * 1000).toISOString().replace(".000Z", "Z");

/** A verified snapshot flagging exactly `entries` ("<type>|<key>"), empty by default. */
function snapshot(entries: string[] = [], stale = false): Snapshot {
  const hashes = [...new Set(entries.map(hashOf))].sort();
  const s: Snapshot = {
    format_version: 1,
    network: "public",
    version: 1,
    // 2 hours old: past DEFAULT_MAX_AGE_SECONDS only when asked to be stale.
    generated_at: AS_OF_ISO,
    ruleset_version: "2026.10.1",
    key_id: "test-key-1",
    entries: hashes,
    signature: "",
    ...(stale ? { generated_at: new Date(MIN_TIME * 1000 - 3 * 3600_000).toISOString().replace(".000Z", "Z") } : {}),
  };
  s.signature = btoa(String.fromCharCode(...SNAPSHOT_KEY.sign(snapshotPayload(s))));
  return s;
}

const hashOf = (id: string): string => {
  const [type, k] = id.split("|") as [string, string];
  return snapshotHash(canonicalKey("public", type, k));
};

interface Fixture {
  xdr: string;
  network_passphrase: string;
}

function fixture(name: string): Fixture {
  return JSON.parse(readFileSync(new URL(name, FIXTURES), "utf8")) as Fixture;
}

// A payment with a memo to an existing account: no simulation and no SEP-29
// lookup are needed, so counterparties are the only open question.
const PAYMENT = fixture("benign/memo_id.json");

type Levels = Record<string, string>;

interface Call {
  url: string;
  body: { entities: { network: string; type: string; key: string }[] };
}

/** An Intel that echoes each requested entity with the level named in `levels`. */
function intel(levels: Levels, overrides: Partial<IntelApiConfig> = {}): { config: IntelApiConfig; calls: Call[] } {
  const calls: Call[] = [];
  return {
    calls,
    config: {
      url: BASE,
      ...overrides,
      fetch: (input: string | URL | Request, init?: RequestInit) => {
        const body = JSON.parse(String(init?.body)) as Call["body"];
        calls.push({ url: String(input), body });
        const results = body.entities.map((e) => ({
          entity: e,
          signal_level: levels[`${e.type}|${e.key}`] ?? "no_signals",
          as_of: AS_OF_ISO,
          facts: {},
          statements: [],
        }));
        return Promise.resolve(new Response(JSON.stringify({ results }), { status: 200, headers: { "content-type": "application/json" } }));
      },
    },
  };
}

const flaggedDest = (r: AnalysisResult) => r.findings.filter((f) => f.code === "G-DEST-FLAGGED").map((f) => f.facts["key"]);

function ctx(extra: Partial<AnalyzeContext> = {}): AnalyzeContext {
  return { networkPassphrase: PAYMENT.network_passphrase, asOf: AS_OF, ...extra };
}

describe("the Intel fallback is opt-in", () => {
  it("nothing is sent without a configured endpoint", async () => {
    const r = await analyzeAsync(PAYMENT.xdr, ctx());
    expect(r.snapshotStatus).toBe("not_provided");
    expect(r.notChecked).toContain("NC-COUNTERPARTY-SIGNALS");
    expect(r.status).toBe("partial");
  });

  it("the synchronous analyze never calls it", () => {
    const { config, calls } = intel({ [`account|${DESTINATION}`]: "caution" });
    const r = analyze(PAYMENT.xdr, ctx({ intel: config }));
    expect(calls).toHaveLength(0);
    expect(r.notChecked).toContain("NC-COUNTERPARTY-SIGNALS");
    expect(r.status).toBe("partial");
  });

  it("only the configured Intel endpoint is contacted, with entity keys alone", async () => {
    const { config, calls } = intel({});
    await analyzeAsync(PAYMENT.xdr, ctx({ intel: config }));
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe(`${BASE}/v1/entities:batchGet`);
    expect(Object.keys(calls[0]?.body ?? {})).toEqual(["entities"]);
    expect(JSON.stringify(calls[0]?.body)).not.toContain(PAYMENT.xdr.slice(0, 32));
    // Both accounts, sorted by key: the order is Guard's, not the endpoint's.
    expect(calls[0]?.body.entities).toEqual([SOURCE, DESTINATION].sort().map((k) => ({ network: "public", type: "account", key: k })));
  });

  it("a network Intel does not cover is never asked", async () => {
    const unknown = fixture("hostile/unknown_network.json");
    const { config, calls } = intel({});
    const r = await analyzeAsync(unknown.xdr, {
      networkPassphrase: unknown.network_passphrase,
      asOf: AS_OF,
      intel: config,
      snapshot: { data: snapshot(), pinnedKeys: PINNED },
    });
    expect(calls).toHaveLength(0);
    expect(r.snapshotStatus).toBe("not_applicable");
    expect(r.notChecked).toContain("NC-NETWORK-COVERAGE");
  });

  it("without asOf nothing is asked: Guard reads no clock of its own", async () => {
    const { config, calls } = intel({});
    const r = await analyzeAsync(PAYMENT.xdr, { networkPassphrase: PAYMENT.network_passphrase, intel: config });
    expect(calls).toHaveLength(0);
    expect(r.notChecked).toContain("NC-COUNTERPARTY-SIGNALS");
  });
});

describe("the snapshot comes first", () => {
  it("a verified snapshot settles counterparties, so Intel is not asked", async () => {
    const { config, calls } = intel({ [`account|${DESTINATION}`]: "high_caution" });
    const r = await analyzeAsync(PAYMENT.xdr, ctx({ intel: config, snapshot: { data: snapshot([`account|${SOURCE}`]), pinnedKeys: PINNED } }));
    expect(calls).toHaveLength(0);
    expect(r.snapshotStatus).toBe("verified");
    expect(flaggedDest(r)).toEqual([SOURCE]);
    expect(r.notChecked).toEqual(["NC-EXECUTION-TIME"]);
    expect(r.status).toBe("findings_present");
  });

  it("an empty verified snapshot is still an answer: nothing is asked", async () => {
    const { config, calls } = intel({});
    const r = await analyzeAsync(PAYMENT.xdr, ctx({ intel: config, snapshot: { data: snapshot(), pinnedKeys: PINNED } }));
    expect(calls).toHaveLength(0);
    expect(r.status).toBe("no_issues_found");
  });

  it("a snapshot that settles nothing leaves Intel to answer", async () => {
    const { config, calls } = intel({ [`account|${DESTINATION}`]: "caution" });
    const r = await analyzeAsync(PAYMENT.xdr, ctx({ intel: config, snapshot: { data: snapshot([], true), pinnedKeys: PINNED } }));
    expect(calls).toHaveLength(1);
    // The snapshot's own state is what is reported; the fallback does not rewrite it.
    expect(r.snapshotStatus).toBe("stale");
    expect(flaggedDest(r)).toEqual([DESTINATION]);
    expect(r.notChecked).toEqual(["NC-EXECUTION-TIME"]);
    expect(r.status).toBe("findings_present");
  });

  it("the same flag gives the same finding from the snapshot and from the API", async () => {
    const flagged = `account|${DESTINATION}`;
    const fromSnapshot = await analyzeAsync(PAYMENT.xdr, ctx({ snapshot: { data: snapshot([flagged]), pinnedKeys: PINNED } }));
    const { config } = intel({ [flagged]: "caution" });
    const fromApi = await analyzeAsync(PAYMENT.xdr, ctx({ intel: config }));
    expect(fromApi.findings).toEqual(fromSnapshot.findings);
    expect(fromApi.notChecked).toEqual(fromSnapshot.notChecked);
    expect(fromApi.status).toBe(fromSnapshot.status);
  });
});

describe("a failed fallback is never a clean result", () => {
  const failing: [string, IntelApiConfig][] = [
    ["timeout", { url: BASE, timeoutMs: 20, fetch: () => new Promise<Response>(() => undefined) }],
    ["network", { url: BASE, fetch: () => { throw new TypeError("down"); } }],
    [
      "http 503",
      { url: BASE, fetch: () => Promise.resolve(new Response('{"error":"unavailable"}', { status: 503 })) },
    ],
    [
      "not JSON",
      { url: BASE, fetch: () => Promise.resolve(new Response("<html>proxy</html>", { status: 200 })) },
    ],
    [
      "wrong number of results",
      { url: BASE, fetch: () => Promise.resolve(new Response('{"results":[]}', { status: 200 })) },
    ],
    [
      "an invented level",
      {
        url: BASE,
        fetch: (_u: string | URL | Request, init?: RequestInit) => {
          const body = JSON.parse(String(init?.body)) as { entities: unknown[] };
          const results = body.entities.map((e) => ({ entity: e, signal_level: "safe", as_of: AS_OF_ISO, facts: {}, statements: [] }));
          return Promise.resolve(new Response(JSON.stringify({ results }), { status: 200 }));
        },
      },
    ],
    ["http endpoint", { url: "http://intel.example.test" }],
  ];

  it.each(failing)("%s: partial, and counterparties stay unchecked", async (_name, config) => {
    const r = await analyzeAsync(PAYMENT.xdr, ctx({ intel: config }));
    expect(r.notChecked, _name).toContain("NC-COUNTERPARTY-SIGNALS");
    expect(r.status, _name).toBe("partial");
    expect(r.findings, _name).toEqual([]);
  });

  it("a failed fallback gives the same answer as no intel at all", async () => {
    const none = await analyzeAsync(PAYMENT.xdr, ctx());
    const failed = await analyzeAsync(PAYMENT.xdr, ctx({ intel: { url: "http://intel.example.test" } }));
    expect(failed.notChecked).toEqual(none.notChecked);
    expect(failed.status).toBe(none.status);
  });
});
