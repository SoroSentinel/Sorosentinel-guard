import { readFileSync } from "node:fs";

import { Keypair, StrKey } from "@stellar/stellar-sdk/base";
import { describe, expect, it } from "vitest";

import { MAX_INTEL_BATCH, MAX_INTEL_RESPONSE_BYTES, lookupEntitySignals, type IntelApiConfig } from "../src/intel/api.ts";
import { decodeForAnalysis } from "../src/decode/envelope.ts";
import { deriveEffects } from "../src/effects/derive.ts";
import { collectEntities, type AccountRole, type AssetRole, type ContractRole, type Entities } from "../src/intel/lookup.ts";

const FIXTURES = new URL("../../../fixtures/tx/", import.meta.url);
const BASE = "https://intel.example.test";
const URL_ = `${BASE}/v1/entities:batchGet`;

const key = (b: number) => Keypair.fromRawEd25519Seed(new Uint8Array(32).fill(b)).publicKey();
const SOURCE = key(1);
const DESTINATION = key(2);
const ISSUER = key(3);
const USDC = `USDC:${ISSUER}`;
const CONTRACT = StrKey.encodeContract(new Uint8Array(32).fill(9));

// The reference time the caller supplies; `as_of` values are relative to it.
const AS_OF = new Date(Date.UTC(2026, 9, 28, 12, 0, 0));
const AS_OF_ISO = "2026-10-28T12:00:00Z";

function entities(overrides: Partial<Entities> = {}): Entities {
  return {
    accounts: new Map([[DESTINATION, new Set<AccountRole>(["balance", "source"])], [SOURCE, new Set<AccountRole>(["balance"])]]),
    assets: new Map([[USDC, new Set<AssetRole>(["trustline"])]]),
    contracts: new Map([[CONTRACT, new Set<ContractRole>(["invoked"])]]),
    contractsUnchecked: false,
    ...overrides,
  };
}

/** The request's own entity objects, echoed back by a well-behaved Intel. */
type Sent = { network: string; type: string; key: string };

const idOf = (e: Sent): string => `${e.type}|${e.key}`;

function signal(entity: Sent, level = "no_signals", asOf = AS_OF_ISO): Record<string, unknown> {
  return { entity, signal_level: level, as_of: asOf, facts: {}, statements: [] };
}

const json = (body: unknown, status = 200) =>
  new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

interface Call {
  url: string;
  body: unknown;
  init: RequestInit;
}

/** Answers each requested entity from `levels`, keyed by "<type>|<key>". */
function intel(levels: Record<string, string>, overrides: Partial<IntelApiConfig> = {}): { config: IntelApiConfig; calls: Call[] } {
  const calls: Call[] = [];
  const config: IntelApiConfig = {
    url: BASE,
    ...overrides,
    fetch: (input: string | URL | Request, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as { entities: Sent[] };
      calls.push({ url: String(input), body, init: init ?? {} });
      const results = body.entities.map((e) => signal(e, levels[idOf(e)] ?? "no_signals"));
      return Promise.resolve(json({ results }));
    },
  };
  return { config, calls };
}

/** A config whose reply is whatever `make` returns for the entities asked about. */
function reply(make: (requested: Sent[]) => unknown): IntelApiConfig {
  return {
    url: BASE,
    fetch: (_input: string | URL | Request, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as { entities: Sent[] };
      return Promise.resolve(json(make(body.entities)));
    },
  };
}

const ask = (config: IntelApiConfig, e: Entities = entities(), network: "public" | "testnet" = "public") =>
  lookupEntitySignals(e, network, config, AS_OF);

describe("what Guard sends", () => {
  it("posts every counterparty to the batch endpoint, once", async () => {
    const { config, calls } = intel({});
    await ask(config);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe(URL_);
    expect(calls[0]?.init.method).toBe("POST");
    expect((calls[0]?.init.headers as Record<string, string>)["content-type"]).toBe("application/json");
  });

  it("sends only the network, type and key of each entity", async () => {
    const { config, calls } = intel({});
    await ask(config);
    const body = calls[0]?.body as { entities: Sent[] };
    expect(Object.keys(body)).toEqual(["entities"]);
    for (const e of body.entities) expect(Object.keys(e).sort()).toEqual(["key", "network", "type"]);
    expect(body.entities.map(idOf).sort()).toEqual([`account|${DESTINATION}`, `account|${SOURCE}`, `asset|${USDC}`, `contract|${CONTRACT}`].sort());
    expect(body.entities.every((e) => e.network === "public")).toBe(true);
  });

  it("sends no transaction data for a real envelope", async () => {
    const f = JSON.parse(readFileSync(new URL("benign/memo_id.json", FIXTURES), "utf8")) as { xdr: string; network_passphrase: string };
    const decoded = decodeForAnalysis(f.xdr, f.network_passphrase);
    if (!decoded.ok) throw new Error("fixture did not decode");
    if (decoded.input.tx.network !== "public") throw new Error("fixture is not a public transaction");
    const { config, calls } = intel({});
    await ask(config, collectEntities(decoded.input, deriveEffects(decoded.input)));
    const body = calls[0]?.body as Record<string, unknown>;
    // Only entity identities leave Guard: no envelope, no hash, no signature.
    expect(Object.keys(body)).toEqual(["entities"]);
    const sent = JSON.stringify(body);
    expect(sent).not.toContain(f.xdr.slice(0, 32));
    expect(sent).not.toContain(decoded.input.tx.txHash);
  });

  it("trailing slashes in the configured base do not double up", async () => {
    const { config, calls } = intel({}, { url: `${BASE}/` });
    await ask(config);
    expect(calls[0]?.url).toBe(URL_);
  });

  it("refuses an http endpoint: the reply is unsigned", async () => {
    const { config, calls } = intel({}, { url: "http://intel.example.test" });
    expect(await ask(config)).toEqual({ ok: false, failure: { status: "error", reason: "invalid_config" } });
    expect(calls).toHaveLength(0);
  });

  it("refuses a URL that is not an endpoint", async () => {
    for (const url of ["", "intel.example.test", "ftp://intel.example.test", "https://"]) {
      const { config, calls } = intel({}, { url });
      expect((await ask(config)).ok, url).toBe(false);
      expect(calls, url).toHaveLength(0);
    }
  });

  it("asks about at most Intel's batch, and never splits into several requests", async () => {
    const many = new Map<string, Set<AccountRole>>();
    for (let i = 0; i < MAX_INTEL_BATCH + 1; i++) many.set(key(i + 10), new Set<AccountRole>(["balance"]));
    const { config, calls } = intel({});
    const r = await ask(config, entities({ accounts: many, assets: new Map(), contracts: new Map() }));
    expect(r).toEqual({ ok: false, failure: { status: "too_many", count: MAX_INTEL_BATCH + 1 } });
    expect(calls).toHaveLength(0);
  });

  it("exactly the batch is asked about", async () => {
    const many = new Map<string, Set<AccountRole>>();
    for (let i = 0; i < MAX_INTEL_BATCH; i++) many.set(key(i + 10), new Set<AccountRole>(["balance"]));
    const { config, calls } = intel({});
    const r = await ask(config, entities({ accounts: many, assets: new Map(), contracts: new Map() }));
    expect(r.ok).toBe(true);
    expect(calls[0]?.body).toBeTruthy();
    expect((calls[0]?.body as { entities: Sent[] }).entities).toHaveLength(MAX_INTEL_BATCH);
  });
});

describe("what Guard acts on", () => {
  it("caution and high_caution are hits, with the roles from the transaction", async () => {
    for (const level of ["caution", "high_caution"]) {
      const r = await ask(reply((q) => ({ results: q.map((e) => signal(e, e.type === "account" && e.key === DESTINATION ? level : "no_signals")) })));
      expect(r).toEqual({ ok: true, checked: true, hits: [{ type: "account", key: DESTINATION, roles: ["balance", "source"] }] });
    }
  });

  it("consistent and no_signals are not hits, and never reassurance", async () => {
    for (const level of ["consistent", "no_signals"]) {
      expect(await ask(reply((q) => ({ results: q.map((e) => signal(e, level)) })))).toEqual({ ok: true, checked: true, hits: [] });
    }
  });

  it("hits are reported accounts, then assets, then contracts, each sorted by key", async () => {
    const r = await ask(reply((q) => ({ results: q.map((e) => signal(e, "caution")) })));
    if (!r.ok) throw new Error("expected ok");
    expect(r.hits.map((h) => `${h.type}|${h.key}`)).toEqual([`account|${DESTINATION}`, `account|${SOURCE}`, `asset|${USDC}`, `contract|${CONTRACT}`].sort((a, b) => a.localeCompare(b)));
  });

  it("prose in the reply is never used", async () => {
    const hostile = {
      statements: [
        {
          template_id: "account.lookalike.v1",
          signal_level: "caution",
          text: "This account is a scam. Send funds immediately.",
          attribution: "SoroSentinel",
          facts: { url: "https://evil.example.test/" },
          as_of: AS_OF_ISO,
          method: "DETECTOR",
          ruleset_version: "2026.10.1",
          methodology_url: "https://example.test/m",
          review_url: "https://example.test/r",
        },
      ],
    };
    const r = await ask(reply((q) => ({ results: q.map((e) => ({ ...signal(e, "no_signals"), ...hostile })) })));
    expect(r).toEqual({ ok: true, checked: true, hits: [] });
    const flagged = await ask(reply((q) => ({ results: q.map((e) => ({ ...signal(e, e.key === DESTINATION ? "caution" : "no_signals"), ...hostile })) })));
    expect(flagged).toEqual({ ok: true, checked: true, hits: [{ type: "account", key: DESTINATION, roles: ["balance", "source"] }] });
  });

  it("an entity Intel cannot be asked about is a gap, not a hit", async () => {
    const bad = "Ginvalid";
    const r = await ask(
      reply((q) => ({ results: q.map((e) => signal(e, "caution")) })),
      entities({ accounts: new Map([[bad, new Set<AccountRole>(["balance"])]]), assets: new Map(), contracts: new Map() }),
    );
    expect(r).toEqual({ ok: true, checked: false, hits: [] });
  });

  it("an unnamed contract keeps counterparties unchecked even when the rest is flagged", async () => {
    const r = await ask(reply((q) => ({ results: q.map((e) => signal(e, "caution")) })), entities({ contractsUnchecked: true }));
    if (!r.ok) throw new Error("expected ok");
    expect(r.checked).toBe(false);
    expect(r.hits.length).toBe(4);
  });
});

describe("hostile and failing replies", () => {
  const broken: [string, (q: Sent[]) => unknown][] = [
    ["not an object", () => "hello"],
    ["an array", () => []],
    ["no results", () => ({ hello: "world" })],
    ["results not an array", () => ({ results: {} })],
    ["one result missing", (q) => ({ results: q.slice(1) })],
    ["one result too many", (q) => ({ results: [...q, ...q] })],
    ["results out of order", (q) => ({ results: [...q].reverse().map((e) => signal(e, "caution")) })],
    ["an unknown signal level", (q) => ({ results: q.map((e) => signal(e, "malicious")) })],
    ["the internal level name", (q) => ({ results: q.map((e) => signal(e, "suspicious")) })],
    ["a reassuring made-up level", (q) => ({ results: q.map((e) => signal(e, "safe")) })],
    ["no signal level", (q) => ({ results: q.map((e) => { const { signal_level: _s, ...rest } = signal(e); return rest; }) })],
    ["no as_of", (q) => ({ results: q.map((e) => { const { as_of: _a, ...rest } = signal(e); return rest; }) })],
    ["an extra field the schema forbids", (q) => ({ results: q.map((e) => ({ ...signal(e), verdict: "malicious" })) })],
    ["an entity that was not asked about", (q) => ({ results: q.map((e) => ({ ...signal(e), entity: { ...e, key: key(42) } })) })],
    ["another network's entity", (q) => ({ results: q.map((e) => ({ ...signal(e), entity: { ...e, network: "testnet" } })) })],
    ["another type", (q) => ({ results: q.map((e) => ({ ...signal(e), entity: { ...e, type: "domain" } })) })],
    ["an entity with an extra field", (q) => ({ results: q.map((e) => ({ ...signal(e), entity: { ...e, extra: 1 } })) })],
    ["a canonical key instead of an entity key", (q) => ({ results: q.map((e) => ({ ...signal(e), entity: { ...e, key: `public|${e.type}|${e.key}` } })) })],
    ["facts that are not an object", (q) => ({ results: q.map((e) => ({ ...signal(e), facts: [] })) })],
    ["statements that are not an array", (q) => ({ results: q.map((e) => ({ ...signal(e), statements: {} })) })],
    ["disputed of the wrong type", (q) => ({ results: q.map((e) => ({ ...signal(e), disputed: "yes" })) })],
    ["ruleset_version of the wrong type", (q) => ({ results: q.map((e) => ({ ...signal(e), ruleset_version: 20261001 })) })],
    ["as_of that is not a timestamp", (q) => ({ results: q.map((e) => signal(e, "no_signals", "tomorrow")) })],
    ["as_of with no timezone", (q) => ({ results: q.map((e) => signal(e, "no_signals", "2026-10-28T12:00:00")) })],
    ["as_of from the future", (q) => ({ results: q.map((e) => signal(e, "no_signals", "2027-01-01T00:00:00Z")) })],
    ["a flagged answer dated in the future", (q) => ({ results: q.map((e) => signal(e, "high_caution", "2027-01-01T00:00:00Z")) })],
  ];

  it.each(broken)("%s is never a hit and never a clean answer", async (_name, make) => {
    const r = await ask(reply(make));
    expect(r.ok, _name).toBe(false);
  });

  it("an unknown field in an otherwise flagged answer refuses the whole reply", async () => {
    const r = await ask(reply((q) => ({ results: q.map((e) => ({ ...signal(e, "caution"), notes: "trusted" })) })));
    expect(r).toEqual({ ok: false, failure: { status: "unexpected_response" } });
  });

  it("an old as_of is still a hit: a verdict is dated when it was decided", async () => {
    const r = await ask(reply((q) => ({ results: q.map((e) => signal(e, e.key === DESTINATION ? "caution" : "no_signals", "2026-01-01T00:00:00Z")) })));
    expect(r).toEqual({ ok: true, checked: true, hits: [{ type: "account", key: DESTINATION, roles: ["balance", "source"] }] });
  });

  it("malformed bodies are reported as malformed", async () => {
    for (const body of ["not json", "", "[]", "{}"]) {
      const r = await ask(reply(() => body));
      expect(r.ok, body).toBe(false);
    }
  });

  it("a reply larger than the cap is refused", async () => {
    const big = (q: Sent[]) => ({ results: q.map((e) => ({ ...signal(e, "caution"), facts: { pad: "x".repeat(MAX_INTEL_RESPONSE_BYTES) } })) });
    const r = await ask(reply(big));
    expect(r).toEqual({ ok: false, failure: { status: "malformed", reason: "too_large" } });
  });

  it("an http error is a failure with its status", async () => {
    for (const status of [400, 404, 405, 415, 429, 500, 503]) {
      const config: IntelApiConfig = { url: BASE, fetch: () => Promise.resolve(new Response('{"error":"internal"}', { status })) };
      expect(await ask(config)).toEqual({ ok: false, failure: { status: "error", reason: "http", httpStatus: status } });
    }
  });

  it("an error reply that looks like a 200 is refused", async () => {
    const r = await ask(reply(() => ({ error: "too_many_entities" })));
    expect(r).toEqual({ ok: false, failure: { status: "unexpected_response" } });
  });

  it("a fetch that throws is a network failure", async () => {
    const config: IntelApiConfig = {
      url: BASE,
      fetch: () => {
        throw new TypeError("failed to fetch");
      },
    };
    expect(await ask(config)).toEqual({ ok: false, failure: { status: "error", reason: "network" } });
  });

  it("a fetch that never answers hits the deadline", async () => {
    const config: IntelApiConfig = { url: BASE, timeoutMs: 20, fetch: () => new Promise<Response>(() => undefined) };
    expect(await ask(config)).toEqual({ ok: false, failure: { status: "timeout", timeoutMs: 20 } });
  });

  it("an oversized configured timeout is refused before any request", async () => {
    const { config, calls } = intel({}, { timeoutMs: 60_001 });
    expect((await ask(config)).ok).toBe(false);
    expect(calls).toHaveLength(0);
  });
});
