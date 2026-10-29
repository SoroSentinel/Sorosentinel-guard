import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { KeyError, normalizeKey } from "../../src/canonical/key.ts";
import {
  BATCH_PATH,
  ENTITY_FIELDS,
  ENTITY_SIGNAL_FIELDS,
  ENTITY_SIGNAL_OPTIONAL_FIELDS,
  HIT_LEVELS,
  MAX_INTEL_BATCH,
  SIGNAL_LEVELS,
} from "../../src/intel/api.ts";
import type { HitType } from "../../src/intel/lookup.ts";

// Pinned from sorosentinel-intel (intel-schemas/PINNED); never edited here.
// Guard has no JSON-schema validator, so this file is where the Intel client's
// hand-written shape checks meet Intel's own contract: a schema change on Intel's
// side fails `make verify` instead of silently making Guard accept or reject the
// wrong reply.
interface Schema {
  $ref?: string;
  required?: string[];
  additionalProperties?: unknown;
  properties?: Record<string, Record<string, unknown>>;
  $defs?: Record<string, Record<string, unknown>>;
}

const dir = new URL("../../../../intel-schemas/", import.meta.url);
const json = (name: string): Schema => JSON.parse(readFileSync(new URL(name, dir), "utf8")) as Schema;
const props = (s: Schema): Record<string, Record<string, unknown> | undefined> => s.properties ?? {};
const defs = (s: Schema): Record<string, Record<string, unknown> | undefined> => s.$defs ?? {};
const propNames = (s: Schema): string[] => Object.keys(props(s)).sort();
const ref = (s: Schema, name: string): string => String(props(s)[name]?.["$ref"] ?? "");
const field = (s: Schema, name: string, key: string): unknown => defs(s)[name]?.[key];
const enumOf = (s: Schema, name: string): string[] => (defs(s)[name]?.["enum"] as string[] | undefined) ?? [];

/** One path item of the pinned OpenAPI: `path` up to the next path at the same indent. */
function pathItem(yaml: string, path: string): string {
  const lines = yaml.split("\n");
  const start = lines.indexOf(`  ${path}:`);
  if (start === -1) throw new Error(`the pinned OpenAPI has no ${path}`);
  const body: string[] = [];
  for (const line of lines.slice(start + 1)) {
    if (/^ {2}\S/.test(line)) break;
    body.push(line);
  }
  return body.join("\n");
}

describe("EntitySignal: the reply Guard parses", () => {
  const signal = json("EntitySignal.json");
  const common = json("common.json");

  it("knows every field Intel defines, and no others", () => {
    expect(signal.required).toEqual(ENTITY_SIGNAL_FIELDS);
    expect(propNames(signal)).toEqual([...ENTITY_SIGNAL_FIELDS, ...ENTITY_SIGNAL_OPTIONAL_FIELDS].sort());
  });

  it("closes the object, which is why an unexpected field makes the reply unusable", () => {
    expect(signal.additionalProperties).toBe(false);
    expect(ref(signal, "entity")).toBe("urn:sorosentinel:schema:v1:Entity");
  });

  it("uses Intel's public level names and the hit rule they imply", () => {
    expect(enumOf(common, "signalLevel")).toEqual([...SIGNAL_LEVELS]);
    // Pinning both halves means a fifth public level fails here until someone
    // decides whether it is a hit; Guard must never default to reassurance.
    expect(HIT_LEVELS).toEqual(["caution", "high_caution"]);
    expect(SIGNAL_LEVELS.filter((l) => !HIT_LEVELS.includes(l))).toEqual(["consistent", "no_signals"]);
  });

  it("treats as_of and facts as Intel's shared definitions describe them", () => {
    expect(ref(signal, "as_of")).toBe("urn:sorosentinel:schema:v1:common#/$defs/timestamp");
    expect(field(common, "timestamp", "type")).toBe("string");
    expect(field(common, "timestamp", "format")).toBe("date-time");
    expect(ref(signal, "facts")).toBe("urn:sorosentinel:schema:v1:common#/$defs/facts");
    expect(field(common, "facts", "type")).toBe("object");
  });

  it("accepts optional fields only in the types Intel gives them", () => {
    expect(props(signal)["ruleset_version"]?.["$ref"]).toBe("urn:sorosentinel:schema:v1:common#/$defs/rulesetVersion");
    expect(props(signal)["disputed"]?.["type"]).toBe("boolean");
  });

  it("reads statements as renderer output, then drops it", () => {
    expect(props(signal)["statements"]?.["type"]).toBe("array");
    const items = props(signal)["statements"]?.["items"] as Schema | undefined;
    expect(items?.["$ref"]).toBe("urn:sorosentinel:schema:v1:PublicStatement");
    const statement = json("PublicStatement.json");
    expect(statement.required).toContain("text");
    expect(statement.additionalProperties).toBe(false);
  });
});

describe("Entity: what Guard may ask about", () => {
  const entity = json("Entity.json");
  const common = json("common.json");

  it("sends exactly the fields Intel requires, and nothing else", () => {
    expect(entity.required).toEqual(ENTITY_FIELDS);
    expect(propNames(entity)).toEqual([...ENTITY_FIELDS].sort());
    expect(entity.additionalProperties).toBe(false);
  });

  it("asks only about the networks and types Intel covers", () => {
    expect(enumOf(common, "network")).toEqual(["public", "testnet"]);
    const types = enumOf(common, "entityType");
    const asked: HitType[] = ["account", "asset", "contract"];
    expect(types).toEqual([...asked, "wasm_hash", "domain"]);
    // A WASM hash or a domain is never a transaction counterparty, so Guard
    // collects neither and can never send one.
  });

  it("knows every entity type Intel defines, so a new one is caught here", () => {
    for (const type of enumOf(common, "entityType")) {
      try {
        normalizeKey(type, "x");
      } catch (err) {
        expect(err, type).toBeInstanceOf(KeyError);
        // Only a key Guard cannot canonicalize is allowed to fail: an unknown
        // type would mean Intel's key encoding was not ported here.
        expect((err as KeyError).code, type).not.toBe("unknown_type");
      }
    }
  });

  it("keeps Intel's key length ceiling", () => {
    expect(field(common, "canonicalKey", "minLength")).toBe(1);
    expect(field(common, "canonicalKey", "maxLength")).toBe(300);
    expect(normalizeKey("domain", "example.test")).toBe("example.test");
    expect(() => normalizeKey("domain", `${"a".repeat(300)}.test`)).toThrow(KeyError);
  });
});

describe("the batch endpoint is Intel's, not invented", () => {
  const item = pathItem(readFileSync(new URL("intel.v1.yaml", dir), "utf8"), BATCH_PATH);

  it("is posted to under the integrator's base URL", () => {
    expect(item).toContain("operationId: batchGetEntities");
    expect(item).toContain("required: [entities]");
  });

  it("refuses a batch Intel would reject", () => {
    // Guard returns `too_many` without asking once Intel's ceiling moves.
    expect(item.match(/maxItems: ([0-9]+)/)?.[1]).toBe(String(MAX_INTEL_BATCH));
    // minItems 1 is why Guard answers an empty entity set locally instead of POSTing.
    expect(item).toContain("minItems: 1");
  });

  it("expects one signal per entity, in request order", () => {
    const [request, response] = item.split("responses:");
    expect(request).toContain(`$ref: '../jsonschema/Entity.json'`);
    expect(response).toContain("required: [results]");
    expect(response).toContain("in request order");
    expect(response).toContain(`$ref: '../jsonschema/EntitySignal.json'`);
  });
});
