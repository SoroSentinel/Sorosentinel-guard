import { assertNever } from "../assert-never.ts";
import type { CounterpartyHit } from "../intel/lookup.ts";
import type { Finding, FindingCode, Rule } from "./types.ts";

/**
 * G-DEST-FLAGGED (accounts, and contracts that only hold a balance),
 * G-TRUST-FLAGGED (assets) and G-CONTRACT-FLAGGED (invoked contracts and
 * non-SAC tokens): an entity in the
 * transaction appears in Intel's verified snapshot (ARCHITECTURE §5.2). The
 * snapshot does not say which level, so severity is high; facts name the
 * entity and every role it plays.
 */
export const counterpartyFlagged: Rule = (_input, _effects, ctx) => flaggedFindings(ctx.hits ?? []);

/** Shared with `analyzeAuthEntry`, which checks the contracts an entry authorizes. */
export function flaggedFindings(hits: readonly CounterpartyHit[]): Finding[] {
  return hits.map(
    (h): Finding => ({
      code: code(h),
      severity: "high",
      operationIndex: null,
      facts: { entity_type: h.type, key: h.key, roles: h.roles.join(",") },
      statement: null,
    }),
  );
}

function code(h: CounterpartyHit): FindingCode {
  switch (h.type) {
    case "account":
      return "G-DEST-FLAGGED";
    case "asset":
      return "G-TRUST-FLAGGED";
    case "contract":
      return h.roles.some((r) => r === "invoked" || r === "token") ? "G-CONTRACT-FLAGGED" : "G-DEST-FLAGGED";
    default:
      return assertNever(h);
  }
}
