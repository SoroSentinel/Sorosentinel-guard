import type { Finding, Rule } from "./types.ts";

/**
 * G-DEST-FLAGGED (accounts) and G-TRUST-FLAGGED (assets): an entity in the
 * transaction appears in Intel's verified snapshot (ARCHITECTURE §5.2). The
 * snapshot does not say which level, so severity is high; facts name the
 * entity and every role it plays.
 */
export const counterpartyFlagged: Rule = (_input, _effects, ctx) =>
  (ctx.hits ?? []).map(
    (h): Finding => ({
      code: h.type === "account" ? "G-DEST-FLAGGED" : "G-TRUST-FLAGGED",
      severity: "high",
      operationIndex: null,
      facts: { entity_type: h.type, key: h.key, roles: h.roles.join(",") },
      statement: null,
    }),
  );
