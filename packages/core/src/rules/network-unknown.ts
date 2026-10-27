import type { Rule } from "./types.ts";

/**
 * G-NETWORK-UNKNOWN: the network passphrase has no Intel coverage. Absence of
 * data is not safety, so the analysis can be at best `partial` (AGENTS.md §3.9).
 */
export const networkUnknown: Rule = (input) =>
  input.tx.network === "unknown"
    ? [{ code: "G-NETWORK-UNKNOWN", severity: "info", operationIndex: null, facts: {}, statement: null }]
    : [];
