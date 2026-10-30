import type { Network } from "../decode/types.ts";
import type { Finding, Rule } from "./types.ts";

/**
 * G-NETWORK-UNKNOWN: the network passphrase has no Intel coverage. Absence of
 * data is not safety, so the analysis can be at best `partial` (AGENTS.md §3.9).
 * Shared with `analyzeAuthEntry`, which has no transaction to inspect.
 */
export function networkUnknownFinding(network: Network): Finding[] {
  return network === "unknown"
    ? [{ code: "G-NETWORK-UNKNOWN", severity: "info", operationIndex: null, facts: {}, statement: null }]
    : [];
}

export const networkUnknown: Rule = (input) => networkUnknownFinding(input.tx.network);
