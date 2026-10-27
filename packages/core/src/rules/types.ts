import type { AnalysisInput } from "../decode/envelope.ts";
import type { EffectsResult } from "../effects/types.ts";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** Finding codes implemented so far (ARCHITECTURE §5.2). */
export type FindingCode = "G-NETWORK-UNKNOWN";

/**
 * A finding carries structured facts only. `statement` stays null until the
 * code's wording template is counsel-approved; consumers then show facts
 * without prose (fail closed, AGENTS.md §5).
 */
export interface Finding {
  code: FindingCode;
  severity: Severity;
  operationIndex: number | null;
  facts: Record<string, string>;
  statement: null;
}

/** A rule inspects the decoded transaction and its effects; it never reads the clock or the network. */
export type Rule = (input: AnalysisInput, effects: EffectsResult) => Finding[];

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** Most severe first, then by operation, then by code. Never truncated. */
export function orderFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
      (a.operationIndex ?? -1) - (b.operationIndex ?? -1) ||
      (a.code < b.code ? -1 : a.code > b.code ? 1 : 0),
  );
}
