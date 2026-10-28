import { memoDestinations } from "../memo/memo-required.ts";
import type { Finding, Rule } from "./types.ts";

/**
 * G-MEMO-REQUIRED: the transaction has no memo and an operation sends to an
 * account whose SEP-29 data entry requires one. One finding per operation.
 * Without the destinations' data entries it reports nothing; the result then
 * carries NC-MEMO-REQUIRED instead.
 */
export const memoRequired: Rule = (input, _effects, ctx) => {
  const required = ctx.memoRequired;
  if (required === undefined || input.tx.memo.type !== "none") return [];
  return memoDestinations(input)
    .filter((d) => required.has(d.account))
    .map(
      (d): Finding => ({
        code: "G-MEMO-REQUIRED",
        severity: "high",
        operationIndex: d.operationIndex,
        facts: { destination: d.account, operation_index: String(d.operationIndex) },
        statement: null,
      }),
    );
};
