import type { Rule } from "./types.ts";

/**
 * An upper time bound further than this past `asOf` counts as no expiry: a
 * signed copy stays usable for that long. Seven days, in seconds.
 */
export const FAR_FUTURE_SECONDS = 7n * 24n * 60n * 60n;

/**
 * G-NO-EXPIRY: the transaction has no upper time bound (max of 0 or none), so a
 * signed copy stays valid until its sequence number is used. With a
 * caller-supplied `asOf`, a bound more than FAR_FUTURE_SECONDS away also counts.
 */
export const noExpiry: Rule = (input, _effects, ctx) => {
  const tb = input.tx.timeBounds;
  const max = tb === null ? 0n : BigInt(tb.max);
  if (max === 0n) {
    return [{ code: "G-NO-EXPIRY", severity: "medium", operationIndex: null, facts: { max_time: "none" }, statement: null }];
  }
  if (ctx.asOf !== undefined && max - ctx.asOf > FAR_FUTURE_SECONDS) {
    return [
      {
        code: "G-NO-EXPIRY",
        severity: "medium",
        operationIndex: null,
        facts: { max_time: max.toString(), as_of: ctx.asOf.toString() },
        statement: null,
      },
    ];
  }
  return [];
};
