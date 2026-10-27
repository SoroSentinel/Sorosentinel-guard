import { assertNever } from "../assert-never.ts";
import type { SignerType } from "../effects/types.ts";
import type { Rule, Severity } from "./types.ts";

/**
 * G-SIGNER-ADDED: SetOptions adds a signer or changes its weight. hash(x) and
 * pre-authorized-transaction signers have no visible owner key (anyone with the
 * preimage, or that exact transaction, can use them), so they rank highest.
 */
export const signerAdded: Rule = (_input, effects) =>
  effects.accountEffects.flatMap((e) =>
    e.kind === "signer" && e.weight > 0
      ? [
          {
            code: "G-SIGNER-ADDED" as const,
            severity: severityFor(e.signerType),
            operationIndex: e.operationIndex,
            facts: { account: e.account, signer: e.signer, signer_type: e.signerType, weight: String(e.weight) },
            statement: null,
          },
        ]
      : [],
  );

function severityFor(type: SignerType): Severity {
  switch (type) {
    case "hash_x":
    case "pre_auth_tx":
      return "critical";
    case "ed25519":
    case "ed25519_signed_payload":
      return "high";
    default:
      return assertNever(type);
  }
}
