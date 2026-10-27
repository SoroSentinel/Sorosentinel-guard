import type { Finding, Rule } from "./types.ts";

/**
 * G-ACCOUNT-CONTROL: SetOptions changes who can authorize the account: master
 * weight, thresholds, or removing a signer. Added signers are G-SIGNER-ADDED,
 * so the same change is not reported twice.
 */
export const accountControl: Rule = (_input, effects) =>
  effects.accountEffects.flatMap((e): Finding[] => {
    if (e.kind === "thresholds") {
      const facts: Record<string, string> = { account: e.account };
      if (e.masterWeight !== null) facts["master_weight"] = String(e.masterWeight);
      if (e.low !== null) facts["low_threshold"] = String(e.low);
      if (e.medium !== null) facts["medium_threshold"] = String(e.medium);
      if (e.high !== null) facts["high_threshold"] = String(e.high);
      return [{ code: "G-ACCOUNT-CONTROL", severity: "critical", operationIndex: e.operationIndex, facts, statement: null }];
    }
    if (e.kind === "signer" && e.weight === 0) {
      return [
        {
          code: "G-ACCOUNT-CONTROL",
          severity: "critical",
          operationIndex: e.operationIndex,
          facts: { account: e.account, removed_signer: e.signer, signer_type: e.signerType },
          statement: null,
        },
      ];
    }
    return [];
  });
