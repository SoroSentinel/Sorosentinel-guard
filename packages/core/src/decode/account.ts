import { StrKey, type xdr } from "@stellar/stellar-sdk/base";

import { assertNever } from "../assert-never.ts";
import type { AccountRef } from "./types.ts";

/** Normalizes a muxed or plain account to its underlying `G…` account. */
export function accountRef(m: xdr.MuxedAccount): AccountRef {
  switch (m.type) {
    case "keyTypeEd25519":
      return { account: StrKey.encodeEd25519PublicKey(m.ed25519.toBytes()) };
    case "keyTypeMuxedEd25519":
      return {
        account: StrKey.encodeEd25519PublicKey(m.med25519.ed25519.toBytes()),
        muxedId: m.med25519.id.toString(),
      };
    default:
      return assertNever(m);
  }
}
