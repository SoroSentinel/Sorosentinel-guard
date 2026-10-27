import { Networks } from "@stellar/stellar-sdk/base";

import type { Network } from "./types.ts";

/** Maps a network passphrase to a covered network, or `unknown`. */
export function networkOf(passphrase: string): Network {
  switch (passphrase) {
    case Networks.PUBLIC:
      return "public";
    case Networks.TESTNET:
      return "testnet";
    default:
      return "unknown";
  }
}
