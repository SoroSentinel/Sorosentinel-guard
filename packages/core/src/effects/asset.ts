import { StrKey, type xdr } from "@stellar/stellar-sdk/base";

import { assertNever } from "../assert-never.ts";

const ASSET_CODE = /^[A-Za-z0-9]{1,12}$/;

/** Thrown for values the network would reject; the operation becomes uncovered. */
export class InvalidOperation extends Error {}

/** Canonical asset key: "native" or "CODE:ISSUER" (sorosentinel-intel schemas/canonical-key.md). */
export function assetKey(asset: xdr.Asset): string {
  switch (asset.type) {
    case "assetTypeNative":
      return "native";
    case "assetTypeCreditAlphanum4":
      return credit(asset.alphaNum4.assetCode.toBytes(), asset.alphaNum4.issuer);
    case "assetTypeCreditAlphanum12":
      return credit(asset.alphaNum12.assetCode.toBytes(), asset.alphaNum12.issuer);
    default:
      return assertNever(asset);
  }
}

export function accountId(key: xdr.PublicKey): string {
  switch (key.type) {
    case "publicKeyTypeEd25519":
      return StrKey.encodeEd25519PublicKey(key.ed25519.toBytes());
    default:
      return assertNever(key.type);
  }
}

function credit(codeBytes: Uint8Array, issuer: xdr.PublicKey): string {
  // Codes are zero-padded on the wire; anything else must be ASCII alphanumeric.
  let end = codeBytes.length;
  while (end > 0 && codeBytes[end - 1] === 0) end--;
  let code = "";
  for (let i = 0; i < end; i++) {
    code += String.fromCharCode(codeBytes[i] ?? 0);
  }
  if (!ASSET_CODE.test(code)) {
    throw new InvalidOperation("malformed asset code");
  }
  return `${code}:${accountId(issuer)}`;
}
