# Example: sign through Guard instead of straight to the wallet

`packages/adapter-reference` wraps a SEP-43-style wallet's two signing calls:
`signTransaction` for a transaction envelope and `signAuthEntry` for one
Soroban authorization entry. Guard analyzes the bytes first, the integrator
reviews them, and only then is the wallet asked — so what the user confirms is
what was analyzed (AGENTS.md §3.8).

`sign.mts` runs both paths against the repository's fixtures and prints the
outcome. It needs no wallet, no network and no key:

```sh
node examples/wallet-adapter/sign.mts                                    # review declines: nothing is signed
node examples/wallet-adapter/sign.mts --approve                          # wallet returns the analyzed bytes: signed
node examples/wallet-adapter/sign.mts --approve --tamper                 # wallet returns other bytes: partial
node examples/wallet-adapter/sign.mts --path auth_entry --approve
node examples/wallet-adapter/sign.mts --path auth_entry --approve --signature # wallet answers with a bare signature
```

| Flag | Meaning |
|---|---|
| `--path transaction\|auth_entry` | Which signing path to run. Default `transaction`. |
| `--approve` | The review callback returns `true`. Without it the review declines and the wallet is never called. |
| `--tamper` | The stub wallet returns *different* bytes than it was shown. |
| `--signature` | With `--path auth_entry`, the stub wallet answers like Freighter does: a bare 64-byte signature instead of an entry. Guard checks it against the payload the analyzed entry implies, and the stub's bytes are not that signature. |

Exit code 0 means `outcome: signed` with the analyzed bytes, or
`signed_preimage_verified`; 1 means the sample ran and the signing did not
complete as analyzed (`signed_other_bytes`, `signed_preimage_mismatch`,
`signed_unverifiable` or `not_signed`); 2 is a bad argument.

## What the sample shows

```text
analysis: status=partial findings=0 not_checked=NC-COUNTERPARTY-SIGNALS, NC-EXECUTION-TIME, NC-MEMO-REQUIRED
review: approving (--approve to let the wallet be asked)
wallet: signTransaction asked for 288 base64 chars
outcome: signed, and the bytes match what was analyzed (status=partial)
```

Three things are deliberate:

- **The status stays `partial`.** No snapshot was configured, so the
  counterparties were not checked, and the transaction was not simulated. Guard
  does not report a clean result it did not earn.
- **The wallet is asked only after an exactly-`true` review.** A `false`, a
  throw, or any other value means `not_signed`, and the wallet is never called.
- **`--tamper` ends as `partial`, not as the analysis above it.** The adapter
  re-decodes what the wallet returned and compares the signed payload with its
  signature fields removed. If they differ, the earlier analysis is no longer a
  description of these bytes, so the caller must not present it as one.

## The wallet here is a stub

```ts
const wallet: Sep43Signer = {
  async signTransaction(xdrBase64) {
    return { signedTxXdr: args.tamper ? other.xdr : xdrBase64, signerAddress };
  },
  ...
};
```

It holds no key and produces no signature; it returns the bytes it was shown so
the flow runs offline. A real wallet replaces this one object. Nothing in this
sample, in the adapter, or in `packages/core` ever reads or needs a private key,
and nothing is submitted: the wallet (or the dApp) does that.

Raw XDR is not printed, per the project's logging rules. Only statuses, finding
codes and sanitized facts reach the console.

## Using it in an app

```ts
import { guardSignTransaction } from "@sorosentinel/guard-adapter-reference";

const result = await guardSignTransaction(wallet, unsignedXdr, {
  networkPassphrase: "Test SDF Network ; September 2015",
  asOf: new Date(),
  snapshot: { data: snapshotJson, pinnedKeys: { "key-id": publicKeyBytes } },
}, async (analysis) => showFindingsAndGetConfirmation(analysis));

switch (result.outcome) {
  case "signed":             // the review covered exactly these bytes
  case "signed_other_bytes": // re-warn: the analysis does not describe these bytes
  case "not_signed":         // reason: review_declined | network_mismatch | wallet_rejected
                             //         | wallet_no_response | wallet_no_signed_bytes
}
```

`guardSignAuthEntry` is that shape plus three more arms, because SEP-43 is not
consistent about what `signAuthEntry` exchanges:

```ts
switch (result.outcome) {
  case "signed":                // an entry came back, and it is the one analyzed
  case "signed_other_bytes":    // a different entry came back
  case "signed_preimage_verified": // a bare signature came back, and it is the
                                // analyzed entry's authorization: the key its
                                // credentials name signed the payload those
                                // credentials imply (this tree, this network,
                                // until that ledger). Freighter answers this way:
                                // given the entry's preimage it returns a bare
                                // Ed25519 signature, which the dApp assembles
                                // into an entry itself.
  case "signed_preimage_mismatch": // a bare signature, and it is not that
                                // authorization
  case "signed_unverifiable":   // reason: entry_undecodable | reply_not_a_signature
                                // | credential_has_no_signature | credential_not_ed25519
  case "not_signed":            // same reason codes as above
}
```

`signed_preimage_verified` carries `authorizedBy`, the address the entry's
credentials name, because that key is what the check verified against; the
wallet's own `signerAddress` claim is reported alongside it and is not what the
verdict rests on. Only the top-level credential is checked, so the entry the dApp
assembles still needs its delegate signatures, and a custom account may authorize
in a way no offline check can follow.

`signed_unverifiable` and `signed_preimage_mismatch` are `partial`, never
`signed`: an analysis of the entry does not describe other bytes, and reporting a
signature as merely unknown would waste a check that can be made. Guard passes a
base64 `SorobanAuthorizationEntry`, because that is the only form whose authorized
call tree it can analyze.

Both entries and transactions: an authorization entry carries no ledger effects,
so its analysis is always `partial`, and its findings are limited to the
contracts its authorized call tree names (`G-CONTRACT-FLAGGED`,
`G-NETWORK-UNKNOWN`).

## What Guard does not say

Every failure this adapter reports is a code, never a sentence; the only text
that passes through is a wallet's own `error.message`, which is untrusted and
must be sanitized before display (the sample runs it through
`sanitizeUntrusted`). Wording for users comes from the wording renderer, per
AGENTS.md §5.
