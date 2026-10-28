# Example: analyze a transaction before signing

Minimal usage of `analyze(xdr, ctx)` from `packages/core`: one base64
transaction envelope, Intel's signed snapshot file, and the snapshot public key
pinned by key id. It prints the status, effects (amounts in stroops, worst case
first) and findings (most severe first, never truncated).

It reads only local files. It sends nothing anywhere and needs no private key:
the envelope can be, and usually is, unsigned.

## Run

Node 23.6 or newer (the example and Guard's source run through Node's built-in
TypeScript type stripping), after `pnpm install` at the repo root:

```sh
node examples/analyze-transaction/analyze.mts \
  --network testnet \
  --snapshot snapshot-testnet-latest.json \
  --key-id <snapshot key id> \
  --public-key <32-byte Ed25519 public key, hex> \
  --xdr-file tx.b64
```

| Flag | Meaning |
|---|---|
| `--network` | `testnet` or `public`; picks the passphrase the transaction is analyzed for. |
| `--snapshot` | Snapshot JSON as Intel publishes it (`GET /v1/snapshots/latest`). |
| `--key-id`, `--public-key` | The pinned key. A snapshot signed by any other key is not used. |
| `--xdr` / `--xdr-file` | The base64 envelope, inline or from a file. |
| `--as-of` | Reference time (ISO 8601) for snapshot freshness and expiry checks. Default: now. Guard itself never reads the clock; the caller passes it. |
| `--json` | Print the whole `AnalysisResult` as JSON (bigint amounts as strings). |

Exit code 0 means the analysis ran (whatever the status), 2 means bad
arguments or an unreadable file.

## Output

```text
status: findings_present
tx_hash: <hash of exactly the bytes to be signed>
network: testnet
operations: 1
snapshot: verified
effects: 1
  G... native delta_min=-100 delta_max=0 assurance=ledger
findings: 1
  high G-TRUST-FLAGGED op=0 ...
not_checked: NC-EXECUTION-TIME
```

The output is codes and facts, not user-facing text: a wallet renders findings
through the wording renderer. `snapshot` other than `verified` means
counterparties were not checked, and the result carries
`NC-COUNTERPARTY-SIGNALS`; it never reads as clean.

Intel's local demo (`make demo` in `sorosentinel-intel`, see its
`docs/runbooks/local-demo.md`) calls this example against a live testnet stack.

## States a host must not drop

An integrating wallet that renders `findings` only when
`status: findings_present` undoes every guarantee above one layer up. ADR 0005
(draft, `sorosentinel-intel/docs/adr/0005-guard-integrator-contract.md`) lists
the six things such a host must show; this example is the reference for them and
prints all of them, and `packages/core/test/example.test.ts` drives it over
fixtures so the reference host cannot shrink into the tidy case:

| Must not be dropped | Where it is printed | Covered by |
|---|---|---|
| A snapshot that is not `verified` | `snapshot: <status>` — `stale`, `unknown_key`, `bad_signature`, `malformed`, `network_mismatch`, `from_future`, `no_as_of` | *an aged-out snapshot reads as stale and never as a clean result*, *with the wrong pinned key…* |
| `NC-COUNTERPARTY-SIGNALS` when lookup did not run | `not_checked:` | same two tests |
| `partial` and `unanalyzable` | `status:`, plus `unanalyzable_reason:` | *an operation Guard only decodes keeps its partial status*, *an undecodable transaction says so and still exits 0* |
| Findings in full, most severe first, with the operation count | `findings:` + `operations:` | *prints every finding, most severe first* |
| The hash of exactly the bytes to be signed | `tx_hash:` (inner hash for a fee bump) | *shows the hash and the operation count for a fee-bump* |
| No destination beyond the configured RPC endpoint and Intel | reads local files and calls nothing (see above) | — |

`--network` is validated before anything is decoded, so a host cannot ask this
example to analyze against a network Guard does not know: it exits 2 instead of
guessing a passphrase.
