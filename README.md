# sorosentinel-guard

Pre-signing transaction analysis SDK for SoroSentinel (TypeScript):
`analyze(xdr, ctx)` called by a wallet before signing. Not a server.

Status: Phase 0. The envelope/operation decoder is in place
(`packages/core/src/decode/`); effects, rules and Intel lookup come next.

## Commands

Requires Node >= 22.12 and pnpm 10.34.7.

```
make deps            # pnpm install --frozen-lockfile
make lint            # strict TypeScript typecheck
make test            # vitest
make gen             # regenerate fixtures/tx from packages/core/scripts/gen-fixtures.ts
make verify          # lint + test + test-contract + fixtures-check
make replay FILE=x   # experiment E2: decode a JSONL file of transactions, print aggregates
```

## Replay (experiment E2)

`make replay FILE=txs.jsonl` reads one `{"xdr": "...", "network_passphrase": "..."}`
per line and prints aggregate counts: unanalyzable rate by reason, envelope
kinds, networks and operation types. It never prints raw XDR, hashes or
addresses. It exits non-zero when the unanalyzable rate exceeds `MAX_RATE`
(default 0.02, the E2 kill threshold). The benign-warning rate is reported as
`not_measured` until effects and rules exist.

## Fixtures

`fixtures/tx/{benign,hostile}/*.json` are generated with fixed **test-only**
keys and fixed time bounds, so regeneration is byte-identical. Never edit them
by hand; change the generator and run `make gen`.
