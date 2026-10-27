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
```

## Fixtures

`fixtures/tx/{benign,hostile}/*.json` are generated with fixed **test-only**
keys and fixed time bounds, so regeneration is byte-identical. Never edit them
by hand; change the generator and run `make gen`.
