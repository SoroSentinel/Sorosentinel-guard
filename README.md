<!-- TODO: add a banner/logo image here once one exists. -->

# SoroSentinel Guard

[![CI](https://github.com/SoroSentinel/Sorosentinel-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/SoroSentinel/Sorosentinel-guard/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/SoroSentinel/Sorosentinel-guard/badge)](https://scorecard.dev/viewer/?uri=github.com/SoroSentinel/Sorosentinel-guard)
![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178C6?logo=typescript)
![Stellar](https://img.shields.io/badge/Stellar-Soroban-black)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Guard is a TypeScript SDK that a wallet calls just before a user signs. It decodes the exact transaction bytes being signed, works out what each operation does to each account (balances, signers, trustlines, contract authorizations), checks counterparties against SoroSentinel's signed snapshot, and returns findings ordered by severity. It never sees private keys and never reports a transaction as "safe": the best result is "no issues found" plus a list of what was not checked.

Part of **SoroSentinel**, security tooling for the Stellar ecosystem. It advises; it never controls the network and never touches private keys.

## Maintainers | [Telegram](TODO-telegram-group-link)

| Maintainer | GitHub | Contact |
|---|---|---|
| TODO name | [@TODO](https://github.com/TODO) | [Telegram](https://t.me/TODO) |

## Community

Questions and coordination: [Telegram group](TODO-telegram-group-link).

## How the pieces fit

| Repo | Language | Role |
|---|---|---|
| [Sorosentinel-intel](https://github.com/SoroSentinel/Sorosentinel-intel) | Go | Evidence, detectors, signals, API, signed snapshot, shared schemas |
| [Sorosentinel-guard](https://github.com/SoroSentinel/Sorosentinel-guard) | TypeScript | Pre-signing transaction analysis SDK for wallets |
| [Sorosentinel-scan](https://github.com/SoroSentinel/Sorosentinel-scan) | Rust | Static triage of deployed Soroban WASM |

Data flows Scan → Intel → signed snapshot/API → Guard. The repos only talk through versioned schemas owned by Intel.

## Status

Phase 1 complete in code. `analyze()` / `analyzeAsync()` decode exactly the signed bytes, derive per-account balance and account effects (worst case first), simulate Soroban calls through a caller-supplied RPC endpoint, verify Intel's signed snapshot and look up counterparties, and report findings: G-ACCOUNT-CONTROL, G-SIGNER-ADDED, G-NO-EXPIRY, G-NETWORK-UNKNOWN, G-MEMO-REQUIRED, G-DEST-FLAGGED, G-TRUST-FLAGGED, G-CONTRACT-FLAGGED. Findings carry facts only until their wording is counsel-approved. Experiment E2 has run over 12,000 real mainnet transactions and 12,000 testnet ones: all decoded, none `unanalyzable`. Not yet: the Protocol 30 SDK upgrade, and E2's benign-warning rate, which needs the labeled corpus.

## Quick start

Prerequisites: Node.js 22.12+ and pnpm 10.34.7 (`corepack enable pnpm` installs the pinned, hash-checked version).

```bash
git clone https://github.com/SoroSentinel/Sorosentinel-guard.git
cd Sorosentinel-guard
make deps
make verify
```

| Command | What it does |
|---|---|
| `make verify` | Strict typecheck, tests, fixtures-up-to-date check |
| `make test` | Vitest |
| `make gen` | Regenerate `fixtures/tx` (never edit fixtures by hand) |
| `make replay FILE=txs.jsonl` | Decode a file of transactions and print aggregate stats |
| `make bench` | Measure `analyze` latency against the PRD §7 targets (local path only, no network) |
| `make bench RPC=https://…` | Also measure the end-to-end path with RPC simulation; sends invocation envelopes to that endpoint |
| `node packages/core/scripts/export-rpc-txs.ts --url …` | Export recent transactions from an RPC endpoint for `make replay` (writes the gitignored `replay/`) |

## Repository layout

| Path | What |
|---|---|
| `packages/core/src/decode/` | Envelope and operation decoder |
| `packages/core/scripts/` | Fixture generator, replay harness, latency benchmark |
| `fixtures/tx/` | Generated benign and hostile transaction fixtures |
| `docs/` | Generated copies of the canonical docs (edit them in Intel) |

## Contributing

Pick an open issue (Wave issues carry the `Stellar Wave` label), comment to be assigned, then follow [CONTRIBUTING.md](CONTRIBUTING.md). Every PR must pass `make verify`. AI coding agents must follow [AGENTS.md](AGENTS.md).

## Security

Do not open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md). This code is **not audited**.

## Contributors

[![Contributors](https://contrib.rocks/image?repo=SoroSentinel/Sorosentinel-guard)](https://github.com/SoroSentinel/Sorosentinel-guard/graphs/contributors)

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
