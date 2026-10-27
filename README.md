<!-- TODO: add a banner/logo image here once one exists. -->

# SoroSentinel Guard

[![CI](https://github.com/SoroSentinel/Sorosentinel-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/SoroSentinel/Sorosentinel-guard/actions/workflows/ci.yml)
![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178C6?logo=typescript)
![Stellar](https://img.shields.io/badge/Stellar-Soroban-black)
![License](https://img.shields.io/badge/license-TODO-lightgrey)

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

Phase 0. In place: an envelope and operation decoder covering every operation type, with the signed-payload hash, muxed-account normalization, fee bumps and Soroban auth entries; 38 deterministic fixtures; and a replay harness for measuring decoder coverage on real traffic. Not yet built: effect derivation, findings, RPC simulation, snapshot lookup.

## Quick start

Prerequisites: Node.js 22.12+ and pnpm 10.34.7.

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

## Repository layout

| Path | What |
|---|---|
| `packages/core/src/decode/` | Envelope and operation decoder |
| `packages/core/scripts/` | Fixture generator and replay harness |
| `fixtures/tx/` | Generated benign and hostile transaction fixtures |
| `docs/` | Generated copies of the canonical docs (edit them in Intel) |

## Contributing

Pick an open issue (Wave issues carry the `Stellar Wave` label), comment to be assigned, then follow [CONTRIBUTING.md](CONTRIBUTING.md). Every PR must pass `make verify`. AI coding agents must follow [AGENTS.md](AGENTS.md).

## Security

Do not open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md). This code is **not audited**.

## Contributors

[![Contributors](https://contrib.rocks/image?repo=SoroSentinel/Sorosentinel-guard)](https://github.com/SoroSentinel/Sorosentinel-guard/graphs/contributors)

## License

TODO: choose a license (see the open question in the maintainer notes) and add a `LICENSE` file.
