# Contributing to SoroSentinel Guard

Thanks for helping. This project handles hostile input and makes public statements about other people's assets, so the bar for changes is deliberately high. Read this whole page before opening a PR.

## Before you start

1. Read [AGENTS.md](AGENTS.md) §3 (invariants) and §4 (what v1 does not build). They apply to humans too.
2. Pick an issue. Wave issues carry the `Stellar Wave` label and a `difficulty:` label. Comment on the issue to be assigned before you start; unassigned PRs may be closed.
3. If the issue needs a new dependency, a schema change, a new detector, finding code or public wording template, ask on the issue first. These need maintainer approval (AGENTS.md §10).

## Setup

Prerequisites: Node.js 22.12+ and pnpm 10.34.7 (`corepack enable pnpm` installs the pinned, hash-checked version).

```bash
make deps
make verify
```

| Command | What it does |
|---|---|
| `make verify` | Strict typecheck, tests, fixtures-up-to-date check |
| `make test` | Vitest |
| `make gen` | Regenerate `fixtures/tx` (never edit fixtures by hand) |
| `make replay FILE=txs.jsonl` | Decode a file of transactions and print aggregate stats |

## Workflow

- Branch from `main`: `feat/<short-name>`, `fix/<short-name>`, `docs/<short-name>`.
- Conventional commits: `type(scope): summary`, for example `feat(guard): add G-NO-EXPIRY finding`. One logical change per commit.
- Stage files explicitly (`git add path/to/file`), never `git add .`.
- Write the test first for decoders, detectors, rules and the renderer. Include at least one hostile or edge-case input.
- `make verify` must pass locally before you open the PR. CI runs the same target and it is a required check.
- `main` is protected: no direct pushes, linear history, squash merge.

## Pull request checklist

Your PR description must cover (the template asks for these):

- What changed and why
- How you tested it
- Which invariants from AGENTS.md §3 it touches
- Anything unverified, marked `TODO(verify)` in code

## Hard rules

- Never output or imply "safe". Unknown, error and timeout paths return `partial` or `unanalyzable`.
- Amounts are integers in stroops. No floating point.
- No secrets, private keys, real user data or raw transaction XDR in code, logs, fixtures or issues.
- User-visible text comes only from the approved templates in Intel's `wording/`. Do not add exceptions to the blocklist.
- Do not disable, skip or loosen a test, lint or type check to get green CI.
- Docs under `docs/` and `AGENTS.md` are generated from `Sorosentinel-intel`. Change them there.

## Questions

Ask on the issue, or in the [Telegram group](TODO-telegram-group-link).
