<!-- GENERATED: edit sorosentinel-intel/docs/adr/0001-phase0-decisions.md, then run scripts/sync-docs.sh. -->

# ADR 0001: Phase 0 decisions

Status: accepted · Date: 2026-10-27

Decisions made while scaffolding Phase 0, recorded so code and docs don't diverge.

| # | Decision | Why |
|---|---|---|
| 1 | Repos are `SoroSentinel/Sorosentinel-intel`, `-guard`, `-scan`. The repo first created as `Sorosentinel-core` was renamed to `Sorosentinel-guard`. | Match AGENTS.md §0 (case differs from the docs' lowercase; GitHub names are case-insensitive). |
| 2 | Go module path: `github.com/SoroSentinel/Sorosentinel-intel`. | Matches the GitHub remote exactly. |
| 3 | Cross-repo packages are consumed via **git tags**, not a registry (project_structure §2.3 open question). | No registry accounts needed yet; Go, Cargo and pnpm all support git dependencies. |
| 4 | `main` is protected in all repos: PR required (0 approvals while the team is one person), `verify` check required and up to date, linear history, no force-push or deletion, conversations resolved. Admins can bypass. | Enforces "run make verify" and trunk-based squash merges (§2.4) without blocking a solo maintainer. |
| 5 | CODEOWNERS uses placeholder teams (`@SoroSentinel/maintainers`, `counsel`, `security`, …) until the org creates them. Requiring counsel **and** a maintainer on `wording/` will need a branch ruleset. | Reviewer names are an open question (§10.6). |
| 6 | Guard pins `@stellar/stellar-sdk` **17.2.1**. SDK 17.3.0 is the first with Protocol 30 XDR but was under 14 days old; upgrade on or after **2026-11-04**. Until then P30-only XDR decodes as `unanalyzable`. | AGENTS.md §6 14-day rule; fail-loud decoding covers the gap. |
| 7 | Guard enforces the 14-day rule for transitive npm deps with pnpm `minimumReleaseAge: 20160`. Scan checks each locked crate's publish date (crates have no equivalent setting); `libc` was held at 0.2.190. | Same rule, applied to the whole dependency tree. |
| 8 | Guard does not depend on `@types/node`; a small `types/node-shim.d.ts` declares the few Node built-ins tests and scripts use. | Avoids an unapproved dependency; keeps `src/` browser-safe. |
| 9 | Scan host-import codes and custom-section names were verified (ARCHITECTURE F7/F8): `update_current_contract_wasm`=`l.6`, `create_contract`=`l.3`, `create_contract_with_constructor`=`l.e`, `call`=`d._`, `try_call`=`d.0` (rs-soroban-env v30.0.0 `env.json`); `contractspecv0`, `contractmetav0` (soroban-sdk v29.0.1), `contractenvmetav0` (rs-soroban-env v30.0.0). | Indicators must not rest on unverified facts. |
| 10 | The labeled corpus will live in a **separate private repo**, not in `Sorosentinel-intel/corpus/`. | All three repos are public; labels about named assets are a legal exposure (§3.1). This is a deliberate exception to "three repos". |
| 11 | No `CLAUDE.md` files are added for now (project_structure §2.1 lists one per repo). Pending the owner's decision. | Tool-specific config; AGENTS.md carries the instructions. |
