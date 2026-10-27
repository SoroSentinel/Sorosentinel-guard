<!-- GENERATED: edit sorosentinel-intel/docs/adr/0003-repo-guard-scope.md, then run scripts/sync-docs.sh. -->

# ADR 0003: Repo Guard is a narrow, Stellar-specific GitHub Action, parked until Phase 1 exits

Status: accepted · Date: 2026-10-27 · Decided by: project owner

## Context

The owner asked for SoroSentinel to detect suspicious files or code implanted
into a user's project by contributors or collaborators. As stated, that is
general malware scanning, which PRD NG1 excludes, is unreliable against
ordinary-looking malicious changes, and is already covered for most languages
by GitHub secret scanning, Dependabot, Socket, Semgrep and similar tools.

## Decision

1. Build it only in a **narrow, Stellar-specific form: "Repo Guard"**, a GitHub
   Action that reports risky changes in pull requests to Stellar and Soroban
   projects: WASM that does not match its source, Stellar secret seeds and
   recovery phrases, install-time code in dependencies, changed addresses,
   contract IDs and network passphrases, and workflow changes (PRD §15).
2. **Park it until the Phase 1 exit test passes** (PRD §9: a look-alike asset
   is flagged on testnet and Guard warns). Until then it is on the "do not
   build" list in AGENTS.md §4.
3. It is **advisory**, follows the same rules as the rest of the project (never
   "safe", fail loud, public text only from approved templates, findings
   describe the change and never the contributor), and never runs pull-request
   code with access to secrets.
4. NG1 still holds: no general malware or virus detection, no non-Stellar scope.

## Open (decide when unparked)

- **Where it lives.** Proposed: inside `Sorosentinel-scan` as a second binary
  plus `action.yml`, since R-1 reuses the WASM parser and sandbox. A separate
  repo would be a fifth repo to maintain.
- Whether Soroban contract builds are reproducible enough for R-1
  (TODO(verify) before committing to it).

## Consequences

- No Repo Guard code, issues or templates before the Phase 1 exit.
- The PRD gains §15 with requirements R-1 to R-8, non-goals and risks.
