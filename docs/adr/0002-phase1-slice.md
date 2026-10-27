<!-- GENERATED: edit sorosentinel-intel/docs/adr/0002-phase1-slice.md, then run scripts/sync-docs.sh. -->

# ADR 0002: Phase 1 slice is Guard effect analysis plus minimal Intel

Status: accepted · Date: 2026-10-27 · Decided by: project owner

## Decision

Phase 1 builds a vertical slice instead of full Intel first:

1. **Guard effect analysis**: per-account effects for the 8 v1 operation types
   (payment, both path payments, create account, change trust, set options,
   account merge, invoke host function), Soroban simulation via a caller-chosen
   RPC endpoint, and the effect-based findings, each shipping with an approved
   template.
2. **Minimal Intel**: only the asset look-alike (`D-ASSET-LOOKALIKE`) and
   home-domain (`D-HOMEDOMAIN-MISMATCH`) detectors, with what they need to
   produce evidence, signals and the signed snapshot that Guard checks.

Exit criterion (unchanged from PRD §9): on testnet, a look-alike asset is
flagged by Intel, appears in the snapshot, and Guard warns on a transaction
that adds a trustline to it.

## Why

- Effect analysis is the only part that gives value on day zero without
  reputation data, and it is what a wallet pilot partner needs to see (PRD §14
  P1, P3).
- Full Intel first delivers value late and needs trust the project does not have yet.
- Look-alike and home-domain checks are objectively verifiable, which suits the
  cold-start trust problem (PRD §11 risk 4).

## Consequences

- Intel work in Phase 1 is limited to: the isolated fetcher, entity and
  evidence storage for these two detectors, the rule table, the snapshot
  builder and signer, and their templates. Other detectors wait.
- Ingestion scope follows from the two detectors (asset and issuer data), not a
  full ledger history pipeline.
- The second open decision (defer Scan beyond the minimal library until
  experiment E3 shows signal) is **still open**; this ADR does not change Scan.
