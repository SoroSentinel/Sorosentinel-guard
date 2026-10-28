<!-- GENERATED: edit sorosentinel-intel/docs/adr/0004-rpc-only-ingestion.md, then run scripts/sync-docs.sh. -->

# ADR 0004: Phase 1 ingestion reads Stellar RPC only

Status: accepted · Date: 2026-10-27 · Decided by: project owner

## Context

ARCHITECTURE §4.1 plans two ingestion paths: a Galexie lake (or Hubble)
backfill for history, and a Stellar RPC live tail. Phase 1 (ADR 0002) only
needs inputs for the look-alike and home-domain detectors, and its exit test
runs on testnet: a look-alike asset is flagged, appears in the signed
snapshot, and Guard warns on a trustline to it. That asset is created during
the test, so no history from before the test is needed.

## Decision

1. Phase 1 ingests **only from Stellar RPC `getLedgers`**, polling forward
   from a checkpoint (`internal/ingest`, `internal/ingest/source/rpc`,
   `cmd/intel-ingest`). No Horizon (invariant 10).
2. **Galexie/Hubble backfill is deferred.** `internal/ingest/source/lake/`
   stays unbuilt until a later phase needs history older than RPC retention.
3. Ingestion extracts only what the two detectors need: credit assets that
   gain a trustline (code, issuer) and accounts whose `home_domain` is set or
   changed. It is not a general history pipeline.
4. The Go XDR library is `github.com/stellar/go-stellar-sdk`, pinned at
   v0.7.3 (approved by the owner on 2026-10-28). It carries Protocol 28 XDR
   and decoded live testnet Protocol 29 ledgers byte-exactly on 2026-10-28.
   Ingestion refuses ledgers above protocol 29 (`xdrcompat.MaxProtocol`).

## Consequences

- **Retention limit.** RPC keeps about 7 days of ledgers (SDF testnet reported
  `ledgerRetentionWindow` 120960 ledgers on 2026-10-28). If ingestion is down
  longer than that, the next ledger falls out of the window: ingestion halts
  with a gap error and cannot recover without a backfill. Until the lake
  source exists, recovery means an operator restarts from a later ledger and
  records the skipped range as unchecked.
- **Halts, never skips.** Unknown or non-canonical XDR, a protocol above the
  pinned one, a non-contiguous sequence, a hash that differs from its meta, a
  broken previous-hash chain or the wrong network passphrase all stop
  ingestion with an alert. Transport and server errors are retried a bounded
  number of times, then also stop it.
- **Protocol 30.** The testnet vote is 2026-11-03. On that upgrade, testnet
  ingestion halts by design until the XDR library is moved to a release with
  Protocol 30 XDR (go-stellar-sdk v0.8.0, released 2026-10-20, clears the
  14-day dependency rule on 2026-11-03) following ARCHITECTURE §12.
- **Single writer.** One ingester per network per process is enforced in
  code. Exclusion across processes (a leader lock) arrives with the Postgres
  checkpoint; until then, deployment must run one `intel-ingest` per network.
- **Checkpoint.** The `Checkpoint` interface has an in-memory implementation
  only. The Postgres-backed one comes with the storage work. The previous-hash
  chain is checked within a run, not across a restart.
- **Update 2026-10-28:** `cmd/intel-worker` adds the Postgres checkpoint
  (`store.Checkpoint`) and cross-process exclusion (`store.AcquireWriter`, a
  Postgres advisory lock per network). The previous-hash chain is still
  checked within a run only.
- Revisit this ADR when a detector needs history older than RPC retention, or
  before mainnet ingestion is relied on for anything a user sees.
