<!-- GENERATED: edit sorosentinel-intel/docs/adr/0006-gcp-provider-and-kms-signing.md, then run scripts/sync-docs.sh. -->

# ADR 0006: Intel deploys on GCP; the snapshot signing key is a Cloud KMS Ed25519 key at SOFTWARE protection level

Status: accepted · Date: 2026-10-28 · Decided by: project owner

## Context

Issue #33 blocks four decisions on one choice, and the first of them shapes the
rest: the snapshot signing key must live in a KMS (AGENTS.md §6), and only some
providers can do what this format asks.

The requirement is narrow and it is not negotiable by us: Guard and Intel verify
with `crypto/ed25519.Verify` over **the whole payload bytes**
(`internal/snapshot/snapshot.go:137`), so the KMS must perform plain Ed25519
(PureEdDSA, RFC 8032 §5.1.6) over an arbitrary-length raw message. Pre-hashing
is not an escape hatch — Ed25519 hashes internally, so a digest-based signature
fails verification. That rules out every digest-only service.

What the payload is, verified against the committed signing vector rather than
estimated: `schemas/vectors/snapshot_signing.json` gives a 3-entry snapshot and
its `payload_sha256`; a from-scratch reimplementation of `Payload()` reproduces
that hash exactly. The bytes are 25 B magic + 6 header lines (138 B in the
vector, 221 B in the worst legal case) + **16 B per entry**.

## Decision

| # | Decision | Why |
|---|---|---|
| 1 | **GCP** is Intel's deployment provider (issue #33 AC 1). | The only cloud KMS that can sign this payload as specified. One provider also covers Postgres, object storage for snapshot files, the worker/API runtime and the log-based alert routing AC 4 needs. |
| 2 | The signing key is a Cloud KMS `ec-sign-ed25519` (`ASYMMETRIC_SIGN`) key at **SOFTWARE protection level**. | Cloud KMS publishes its algorithm list per protection level, and `ec-sign-ed25519` appears **only** under `software`: the `hsm`, `hsm-single-tenant`, `external` and `external-vpc` lists carry only p256/p384 (plus secp256k1 on the multi-tenant HSM). There is no HSM-held Ed25519 option here. |
| 3 | **AWS KMS is rejected**, not deferred. | `Sign.Message` is capped at 0–4096 bytes and `ED25519_SHA_512` requires `MessageType:RAW`, which caps a snapshot at **242–247 entries** against the format's own `MaxEntries = 10_000_000` (a 160 MB payload) — off by ~65,000×. `ED25519_PH_SHA_512` requires `MessageType:DIGEST` and AWS states the input "is hashed twice: once by you and once by KMS"; HashEdDSA is not what `crypto/ed25519.Verify` accepts. |
| 4 | **Azure is rejected** on two independent grounds. | Neither Key Vault nor Managed HSM offers an Ed25519 key type at all (their key-type tables list only EC-P256/P256K/P384/P521, RSA 2K/3K/4K and oct/oct-HSM), and both perform digest-only signing: "the service doesn't hash content as part of signature creation". |
| 5 | **No snapshot format change.** The signature stays one Ed25519 signature over the whole payload; `Snapshot.json` and the signed-bytes spec are unchanged. | It is the only change-free option. A Merkle root over the 16-byte entries, or segments of ≤242 entries each signed separately, would reopen a schema, the signed-bytes spec, Guard's verifier and a dual-run period (§10) — that is a different decision, recorded as the escape hatch below. |
| 6 | The SOFTWARE-level key is an **accepted deviation**, stated here rather than assumed. | It is FIPS 140-3 Level 1, while Cloud HSM is Level 3. "Signing keys live in KMS" (§6) holds in the operational sense — non-exportable, IAM-gated, audit-logged — but not in the hardware sense. Accepted because this key's actual compromise impact is the ability to publish forged *public* intelligence text, which OE4's existing controls address directly: two active key IDs for rotation, a keyset pinned in Guard, and a revocation list in the release. Level 3 defends a different threat (hardware key extraction). |
| 7 | Mainnet ingestion runs with `-page-size 10`; **≥50 is known to halt**. | Measured against a mainnet endpoint with Intel's own request shape: 10 ledgers = 29.0 MB / 5.2 s, 20 = 60.2 MB / 11.6 s, 50 = **155.6 MB / 22.6 s**, which exceeds `DefaultMaxBodyBytes` (64 MiB) and therefore fails loud with `ErrTooLarge`; 100+ also exceeds `DefaultTimeout` (30 s). The E4 run used `-page-size 50`, which is only safe on testnet. |
| 8 | E4's transfer is budgeted **uncompressed**: ~2.9 MB/ledger → ~50 GB/day, ~354 GB/week on mainnet. | `internal/ingest/source/rpc/rpc.go:95` sets `DisableCompression: true` so the size cap measures bytes on the wire. Mainnet meta is **9.1×** testnet's 314 KiB/ledger, which is the multiplier the E4 note flagged as unknown. Enabling compression would let a 50-ledger page fit the cap, but it changes what that cap measures — an architecture call, deliberately not taken here. |

## Consequences

- Nothing is provisioned by this ADR. Cloud SDK/IaC (Terraform) is a §10
  dependency approval, KMS code is a §10 ask-first, and E4 implies real spend;
  all three remain open and none is implied by choosing GCP.
- The interim PEM/PKCS#8 loader (`internal/snapshot/keyfile.go`) stays the only
  signer implementation until someone approves writing the Cloud KMS one. No key
  material in git, logs or fixtures.
- Rotation is still unresolved: Cloud KMS gives multiple `cryptoKeyVersions` per
  key, but the dual-sign window from #34 is an architecture decision, not a
  provider feature.
- **Escape hatch, if Level 3 custody is later required:** GCP stops being the
  provider choice and the format change in decision 5 becomes mandatory — at
  which point AWS becomes viable again and this ADR is superseded rather than
  amended.
- PRD §12 Q6 (jurisdiction: where this data may live) can override a technical
  fit. Q1 (team size) and Q7 (mainnet or testnet first) still shape AC 2–3.
- OE4 said "add deltas and a manifest when measured size or rotation need
  appears". The 4 KiB ceiling and the ≤20,500-new-assets/day figure below are
  that measurement arriving; deltas and a manifest remain cut for v1.

## Measured inputs

Reproducible, read-only, nothing written to a cloud account:

- Cadence, both networks, from two `getLatestLedger` calls 60 s apart: **5.00 s
  per ledger**, protocolVersion **29** → 17,280 ledgers/day.
- `cmd/intel-ingest -network public -start-ledger 65,186,400 -page-size 10`:
  **180 contiguous ledgers**, no halts → 214 new-trustline assets (mean 1.19,
  median 1, max 21, 63 ledgers with none) and 4 home-domain changes; testnet over
  80 ledgers gave 61 assets and 1 domain change. Extrapolated **upper bound**
  ≤20,500 new assets/day, ≤384 domain changes/day — an upper bound because the
  ingester counts distinct assets *per ledger*, so an asset seen again in a later
  ledger counts twice.
- Time to fill a 242-entry payload as a function of the fraction of new assets
  the detectors flag: 0.1 % → ~12 days, 1 % → ~1.2 days, 5 % → ~6 h. The flag
  rate itself is **not measured**: `ListFlagged` volume is a detector-policy and
  curation choice. The mainnet flagged count through the real pipeline still
  needs a Postgres run and a reviewed mainnet reference-asset file
  (`config/` has only the testnet one).
- Payload ceilings computed from the vector-verified model: 4096 B → 247 entries
  with the vector's header, 242 with the worst legal header.
