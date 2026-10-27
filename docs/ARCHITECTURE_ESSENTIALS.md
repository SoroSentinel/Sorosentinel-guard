<!-- GENERATED: edit sorosentinel-intel/docs/ARCHITECTURE_ESSENTIALS.md, then run scripts/sync-docs.sh. -->

# ARCHITECTURE_ESSENTIALS — SoroSentinel

Condensed for agent reference. Full detail: `ARCHITECTURE.md`. Product scope: `PRD.md`.
If anything here conflicts with the full doc, the full doc wins; flag the conflict. **Exception:** the "v1 cut list" in §12 (HQ3) overrides the full doc for the v1 build.

## 1. Shape
- 3 repos, 1 org (**SoroSentinel**): `sorosentinel-intel` (Go) · `sorosentinel-scan` (Rust) · `sorosentinel-guard` (TypeScript)
- Data flow: Scan → evidence → **Intel** → signed snapshot/API → Guard
- Intel is the foundation and ships first. Repos talk only via versioned REST/OpenAPI + signed artifacts.

## 2. Non-negotiable invariants
1. Never output "safe." Allowed Guard states: `findings_present | no_issues_found | partial | unanalyzable`.
2. Errors/timeouts → `partial` or `unanalyzable`, never a clean result.
3. No verdict without stored evidence.
4. Automated sources cap at `suspicious`. `malicious` = human-confirmed (v1) or ≥2 independent evidence classes + review.
5. Guard never touches private keys.
6. All inputs (XDR, WASM, domains, reports) are hostile. Scan runs in a sandbox: no network, resource limits, timeouts.
7. Verdict scoring is deterministic; every change appends to `verdict_events`.
8. Do not depend on Horizon.
9. **Public text only via the template renderer** (`wording/` registry, `counsel_approved` only). No free-text slots. Analyst notes are internal and never serialized publicly.
10. **Public wording = verifiable observation + `as_of` + method + "indicator, not a determination" + methodology link + review link.** Describe transaction *effects*, never entity character, intent, or identity.
11. **Blocklisted public terms:** scam, fraud, fake, stolen, hack, criminal, illegal, malicious, rug pull, Ponzi, "designed to". CI lint + runtime check; render fails closed (structured fields, no prose).
12. **Public signal names:** `consistent | no_signals | caution | high_caution`. `consistent` = matches the entity's own published data; it never implies trustworthiness (attackers can publish matching data). Internal `benign/unknown/suspicious/malicious` never leave the system.
13. Store write-once raw evidence and every rendered `public_statement` so published facts are provable later.

## 3. Platform facts (as of 2026-10-26)
- Horizon deprecated → use Stellar RPC (live, ~7-day retention) + Galexie/Hubble (history). [Certain]
- `simulateTransaction` is RPC-only. [Certain]
- Protocol 30 mainnet vote 2026-11-23 (testnet 2026-11-03); update XDR libs first; ingest must halt on unknown XDR. [Certain]
- Verify before coding: WASM custom-section names, host-import mapping, SEP-43 API, Go ingest package. [Likely]

## 4. Intel
- Ingest: Galexie lake backfill + RPC live tail; idempotent by `(network, ledger_seq)`; checkpoint table.
- Entities: `account | asset | contract | wasm_hash | domain`.
- Verdict levels: `benign | unknown | suspicious | malicious`; status (v1): `active | revoked` plus a `disputed` flag; review queue is separate.
- Level = rule table over fired detectors, evidence classes and analyst confirmation, as a function of `(evidence_set, as_of, ruleset_version)` (v1: no numeric score). `as_of` is an input and is stored (never read the wall clock in verdict logic). Replay must reproduce stored verdicts.
- Create entities lazily (on evidence / first lookup / watchlist). Normalize muxed `M…` → `G…`; link classic asset ↔ SAC via `entity_link`.
- Informational Scan indicators (upgradeable, cross-call, creates contracts, old SDK) never raise a level alone.
- Detectors v1: lookalike asset, home-domain mismatch, trustline spam, takeover pattern, scan evidence, community, curated.
- Outputs: REST API (`/v1/entities/...`, `:batchGet`, `/v1/snapshots/...`) + Ed25519-signed snapshot (≤5 min cadence; v1: one KMS key plus one offline backup key pinned in the SDK; signed bytes in `schemas/snapshot-signing.md`).
- Stack: Postgres 16, S3-compatible store, Postgres-backed queue (no Kafka). v1: no Redis; in-process cache, rate limits at the gateway.
- Owns shared schemas in `schemas/` → published to npm / crates / Go.

## 5. Guard
- Pipeline: parse XDR → classify → simulate (Soroban, via RPC) → derive effects → local snapshot lookup (API fallback on hit) → rules → findings.
- Critical findings: account-control changes (SetOptions), account merge, flagged trustline/destination/contract, over-broad Soroban auth entries.
- Ships as SDK/middleware first; SEP-43-style adapter second; standalone extension last (can't reliably hook other wallets).
- Privacy: snapshot-first, no telemetry by default.

## 6. Scan
- Pipeline (v1): Intel acquires the WASM, dedupes by sha256 + ruleset version, and runs the Scan CLI as a one-shot sandboxed job (no network) → parse → feature extraction → indicators → Intel reads the `ScanReport` JSON. No Scan service or callbacks.
- v1 detectors are coarse indicators (upgradeable, creates contracts, cross-calls, missing auth import, SEP-41 deviation, known-bad hash, old SDK). Not proof of malice.
- Binary/deployed WASM only. No source-level analysis (Scout/Certora cover it).

## 7. Contracts between repos
- Source of truth: OpenAPI + JSON Schema in `sorosentinel-intel/schemas/`.
- Additive-only within a major version; breaking change = new `/v2` + dual run.
- Consumer-driven contract tests in every repo; pin schema versions.

## 8. Stack decisions
| Layer | Choice |
|---|---|
| Intel | Go |
| Scan | Rust (`wasmparser`, Soroban host crates) |
| Guard | TypeScript (official JS Stellar SDK) |
| DB | Postgres 16 |
| Infra | Docker + Terraform, single managed cloud, no Kubernetes at v1 |
| API | REST, OpenAPI 3.1 |
| Signing | Ed25519 + KMS |
| Observability | OpenTelemetry, Prometheus/Grafana |

## 9. Targets (proposed, unmeasured)
- Guard p95 < 800 ms (local-snapshot path < 100 ms); Intel read p95 < 150 ms.
- New malicious verdict → snapshot ≤ 5 min; new WASM scanned ≤ 10 min.
- `malicious` precision ≥ 98% on golden corpus; benign false-warning < 1%.

## 10. Build order
1. Phase 0: shared schemas, ingestion, golden labeled corpus.
2. Phase 1: Intel P0 + Guard SDK P0 + Scan P0; e2e test (lookalike asset flagged → Guard warns).
3. Phase 2: reports, disputes, feeds, CLI, similarity matching.
4. Phase 3: extension, dynamic analysis, partner imports.

## 11. Known weak points (don't paper over)
- Guard distribution depends on wallet partners.
- Scan efficacy unproven until corpus exists.
- False `malicious` labels carry legal/reputational risk → dispute process + enforced public language layer (invariants 9–13). Wording reduces risk, does not eliminate it; counsel must approve templates.
- Neutral wording weakens warnings → measure override rate; prefer effect-based Guard text.
- Three languages = coordination cost.
- Open: team size, cloud, business model, first wallet partner, who staffs review/dispute desk.

## 12. Hard Questions
Full detail: `PRD.md` §14 (product) and `ARCHITECTURE.md` §17 (technical). Append new questions here as HQ2, HQ3…

### HQ1 — What would break? (top items; thresholds are proposed, unmeasured)
| Break | Tripwire | Standing response |
|---|---|---|
| No wallet integrates Guard | No pilot partner in 6 weeks | Get pilot before building past decoder; fallback = web "paste XDR" checker |
| Intel is late for new threats (human review > attack window) | Time-to-flag > active life of flagged assets | Fast auto `caution`; Guard effect analysis works without Intel |
| Protocol 30 vote 2026-11-23 | `unanalyzable` > ~2%; ingest halted > 15 min | Follow §12 runbook; exhaustive decoder switch; no mainnet demo vote week |
| Sign-to-execute mismatch (upgradeable contracts, signed auth entries) | Simulated ≠ executed effects | `G-AUTH-UPGRADEABLE`; `not_checked` states the limit |
| Identity fragmentation (SAC / muxed / shared WASM) | Flagged asset not warned via SAC | `entity_link` + normalization + fixtures |
| Ingest gaps (7-day RPC window, leader-lock bugs) | Non-contiguous ledger sequence | Gap detector; Phase 0 spike: Hubble vs own Galexie |
| Alert fatigue | Override rate > ~90% per code | Per-code tuning; informational indicators capped |
| Unstaffed review/dispute desk | Queue age > SLA 2 weeks | Name an owner or defer `high_caution` |
| Hostile fetches (SSRF via `stellar.toml`) | Any private-range egress | Isolated fetcher, allowlist, caps |
| Unfunded running costs | Cost > runway | Cost model from a real one-week ingest run (Phase 0) |

### Decided: Phase 1 slice (ADR 0002)
Phase 1 vertical slice is **Guard effect analysis + minimal Intel (lookalike, home-domain)**, accepted 2026-10-27. See `docs/adr/0002-phase1-slice.md`.

### First experiments
E1 wallet-team conversations · E2 replay ≥10k historical txs through decoder · E3 labeled corpus + per-detector precision · E4 one-week ingest cost run · E5 auth-entry-only analysis spike.

### HQ2 — Edge cases to handle (full table: `ARCHITECTURE.md` §17 HQ2)
**Guard pipeline rules (v1):**
- Analyze exactly the bytes that are hashed for signing; display the tx hash.
- Compute effects per affected account from the signer's perspective (per-op source accounts, fee-bump inner/outer, signer-as-issuer).
- Effects carry `assurance` (`ledger | contract_reported`) and `bounds` (worst case first). Never trust contract events as ledger truth.
- Findings sorted by severity, never truncated; show op count.
- Unknown network passphrase → `partial`, never `no_signals`. Absence of data ≠ safety.
- Escape and strip control/bidi characters from all untrusted strings; no linkification.

**New Guard findings:** `G-MEMO-REQUIRED` (P0, highest everyday value), `G-SIGNER-ADDED` (hashX/preAuthTx ranked above plain keys), `G-NO-EXPIRY`, `G-SPONSORSHIP`, `G-DEST-LOOKALIKE`, `G-FEE-HIGH`, `G-NETWORK-UNKNOWN`, plus `G-AUTH-UPGRADEABLE`.

**Intel/Scan rules (v1):**
- Contract verdicts record the WASM hash and `as_of`; re-scan and recompute on contract upgrade (bait-and-switch).
- Treat WASM spec/meta as untrusted claims.
- Two lookalike detectors: ASCII code-confusables (assets) and IDN-confusables (domains); reference set is `code → {known issuers}` (legit multi-issuer codes exist).
- Re-verify `home_domain`/flags on schedule and on change; `consistent` can decay.
- Overturned disputes store suppressed evidence fingerprints (no re-flag loops); disputers prove control via `stellar.toml` challenge.
- One canonical key encoding + shared test vectors across Go/Rust/TS.
- Evidence store = public data only; reporter PII in a separate erasable store.

### HQ3 — v1 cut list (overrides the full doc for v1)
| Cut / simplify | v1 replacement |
|---|---|
| Numeric score (weight × trust × decay) | Rule table over fired detectors + evidence classes + analyst confirmation; evidence expiry dates; keep `as_of` |
| 5 verdict statuses | `active | revoked` + `disputed` flag; review queue separate |
| Scan HTTP service, job table, callbacks | Rust library + CLI, run by Intel as a one-shot sandboxed container job |
| Snapshot deltas / bloom / confirm step / key manifest / 2 active keys | Full sorted 128-bit-hash snapshot; 1 KMS key + 1 offline backup key pinned in SDK; max-age check |
| Redis | Postgres + in-process cache; rate limit at gateway |
| Partitioned evidence table | Plain table |
| `wording_template` DB table, locales | Templates in git (counsel as required reviewer), English only; keep renderer, lint, `public_statement` |
| `entity_link` 4 relations | `sac_of` only; WASM hash in contract attrs; muxed normalized at input |
| Report/dispute/webhook tables | Mailbox/form + manual log in `verdict_events`; 72 h ack target remains |
| Distributed tracing | Structured logs with correlation IDs |
| Effects for every op; SEP-43 adapter; UI component; local-only mode | Effects for ~7 ops; rest decode + `unanalyzable`; core library + one reference adapter |
| Roadmap: dynamic analysis, fuzzy similarity, extension, origin checks, partner imports | Parking lot |

**Kept (don't cut):** fail-closed renderer + blocklist lint, immutable evidence + statement history, lazy entity creation, `as_of`, WASM-parse sandbox, cross-repo contract tests, effect-first Guard, simple signed snapshot, append-only `verdict_events`.

**Decisions:** (1) Phase 1 slice = Guard effect analysis + minimal Intel: **accepted** (ADR 0002). (2) Defer Scan beyond minimal library until E3 shows signal: **still open**. Repo/language split (3 repos) is kept per your decision.
