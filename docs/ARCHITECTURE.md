<!-- GENERATED: edit sorosentinel-intel/docs/ARCHITECTURE.md, then run scripts/sync-docs.sh. -->

# ARCHITECTURE — SoroSentinel

| | |
|---|---|
| **Status** | Draft v0.1 |
| **Date** | 2026-10-26 |
| **Companion docs** | `PRD.md`, `ARCHITECTURE_ESSENTIALS.md` |

---

> **v1 scope override (HQ3, §17).** This document describes the target-state design. For the v1 build, the cuts in §17 HQ3 marked *Applied* override the sections they touch: no numeric score, no Redis, no partitioned evidence table, no Scan HTTP service, simple snapshot (no deltas/bloom/confirm step), templates in git instead of a DB table, `entity_link` limited to `sac_of`. Where this document and HQ3 disagree on v1 scope, **HQ3 wins**.

## 0. Platform facts this design depends on (with confidence)

Items marked **verify** were not confirmed against primary docs and must be checked before implementation.

| # | Fact | Confidence |
|---|---|---|
| F1 | Horizon is deprecated in favor of Stellar RPC; it still gets compatibility updates but no significant new features | [Certain] (Stellar developer docs) |
| F2 | Stellar RPC is the recommended real-time API; recent history (transactions/events) is limited to about a 7-day retention window | [Certain] (Stellar developer docs) |
| F3 | Full history must come from Galexie (ledger-metadata data lake) or Hubble (BigQuery dataset), not RPC | [Certain] (Stellar developer docs) |
| F4 | RPC offers `simulateTransaction` for Soroban transactions; Horizon does not | [Certain] |
| F5 | Protocol 23 introduced `TransactionMetaV4` / a unified events stream covering classic operations and contract events (CAP-67) | [Certain] (SDF upgrade guide + data provider docs) |
| F6 | Protocol 30 ("Bell"): Core v30.0.0 released 2026-10-16; testnet vote 2026-11-03; mainnet vote 2026-11-23; raw ledger-data consumers must update XDR definitions before upgrade | [Certain] (SDF guide updated 2026-10-20) |
| F7 | Soroban contracts are WASM modules; deployed WASM embeds contract spec/meta in custom sections (e.g., `contractspecv0`, `contractenvmetav0`, `contractmetav0`) | [Likely], **verify** section names |
| F8 | WASM host-function imports use compact module/function identifiers mapped via the env interface in `soroban-env-common` | [Likely], **verify** |
| F9 | Existing Soroban security tools: Scout (CoinFabrik, source-level), Certora Sunbeam (Wasm-level formal verification), Almanax (LLM-based) | [Certain] |
| F10 | SEP-1 (`stellar.toml`, home-domain metadata), SEP-41 (token interface), SEP-43 (wallet interface; used by Freighter / Wallets Kit) | [Certain] for SEP-1/41; **SEP-43 API surface checked 2026-10-30** against `stellar/stellar-protocol@62a67297ea14` v1.2.1 (still Draft): its `signAuthEntry` is self-contradictory — entry in the interface, preimage in the prose — and Freighter implements the **preimage** reading, returning a bare signature. See Guard `packages/adapter-reference/src/sep43.ts` |
| F11 | Go ecosystem has first-party ingestion tooling that can read Galexie output | [Likely], **verify** |
| F12 | A standalone browser extension cannot reliably hook other wallets' signing flows | [Guessing] |

---

## 1. Principles

1. **Intel is the center.** Guard and Scan are producers/consumers of Intel's data model. No product talks to another except through documented, versioned APIs.
2. **Fail loud, never fail clean.** An error, timeout, or unsupported operation yields "could not analyze," never "no issues."
3. **Evidence over opinion.** Every verdict is derived from recorded evidence. No evidence, no verdict.
4. **Automation can accuse softly; humans accuse firmly.** Automated sources are capped at `suspicious` unless ≥ 2 independent evidence classes agree.
5. **Local-first for privacy and latency.** Guard checks a signed snapshot locally before calling any API.
6. **Treat all inputs as hostile:** XDR, WASM, domains, reports, and dApp-provided data.
7. **Boring tech at v1.** Postgres, containers, one cloud. No Kafka, no Kubernetes until measured need.

---

## 2. System overview

```
                    ┌──────────────────────────────────────────┐
                    │           Stellar network                │
                    │  Core → Galexie (lake) / Stellar RPC     │
                    └───────────────┬──────────────────────────┘
                                    │ ledgers, events, deployments
                                    ▼
┌──────────────┐   evidence   ┌───────────────────────────────────┐   snapshot (signed)   ┌────────────────────┐
│ scan         │─────────────▶│               intel               │──────────────────────▶│       guard        │
│ (Rust)       │◀─────────────│  ingest · detectors · verdicts    │◀── API lookups ───────│  (TypeScript SDK)  │
│ WASM triage  │  scan jobs   │  Postgres · Redis · object store  │                       │  in wallets/dApps  │
└──────┬───────┘              └───────────────┬───────────────────┘                       └─────────┬──────────┘
       │                                      │ REST API / webhooks                                 │ simulateTransaction
       │ reads WASM via RPC                   ▼                                                     ▼
       ▼                          exchanges · anchors · analysts · lookup UI                  Stellar RPC
   Stellar RPC
```

*Diagram labels are short names for the repos `sorosentinel-scan`, `sorosentinel-intel` and `sorosentinel-guard`.*

### Data flows

| Flow | Path |
|---|---|
| **A. Detection** | Ledger → Intel ingest → detectors → evidence → verdict engine → snapshot/API |
| **B. Contract triage** | Intel sees new WASM/contract → `POST scan job` → Scan fetches + analyzes → callback with findings → Intel stores as evidence |
| **C. Signing** | Wallet → Guard SDK → decode → (simulate via RPC) → effects → local snapshot lookup (API fallback) → findings → UI |
| **D. Community** | Report → review queue → human decision → verdict (+ dispute path) |

---

## 3. Repositories and boundaries

| Repo | Language | Owns | Exposes | Depends on |
|---|---|---|---|---|
| `sorosentinel-intel` | Go | Ingestion, entities, evidence, verdicts, API, snapshots, **shared schemas** | REST API (OpenAPI), signed snapshots, webhooks; published `schemas` packages | Galexie/RPC, Postgres, Redis, object store |
| `sorosentinel-scan` | Rust | WASM analysis engine, detectors, sandbox, CLI | REST API (OpenAPI), CLI, report JSON/SARIF | Stellar RPC (to fetch WASM), Intel (callback) |
| `sorosentinel-guard` | TypeScript | Tx/auth-entry decoding, effect computation, rules, SDK | npm package; optional extension (P2) | Stellar RPC, Intel snapshot/API |

### 3.1 Polyrepo risk and mitigation (important)

Three repos in three languages will drift unless the contract between them is machine-enforced.

- **Source of truth:** OpenAPI specs + JSON Schema for `Verdict`, `Evidence`, `Entity`, `Finding`, `ScanReport`, `Snapshot`, all owned by `sorosentinel-intel/schemas/`.
- **Publishing:** CI in `sorosentinel-intel` publishes generated types: `@sorosentinel/schemas` (npm), `sorosentinel-schemas` (crate), Go package in-repo. Consumers pin versions.
- **Compatibility rule:** additive changes only within a major version; breaking changes require a new `/v2` path and a dual-run period.
- **Contract tests:** each consumer repo runs contract tests against a mock generated from the pinned spec; Intel runs provider tests against recorded consumer expectations.
- **Rejected alternative:** a 4th `sorosentinel-schemas` repo. It adds a release hop. (You asked for three repos; hosting schemas in Intel keeps that true.)

---

## 4. Intel design

### 4.1 Ingestion

- **Backfill:** read ledger metadata from Galexie lake (or Hubble/BigQuery for bulk analytics) in batch. [F3]
- **Live tail:** poll Stellar RPC `getLedgers` / `getEvents` and reconcile against lake data. [F2, F5]
- **Do not build on Horizon.** [F1]
- **Lazy entity creation:** do not create an `entity` row for every account/asset/contract on the ledger (asset creation is cheap, so attackers can inflate the table and the snapshot). Create entities only when (a) a detector emits evidence, (b) a lookup/scan first requests them, or (c) they are in a curated watchlist (e.g., top assets by volume used as lookalike references).
- **Identity normalization before lookup/storage:** muxed addresses (`M…`) normalize to their underlying `G…` account; classic assets and their Stellar Asset Contract (SAC) address are linked via `entity_link` (§7.1) so evidence on one identity applies to the other.
- **Idempotency:** every ingest unit is keyed by `(network, ledger_seq)`; replays are safe.
- **Checkpointing:** last fully processed ledger per network stored in Postgres; reorg is not a concern (Stellar ledgers are final on close) [Likely].
- **Upgrade safety:** XDR library version is pinned and upgraded deliberately with each protocol release (see §12).

### 4.2 Detectors (v1, rule-based)

| ID | Detector | Signal | Max level alone |
|---|---|---|---|
| D-ASSET-LOOKALIKE | Asset code equals or is a homoglyph/near-match of a known-benign asset code but issuer differs | Lookalike + low age + low holders | `suspicious` |
| D-HOMEDOMAIN-MISMATCH | Issuer's `home_domain` stellar.toml does not list the asset, or domain unreachable/typosquat of known domain | SEP-1 check | `suspicious` |
| D-FLAGS-RISK | Issuer has clawback / revocable / auth-required flags set | Informational risk factor, **not** accusation | `unknown` + tag |
| D-TRUSTLINE-SPAM | Account(s) mass-creating trustlines or mass-sending dust of an asset | Pattern over window | `suspicious` |
| D-ACCOUNT-TAKEOVER-PATTERN | Reported/observed SetOptions that remove owner signer and add unknown signer, then drain | Multi-step pattern | `suspicious` |
| D-CONTRACT-SCAN | Evidence from Scan | Informational indicators (S-UPGRADEABLE, S-CROSS-CALL, S-CREATES-CONTRACTS, S-OLD-SDK) never raise a level alone: `unknown` + tag. `suspicious` only when combined with another evidence class or a known-bad hash. Indicators are per `wasm_hash`, so one hash can span many legitimate instances. | `suspicious` (combined only) |
| D-COMMUNITY-REPORT | Human-submitted report | Weight by reporter trust | `suspicious` |
| D-CURATED | Human analyst decision with evidence | Manual | up to `malicious` |

### 4.3 Verdict engine

- **Score:** `score = f(evidence_set, as_of) = Σ (evidence.weight × source.trust × decay(as_of − observed_at))`, clamped 0–100. `as_of` is an explicit input and is stored with every verdict; the engine never reads the wall clock inside the scoring function.
- **Level mapping:** thresholds → `unknown` / `suspicious`; `malicious` requires (a) curated human verdict, **or** (b) ≥ 2 independent evidence classes with score above threshold *and* a review-queue pass in v1.
- **Overrides:** a curated `benign` (analyst-confirmed legitimate) beats automated `suspicious` until new evidence arrives and a human re-reviews.
- **State machine:** `proposed → active → disputed → (active | revoked | expired)`. All transitions append to `verdict_events`.
- **Determinism:** the same `(evidence_set, as_of, ruleset_version)` must always produce the same score. Disputes and audits replay at the stored `as_of`. (A time-decayed score cannot be deterministic without `as_of`; the first draft omitted this.)

### 4.4 Snapshot

- Compact artifact containing hashed entity keys for `suspicious`/`malicious` entities, a version number, generation time, and an Ed25519 signature.
- Format: sorted truncated-hash list with an index (simple, diffable); a cuckoo/bloom filter is an optimization if size demands. Hash collisions are resolved by an API confirm step in Guard when a hit occurs.
- Published to object storage + CDN every ≤ 5 min when changed; delta files between versions.
- Signing key in KMS; two active key IDs for rotation; Guard ships with a pinned public keyset.

### 4.5 API (v1 outline)

| Endpoint | Purpose |
|---|---|
| `GET /v1/entities/{type}/{id}?network=` | Verdict + evidence summary |
| `POST /v1/entities:batchGet` | Up to N entities (used by Guard fallback and exchanges) |
| `GET /v1/snapshots/latest`, `GET /v1/snapshots/{version}` | Snapshot metadata/download |
| `POST /v1/reports` | Community report (P1) |
| `POST /v1/disputes` | Appeal (P1) |
| `POST /v1/scan-callbacks` | Receive Scan results (internal, signed) |
| `POST /v1/webhooks` | Subscribe (P1) |

Auth: API keys (hashed at rest), per-key rate limits, public tier for lookups with strict limits. Internal service-to-service calls use signed requests (HMAC or mTLS).

### 4.6 Public language layer (legal-risk control; implements PRD §5.1)

**Design rule:** the *renderer* is the only code path that produces user-visible text. Nothing else (API handlers, Guard, Scan, analysts) can put free text in front of a user.

```
evidence + verdict (internal)
        │
        ▼
 statement builder ──► picks template by (finding/detector code, entity_type, internal level)
        │                fills slots ONLY from structured, verifiable facts
        ▼
 renderer ── validates: required slots present, as_of present, methodology_url present,
        │               blocklist lint passes, template.status = 'approved'
        ▼
 public statement { statement_id, template_id, template_version, text, facts[], as_of,
                    method, methodology_url, review_url, signal_level }
```

**Controls (each is enforced, not advisory)**

| Control | Mechanism |
|---|---|
| Template registry | Templates live in `sorosentinel-intel/wording/` (versioned in git) and are mirrored to table `wording_template` with `status` (`draft` → `counsel_approved` → `retired`). Only `counsel_approved` templates can render in prod. |
| Slot discipline | Slots accept only typed, structured values (timestamps, asset keys, domains, ledger numbers, booleans). No free-text slot exists. |
| Fail closed | If any required piece is missing or validation fails, the API returns the structured `signal_level` + `facts[]` **without** prose, never an unreviewed string. |
| Blocklist lint | CI job scans every template and its translations for blocked terms (PRD §5.1 L6) and for missing attribution placeholders. Same check runs at render time as a second layer. |
| Internal/public separation | `verdict.rationale` and analyst notes are internal columns. Public response schemas use an **allowlist** of fields; a contract test fails if an internal field appears in any public response. |
| Public enum mapping | DB enums stay `benign/unknown/suspicious/malicious`; API exposes `consistent/no_signals/caution/high_caution` (`consistent` = matches the entity's own published data; it never implies trustworthiness). Mapping is a single function with tests; internal names never serialize. |
| Immutable evidence | For every published fact, store the raw artifact (e.g., fetched `stellar.toml` body + hash + fetch time, ledger/tx refs, WASM sha256 + ruleset version) in object storage with write-once retention. |
| Statement history | Every rendered statement is stored (`public_statement`), so what was shown, when, and from which template version is reproducible for disputes. |
| Localization | Translations are separate template rows, each needing approval; no machine translation straight to prod. |
| Integrators | API response includes ready-to-display `text`; ToS requires displaying it unaltered with attribution. Cannot be technically enforced for third-party UIs [Likely]. |

**Template shape (illustrative)**

```yaml
id: asset.lookalike.v1
applies_to: { entity_type: asset, detector: D-ASSET-LOOKALIKE }
signal_level_min: caution
text: >
  This asset uses the same code as {known_asset} but a different issuer account.
  The issuer of {known_asset} is {known_issuer}. Observed {as_of}.
required_slots: [known_asset, known_issuer, as_of]
attribution: standard_v1   # adds: method, "indicator, not a determination of intent or wrongdoing", methodology + review links
status: counsel_approved
```

**Guard specifics:** findings render from the same registry. Prefer templates keyed on *effect* (e.g., `tx.signer_added.v1`) over entity judgments; entity-based templates (`G-DEST-FLAGGED`) reuse the Intel statement text verbatim.

---

## 5. Guard design

### 5.1 Pipeline

```
input: { xdr (tx envelope | auth entry), network_passphrase, signer_account, origin? }
  1. Parse (stellar-sdk XDR) ── fail ─▶ UNANALYZABLE
  2. Classify operations / invocation tree
  3. If Soroban: simulateTransaction via RPC ── fail/timeout ─▶ PARTIAL (static findings + "simulation unavailable")
  4. Derive effects: balance deltas for signer, trustline changes, signer/threshold changes, approvals, auth tree
  5. Enrich: local snapshot lookup (counterparties, assets, contracts); API fallback on hit/uncertain
  6. Rules → findings {code, severity, title, explanation, evidence_ref}
  7. Output: { status: findings_present | no_issues_found | partial | unanalyzable, effects, findings }
```

`no_issues_found` always ships with a standard "what was not checked" notice; there is no `safe` state.

**Pipeline rules added by HQ2 (§17):**
1. Analyze exactly the bytes that are hashed for signing, and display that transaction hash. Integrate at the signing boundary, not at the dApp boundary.
2. Compute effects **per affected account from the signer's perspective** (per-operation source accounts, fee-bump inner vs. outer, signer-as-issuer).
3. Every effect carries `assurance` (`ledger` | `contract_reported`) and `bounds` (worst case first: "up to X").
4. Findings are ordered by severity and **never truncated**; always show the operation count.
5. Unknown network passphrase → `partial` ("no intelligence for this network"), never `no_signals`.
6. Untrusted strings (memo, asset codes, `stellar.toml` fields, domains) are escaped, stripped of control/bidi characters, and never linkified.

### 5.2 Finding codes (v1)

| Code | Trigger | Severity |
|---|---|---|
| G-ACCOUNT-CONTROL | SetOptions changing signers/thresholds/master weight | Critical |
| G-ACCOUNT-MERGE | AccountMerge | High |
| G-TRUST-FLAGGED | ChangeTrust to asset with `suspicious`/`malicious` verdict | High–Critical |
| G-TRUST-CLAWBACK | Trustline to clawback-enabled asset (informational) | Info–Medium |
| G-DEST-FLAGGED | Destination account/contract flagged | High–Critical |
| G-AUTH-WIDE | Soroban auth entry covering deep sub-invocation transferring tokens, or unusually long expiry ledger | High |
| G-AUTH-UPGRADEABLE | Auth entry signed for a contract whose code can be replaced after deployment (Scan: S-UPGRADEABLE). The signature authorizes the invocation, and the code that runs at execution time may differ from the code simulated now. Wording describes the capability and the signing window, not the contract's operator. | Medium–High |
| G-CONTRACT-FLAGGED | Invoked contract/WASM hash flagged | High–Critical |
| G-ORIGIN-FLAGGED | dApp origin matches flagged/lookalike domain (P1) | High |
| G-UNKNOWN-EFFECT | Effects could not be fully determined | Medium |
| G-MEMO-REQUIRED | Destination account declares it requires a memo (SEP-29-style account data flag [Likely, verify exact key]) and the transaction has none. Non-accusatory; likely the most common real-world loss. | High |
| G-SIGNER-ADDED | SetOptions adds a signer. Severity depends on key type: hash(x) and pre-authorized-transaction signers have no visible owner key and rank above a plain public key. Includes weight and threshold effect. | High–Critical |
| G-NO-EXPIRY | Transaction has no upper time bound (or one far in the future), so a signed copy stays usable until its sequence number is consumed | Medium |
| G-SPONSORSHIP | Begin/End-sponsoring or revoke-sponsorship operations that change who locks reserves | Medium |
| G-DEST-LOOKALIKE | Destination matches the prefix/suffix of an address in the wallet-supplied `known_counterparties[]` but is not in it (address-poisoning pattern) | High |
| G-FEE-HIGH | Declared fee/resource fee far above the simulated minimum | Medium |
| G-NETWORK-UNKNOWN | Network passphrase has no Intel coverage; returns `partial`, never `no_signals` | Info |

### 5.3 Integration model (decision driven by risk F12)

1. **Primary:** SDK/middleware that a wallet or dApp calls before signing (`analyze(xdr, ctx)`), plus a ready-made UI component for the warning.
2. **Secondary:** adapter for the common wallet-kit interface (SEP-43-style `signTransaction` / `signAuthEntry` wrappers). [F10, verify]
3. **Last (P2):** standalone extension, only if data shows demand; likely limited to dApp-side pages where it can mediate calls.

### 5.4 Privacy

- Default path sends nothing to Intel except on a snapshot hit (hash prefix confirm) or explicit opt-in.
- RPC simulation requires sending the transaction to an RPC endpoint; the integrator chooses the endpoint (documented).
- No telemetry by default; opt-in anonymous counters only.

---

## 6. Scan design

### 6.1 Pipeline

```
trigger: Intel job | API request | CLI
  1. Acquire WASM (RPC getLedgerEntries by contract/hash, or upload); store by sha256 in object store
  2. Dedupe: if sha256 already analyzed with current ruleset version → reuse
  3. Sandboxed worker (no network, cgroup limits, wall-clock timeout, read-only FS)
  4. Parse: wasmparser → imports, exports, custom sections (spec/meta), function count, size  [F7, F8]
  5. Feature extraction → detectors → indicators[]
  6. Report: { wasm_sha256, ruleset_version, indicators[], not_checked[], meta{sdk, protocol} }
  7. Callback to Intel as evidence (signed)
```

### 6.2 Detectors (v1, feature-based — coarse by design)

| ID | Indicator | Basis | Efficacy |
|---|---|---|---|
| S-UPGRADEABLE | Imports host function enabling replacing the contract's own code | Import list | Reliable detection; **risk implication depends on who controls it** |
| S-CREATES-CONTRACTS | Imports contract-deployment host functions | Import list | Reliable |
| S-CROSS-CALL | Uses cross-contract invocation; count/targets if statically resolvable | Import list | Reliable for presence |
| S-NO-AUTH-CHECK | Mutating exports (storage writes) with no auth-check host function imported anywhere | Import list + spec | Coarse heuristic; false positives likely [Guessing] |
| S-SEP41-DEVIATION | Declares token-like interface but spec deviates from standard | Spec section | Moderate |
| S-KNOWN-BAD-HASH | Exact sha256 match to known malicious WASM | Intel lookup | Reliable but only for known samples |
| S-OLD-SDK | Embedded SDK/env version older than a threshold | Meta section | Reliable |

**Honest limitation:** these are indicators, not proof of malice. Effectiveness against real hostile contracts is unvalidated until a labeled corpus exists (PRD risk #3). Phase 0 builds that corpus before detector tuning.

### 6.3 Later phases

- **P1:** function-level hashing + fuzzy similarity (minhash) against known-bad.
- **P2:** dynamic analysis using the Soroban host in a simulated environment with fuzzed inputs; strict resource budgets.

### 6.4 Scanner hardening

- Parsing hostile WASM: memory-safe language (Rust), fuzzing the parser integration (`cargo-fuzz`), max module size, max section count.
- Never instantiate or execute contract code outside the Soroban host sandbox (P2 only).
- Per-job container with seccomp profile, no network, tmpfs workspace, killed on timeout.

---

## 7. Data models

### 7.1 Intel (PostgreSQL 16) — core tables

```sql
CREATE TYPE entity_type AS ENUM ('account','asset','contract','wasm_hash','domain');
CREATE TYPE verdict_level AS ENUM ('benign','unknown','suspicious','malicious');
CREATE TYPE verdict_status AS ENUM ('proposed','active','disputed','revoked','expired');
CREATE TYPE source_kind AS ENUM ('heuristic','scan','community','curated','partner');

CREATE TABLE entity (
  id            BIGSERIAL PRIMARY KEY,
  network       TEXT NOT NULL CHECK (network IN ('public','testnet')),
  type          entity_type NOT NULL,
  key           TEXT NOT NULL,          -- G... / asset "CODE:ISSUER" / C... / sha256 hex / domain
  first_seen_ledger BIGINT,
  first_seen_at TIMESTAMPTZ,
  attrs         JSONB NOT NULL DEFAULT '{}',   -- type-specific: flags, home_domain, holders, etc.
  UNIQUE (network, type, key)
);

CREATE TABLE source (
  id          SMALLSERIAL PRIMARY KEY,
  name        TEXT UNIQUE NOT NULL,
  kind        source_kind NOT NULL,
  trust       REAL NOT NULL CHECK (trust BETWEEN 0 AND 1),
  config      JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE evidence (
  id          BIGSERIAL,
  entity_id   BIGINT NOT NULL REFERENCES entity(id),
  source_id   SMALLINT NOT NULL REFERENCES source(id),
  detector    TEXT NOT NULL,            -- e.g. D-ASSET-LOOKALIKE
  evidence_class TEXT NOT NULL,         -- groups independence: 'onchain-pattern','scan','human','domain'
  weight      REAL NOT NULL,
  category    TEXT NOT NULL,            -- impersonation_asset, trustline_spam, drainer_contract, ...
  payload     JSONB NOT NULL,           -- details, tx hashes, ledger refs, scan indicator
  observed_at TIMESTAMPTZ NOT NULL,
  ledger_seq  BIGINT,
  expires_at  TIMESTAMPTZ,
  PRIMARY KEY (id, observed_at)
) PARTITION BY RANGE (observed_at);

CREATE TABLE verdict (
  id          BIGSERIAL PRIMARY KEY,
  entity_id   BIGINT NOT NULL REFERENCES entity(id),
  level       verdict_level NOT NULL,
  score       REAL NOT NULL,
  confidence  REAL NOT NULL,
  category    TEXT,
  status      verdict_status NOT NULL,
  decided_by  TEXT,                      -- 'engine' or analyst id
  rationale   TEXT,
  ruleset_version TEXT NOT NULL,
  valid_from  TIMESTAMPTZ NOT NULL DEFAULT now(),
  valid_until TIMESTAMPTZ,
  UNIQUE (entity_id) DEFERRABLE INITIALLY IMMEDIATE   -- one current verdict per entity; history in verdict_events
);

CREATE TABLE verdict_events (            -- append-only audit log
  id          BIGSERIAL PRIMARY KEY,
  entity_id   BIGINT NOT NULL,
  from_level  verdict_level, to_level verdict_level,
  from_status verdict_status, to_status verdict_status,
  actor       TEXT NOT NULL,
  reason      TEXT,
  evidence_ids BIGINT[],
  at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Alternate identities of the same real-world thing (see §4.1 normalization)
CREATE TABLE entity_link (
  from_entity_id BIGINT NOT NULL REFERENCES entity(id),
  to_entity_id   BIGINT NOT NULL REFERENCES entity(id),
  relation       TEXT NOT NULL CHECK (relation IN ('sac_of','wasm_of','muxed_of','same_issuer')),
  PRIMARY KEY (from_entity_id, to_entity_id, relation)
);
-- Verdict lookup follows entity_link: a flag on a classic asset applies to its SAC contract and vice versa.

-- Public language layer (see §4.6)
CREATE TABLE wording_template (
  id            TEXT NOT NULL,            -- e.g. asset.lookalike.v1
  version       INT  NOT NULL,
  locale        TEXT NOT NULL DEFAULT 'en',
  body          TEXT NOT NULL,
  required_slots TEXT[] NOT NULL,
  attribution   TEXT NOT NULL,
  status        TEXT NOT NULL CHECK (status IN ('draft','counsel_approved','retired')),
  approved_by   TEXT, approved_at TIMESTAMPTZ,
  PRIMARY KEY (id, version, locale)
);

CREATE TABLE public_statement (          -- immutable record of what was shown
  id            BIGSERIAL PRIMARY KEY,
  entity_id     BIGINT NOT NULL REFERENCES entity(id),
  verdict_id    BIGINT REFERENCES verdict(id),
  template_id   TEXT NOT NULL, template_version INT NOT NULL, locale TEXT NOT NULL,
  signal_level  TEXT NOT NULL CHECK (signal_level IN ('consistent','no_signals','caution','high_caution')),
  rendered_text TEXT NOT NULL,
  facts         JSONB NOT NULL,          -- structured slot values
  as_of         TIMESTAMPTZ NOT NULL,
  evidence_artifacts TEXT[] NOT NULL,    -- object-store keys of write-once raw artifacts
  superseded_at TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE report (
  id BIGSERIAL PRIMARY KEY, entity_id BIGINT REFERENCES entity(id),
  reporter_id TEXT, body JSONB NOT NULL, status TEXT NOT NULL DEFAULT 'open',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE dispute (
  id BIGSERIAL PRIMARY KEY, verdict_id BIGINT NOT NULL REFERENCES verdict(id),
  submitter_contact TEXT, claim TEXT NOT NULL, supporting JSONB,
  status TEXT NOT NULL DEFAULT 'open', resolution TEXT,
  opened_at TIMESTAMPTZ NOT NULL DEFAULT now(), resolved_at TIMESTAMPTZ
);

CREATE TABLE scan_job (
  id UUID PRIMARY KEY, entity_id BIGINT NOT NULL REFERENCES entity(id),
  wasm_sha256 TEXT NOT NULL, ruleset_version TEXT NOT NULL,
  status TEXT NOT NULL, requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ, report_ref TEXT
);

CREATE TABLE snapshot (
  version BIGSERIAL PRIMARY KEY, generated_at TIMESTAMPTZ NOT NULL,
  entry_count INT NOT NULL, object_key TEXT NOT NULL,
  signing_key_id TEXT NOT NULL, signature BYTEA NOT NULL
);

CREATE TABLE api_key (
  id UUID PRIMARY KEY, key_hash BYTEA NOT NULL, owner TEXT NOT NULL,
  tier TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), revoked_at TIMESTAMPTZ
);

CREATE TABLE ingest_checkpoint (
  network TEXT PRIMARY KEY, last_ledger BIGINT NOT NULL, updated_at TIMESTAMPTZ NOT NULL
);
```

Indexes of note: `entity(network,type,key)` unique; `evidence(entity_id, observed_at DESC)`; `verdict(level, status)` for snapshot generation; partial index on `verdict` where `level IN ('suspicious','malicious')`.

### 7.2 Shared JSON contracts (in `sorosentinel-intel/schemas/`)

| Schema | Key fields |
|---|---|
| `Entity` | `network`, `type`, `key` |
| `Verdict` | `entity`, `level`, `score`, `confidence`, `category`, `status`, `valid_from`, `valid_until`, `ruleset_version` |
| `Evidence` | `detector`, `evidence_class`, `source`, `weight`, `observed_at`, `payload` |
| `Finding` (Guard) | `code`, `severity`, `title`, `explanation`, `evidence_ref?` |
| `AnalysisResult` (Guard) | `status`, `tx_hash`, `network`, `effects[]` (each: `account`, `asset`, `delta_min`, `delta_max`, `assurance`), `findings[]`, `not_checked[]` |
| `ScanReport` (Scan) | `wasm_sha256`, `ruleset_version`, `indicators[]`, `meta`, `not_checked[]` |
| `Snapshot` | `version`, `generated_at`, `key_id`, `signature`, `entries` |

### 7.3 Scan storage

- Object store: `wasm/{sha256}.wasm`, `reports/{sha256}/{ruleset_version}.json`.
- Scan is stateless apart from the object store plus a small job table (Postgres or SQLite per deployment) to track in-flight jobs.

### 7.4 Guard storage

- None server-side. Client holds: latest snapshot (IndexedDB/memory), pinned public keyset, optional user-set preferences.

---

## 8. Tech stack

| Layer | Choice | Why | Rejected alternatives (and why) |
|---|---|---|---|
| Intel language | **Go** | First-party ingestion tooling for Galexie/ledger data [F11, verify]; simple concurrency for ingest workers | TypeScript (weaker for high-throughput ingest); Rust (less ingest ecosystem [Guessing]) |
| Scan language | **Rust** | Native `wasmparser`, Soroban host/env crates, memory safety when parsing hostile input | Go (weak WASM-analysis ecosystem); TS (worse perf/safety for the job) |
| Guard language | **TypeScript** | Wallet ecosystem is JS/TS; official JS Stellar SDK; runs in browser/extension/Node | Rust→WASM (adds build complexity for integrators; revisit if decoders must be shared) |
| Primary DB | **PostgreSQL 16** (managed) | Relational integrity for verdicts/evidence, JSONB flexibility, partitioning | Document DB (weaker integrity for audit log); ClickHouse (premature; revisit for analytics) |
| Cache / rate limits | **Redis** | Hot verdict cache, rate limiting | In-process cache only (breaks with multiple instances) |
| Job queue | **Postgres-backed queue** (e.g., River for Go) | One less system at v1 | Kafka/NATS (operational overhead without measured need) |
| Object storage | **S3-compatible** | WASM blobs, snapshots, reports, CDN origin | Local disk (not durable/shareable) |
| API style | **REST + OpenAPI 3.1** | Simple for integrators; codegen for 3 languages | gRPC (poor browser ergonomics for Guard fallback) |
| Signing | **Ed25519**, keys in cloud KMS | Compact, fast verify in browser | RSA (larger/slower); unsigned snapshots (unacceptable) |
| Infra | **Docker + Terraform, single cloud, managed services** | Small team friendly | Kubernetes at v1 (cost/complexity) |
| CI/CD | **GitHub Actions per repo** | Standard; repo-local pipelines | Monorepo CI (not applicable: polyrepo) |
| Observability | **OpenTelemetry → Prometheus/Grafana + structured logs** | Vendor-neutral | Vendor lock-in APM at v1 |
| Testing | See §13 | | |

Cloud provider: **undecided** (open question). Nothing in the design requires a specific provider.

---

## 9. Security and trust model

| Threat | Control |
|---|---|
| Poisoned verdict (attacker submits fake reports to smear competitor) | Reporter trust weights, human review before `malicious`, evidence required, rate limits, audit log |
| Compromised snapshot signing key | KMS-held keys, two-key rotation, Guard pins keyset with key IDs and revocation list in the release |
| Tampered snapshot in transit/CDN | Signature verification client-side (never trust transport) |
| Malicious WASM/XDR attacking the scanner/decoder | Sandboxing, resource limits, fuzzing, memory-safe parsers, size caps |
| API abuse / scraping | API keys, rate limits, tiering, caching |
| Supply chain (npm/crates/go modules) | Lockfiles, pinned versions, provenance/signing for published packages, dependency review in CI |
| Guard SDK exfiltrating user data | Minimal network surface, documented endpoints, opt-in telemetry, open-source SDK |
| Insider changing a verdict silently | Append-only `verdict_events`, two-person rule for `malicious` (recommended), periodic audit export |
| Hostile fetches (Intel fetches attacker-controlled `stellar.toml` / domains: SSRF, huge bodies, slow responses, redirects to internal addresses) | Dedicated fetcher in an isolated network segment; egress allowlist denying private/link-local/metadata ranges (re-checked after DNS resolution and on every redirect); no redirects to private IPs; body-size and wall-clock caps; fixed User-Agent; per-domain rate limits |
| Revoked/compromised snapshot key still trusted by old SDKs | Signed keyset manifest with expiry (root key offline); clients refuse snapshots older than a max age and show "protection data stale" rather than silently using old data; SDK checks manifest at startup |
| Defamation/legal exposure | Enforced public language layer (§4.6): counsel-approved templates only, fact-based slots, fail-closed rendering, blocklist lint, internal/public field separation, immutable evidence + statement history, dispute SLA, documented methodology. Reduces, does not eliminate, risk. |

---

## 10. Deployment and operations

- **Environments:** `dev`, `staging` (Stellar testnet), `prod` (Stellar public network). Separate Postgres per env.
- **Intel:** stateless API pods + ingest worker(s) + verdict worker + snapshot publisher cron. Horizontal scale on API; single-writer ingest per network with leader lock.
- **Scan:** autoscaled worker pool consuming jobs; each job in an isolated container.
- **Guard:** distributed as npm package; no server-side deployment (except optional docs/demo site).
- **Backups:** Postgres PITR; object store versioning; snapshot history retained.
- **SLOs:** per PRD §7; alert on ingest lag (> N ledgers), snapshot age, scan queue age, verdict-engine error rate.
- **Cost watch-outs:** RPC provider rate limits for Guard simulation (integrator-supplied endpoint); lake/BigQuery scan costs for backfill.

---

## 11. Observability

- Metrics: ingest lag, ledgers/sec, detector hit rates, verdict counts by level, snapshot size/age, API latency, Guard-provided opt-in counters, scan duration/failure rate.
- Tracing across Intel↔Scan callbacks via propagated trace IDs.
- Quality dashboards: dispute rate, overturn rate, detector precision (from labeled corpus + review outcomes).

---

## 12. Protocol and dependency upgrades

- **Why this matters now:** Protocol 30 mainnet vote is 2026-11-23, testnet vote 2026-11-03; ledger-data consumers must update XDR definitions before upgrade. [F6]
- **Runbook (per protocol release):**
  1. Track SDF upgrade guide; bump XDR libs in all three repos on a branch.
  2. Replay recent testnet ledgers through ingest + Guard decode fixtures.
  3. Deploy to staging against testnet before the testnet vote.
  4. Canary on mainnet before the vote date.
  5. Ingest worker must **halt with an alert**, not skip or guess, on unknown XDR.
- Guard: SDK ships a compatibility matrix (protocol version ↔ SDK version); unknown operation types produce `unanalyzable`.

---

## 13. Testing strategy

| Level | What |
|---|---|
| Unit | Detectors, scoring, XDR classification, effect derivation |
| Golden corpus | Labeled set of known scam/benign assets, accounts, contracts, WASM (built in Phase 0) with per-detector precision/recall tracking |
| Fixtures | Real transaction XDRs (benign + hostile) for Guard, incl. SetOptions takeover and wide auth entries |
| Contract tests | Consumer-driven tests between repos on the shared OpenAPI/JSON Schema |
| Fuzzing | XDR decoder, WASM parser, API inputs |
| Replay | Re-run historical ledger ranges through ingest to confirm deterministic verdicts |
| E2E | Testnet scenario: create lookalike asset → Intel flags → snapshot → Guard warns |
| Chaos | RPC down/slow, snapshot stale, Intel unreachable: Guard must degrade to `partial`/`unanalyzable`, never clean |

---

## 14. Architecture decision records (summary)

| ADR | Decision | Status |
|---|---|---|
| 001 | Intel is the shared foundation; all cross-product communication is via versioned REST/OpenAPI + signed artifacts | Proposed |
| 002 | Schemas live in `sorosentinel-intel/schemas`, published as packages to other repos | Proposed |
| 003 | Go (Intel), Rust (Scan), TypeScript (Guard) | Proposed |
| 004 | No Horizon dependency; RPC for live, Galexie/Hubble for history | Proposed |
| 005 | Automated sources capped at `suspicious`; `malicious` requires human confirmation (v1) | Proposed |
| 006 | Never output "safe"; fail-safe statuses (`partial`, `unanalyzable`) | Proposed |
| 007 | Signed snapshot, local-first checks in Guard | Proposed |
| 008 | Postgres-backed queue and single cloud; no Kafka/Kubernetes at v1 | Proposed |
| 009 | Scan = deployed-bytecode triage; no source-level analysis (covered by existing tools) | Proposed |
| 010 | Guard ships as SDK first, extension last | Proposed |
| 011 | All public text is produced by a template renderer from structured facts; no free text, internal enums never exposed, fail closed (§4.6) | Proposed |

---

## 15. Known weaknesses of this design

1. **Three languages.** Hiring and context-switching cost. Justified per component but real. If the team is ≤ 3 people, collapse Intel to TypeScript and accept slower ingest tooling.
2. **Snapshot-first privacy trades completeness for freshness.** A 5-minute window exists in which a brand-new scam is unknown to Guard.
3. **Rule-based detection is brittle.** Attackers adapt to published rules; transparency (good for trust) helps them.
4. **Scan v1 indicators are coarse.** See §6.2.
5. **RPC retention (~7 days) forces a dual-source ingest path** (live RPC + lake) with reconciliation complexity. [F2, F3]
6. **Single-writer ingest** is a bottleneck/failure point; needs a clear failover procedure.
7. **Neutral wording trades warning strength for legal safety.** Users may under-react to "caution" text. Mitigated by effect-based Guard wording, but the tradeoff is real and should be measured (warning override rate).
8. **Template approval is a bottleneck.** Counsel review per template slows new detectors; each new detector must ship with its template, or it cannot render prose in prod.
9. **Integrators can alter or soften/harden displayed text.** ToS can forbid it; technical enforcement is not possible for third-party UIs. [Likely]

---

## 16. Open questions affecting architecture

1. Team size/skills (language split, §15.1).
2. Cloud provider and data-residency constraints.
3. Business model (drives tiering, SLOs, support).
4. First wallet integration target (drives Guard API shape and SEP-43 adapter).
5. Existing labeled data for the golden corpus.
6. Mainnet only or testnet too in public API?
7. Who operates the human review queue and the dispute desk?

---

## 17. Hard Questions

Numbered so more can be appended. Product/business counterparts live in `PRD.md` §14. Rankings are my judgment, not measured. [Guessing]

### HQ1 — What would break? (technical)

| # | What breaks | Why I expect it | Tripwire (proposed) | Response | Status |
|---|---|---|---|---|---|
| T1 | **Protocol 30 upgrade window.** Ingest halts on unknown XDR (by design) and Guard returns `unanalyzable` for new variants. SDF's guide notes a credentials-type name (`SOROBAN_CREDENTIALS_ADDRESS`) still works with no deprecation date, and that a future protocol may retire it. [Certain] The mainnet vote is 2026-11-23. [Certain] | Any launch or demo near the vote date inherits upgrade risk; every new auth/credential variant is a decode gap. | Guard `unanalyzable` rate above ~2% of requests; ingest halted > 15 min | Follow §12 runbook; exhaustive switch over op/credential types with compile-time exhaustiveness; replay P30 testnet ledgers before the testnet vote (2026-11-03). **Do not demo on mainnet during the vote week.** | Open |
| T2 | **Sign-to-execute mismatch (TOCTOU).** Guard simulates against *now*. A signed auth entry stays valid until its expiry ledger, and if the contract is upgradeable the code that runs may not be the code that was simulated. [Likely] | Guard's strongest feature (simulation) answers "what would happen now," not "what will happen when it lands." | Any incident where simulated effects ≠ executed effects | New finding `G-AUTH-UPGRADEABLE` (§5.2); recommend short expiry in guidance; `not_checked` always states "behavior at execution time can differ if contract code or state changes." | **Applied** |
| T3 | **Identity fragmentation.** One asset has a classic identity and a Stellar Asset Contract identity; one account can appear as `G…` or muxed `M…`; many contracts share one WASM. [Certain for SAC/muxed existence] | A flag on one identity silently misses the other, so Guard shows nothing for the same asset moved via a contract. | Cross-identity lookup tests fail; any known-flagged asset not warned via its SAC | `entity_link` table + normalization in ingestion/API (§4.1, §7.1); contract tests with muxed and SAC fixtures. | **Applied** |
| T4 | **Dual-source ingestion gaps.** RPC history is about 7 days; a longer outage needs a lake backfill. I have **not verified** that a public Galexie lake exists for you to read; you may need to run your own, which means operating Core-derived infrastructure. [Likely] Single-writer leader-lock bugs can also skip or duplicate ledgers (duplicates are safe by idempotency; skips are not). | Ingest is the foundation; a silent gap corrupts every downstream verdict. | Any non-contiguous `ledger_seq` in processed history; lag above threshold | Gap detector comparing ledger-sequence continuity after every batch; decide Hubble vs. own Galexie in a Phase 0 spike (experiment E4); runbook for failover and re-backfill. | Open |
| T5 | **Entity/snapshot explosion.** Asset creation is cheap, so attackers (or just normal spam) can inflate tables and the snapshot. [Likely] | Naively materializing every ledger object grows storage without bound. | Entity table growth rate; snapshot size growth rate | Lazy entity creation (§4.1); snapshot size cap with eviction by evidence expiry; per-issuer aggregate entries instead of per-asset when many lookalikes share an issuer. | **Applied** (lazy creation); cap/eviction Open |
| T6 | **Non-reproducible scores.** A time-decayed score depends on "now," so replaying a verdict in a dispute can give a different answer. My first draft claimed determinism without an `as_of` input. | Disputes need "what did the engine know, and what did it conclude, at time X." | Replay test: stored verdict ≠ recomputed verdict at stored `as_of` | `score = f(evidence_set, as_of, ruleset_version)`; `as_of` stored; replay test in CI (§4.3). | **Applied** |
| T7 | **Hostile fetches.** Intel fetches attacker-controlled domains/`stellar.toml`. | SSRF into internal networks, resource exhaustion, redirect tricks. [Likely] | Any outbound request to a private range from the fetcher | Isolated fetcher with egress allowlist and caps (§9). | **Applied** |
| T8 | **Decoder coverage gaps.** Fee-bump envelopes, muxed accounts, claimable balances, liquidity-pool operations, path payments, and new credential types: each unhandled case is a silent miss unless it fails loudly. | The Stellar operation set is large and still grows with protocols. | A transaction type in the wild with no fixture | One fixture per operation/credential type; exhaustive switch; unknown → `unanalyzable`; fuzz the decoder. | Open (Phase 0 task) |
| T9 | **Stale or revoked snapshot trust.** Pinned keys can't be revoked for wallets that never update the SDK. | Wallet release cycles are slow. | Share of clients on old SDK versions | Signed keyset manifest with expiry; max snapshot age with visible "data stale" state (§9). | **Applied** (design); Open (implementation) |
| T10 | **Guard habituation through degradation.** If RPC is rate-limited or slow, users see `partial`/`unanalyzable` constantly and learn to ignore it. | Public RPC endpoints are rate limited; integrators choose providers. [Likely] | `partial + unanalyzable` share above ~5% | Static-findings-first rendering (value even without simulation), retry/backoff, cache simulation by tx hash, doc the recommended RPC setup for integrators. | Open |

### Highest-risk assumptions in this architecture (what to test first)

1. A wallet will integrate Guard (PRD P1).
2. Effect analysis works on auth-entry-only signing requests, not just full transactions (experiment E5).
3. A ledger-data source is available at a cost you can afford (T4, experiment E4).
4. Scan indicators carry enough signal to matter (PRD E3).

---

### HQ2 — What edge cases are we missing? (technical)

Confidence tags mark facts about Stellar/Soroban; "verify" means check against primary docs before building. "v1" = needed before a pilot; "Later" = acceptable to defer.

#### Transaction semantics (Guard)

| # | Edge case | Why it breaks us | Response | When |
|---|---|---|---|---|
| EC1 | **Signature scope ≠ transaction source.** Operations can carry their own source account, and a fee-bump has an outer fee source plus an inner transaction. [Certain] | "Balance change for the user" is wrong unless computed per affected account from the signer's perspective: the signer may only pay fees, may be tx source for the sequence number while ops move *another* account's funds, or may be an asset issuer. | Effect engine takes `signer_accounts[]`; computes effects per account; unwraps fee-bump envelopes and analyzes the inner transaction plus the fee-payer's exposure. | v1 |
| EC2 | **Signer-type time bombs.** SetOptions can add signers that are not ordinary keys: hash(x) signers (anyone knowing the preimage can sign), pre-authorized-transaction signers, signed-payload signers. [Certain] | A check for "new public-key signer" misses a hash(x) signer, which has no visible owner. | `G-SIGNER-ADDED` classifies key type; hashX/preAuthTx rank higher; show weight and threshold effect in plain words. | v1 |
| EC3 | **No expiry.** A transaction with no upper time bound stays valid until its sequence number is used. [Certain] | A signed copy can be held and submitted later; Guard simulated "now." | `G-NO-EXPIRY`; recommend short windows; note in `not_checked`. | v1 |
| EC4 | **Worst-case effects.** Path payments (send max / min destination), DEX offers and liquidity-pool deposits authorize *up to* a limit, not one outcome. [Certain] | A single "you will send X" number understates what the signature allows. | Effects carry `delta_min/delta_max`; UI leads with the worst case. | v1 |
| EC5 | **Sponsorship operations.** Begin/End-sponsoring and revoke-sponsorship change who locks reserves. [Certain] | A transaction with no payments can still lock the signer's XLM as sponsor. | `G-SPONSORSHIP`; effect text states the reserve locked. | v1.x |
| EC6 | **Memo-required destinations.** Exchanges and custodians need a memo; omitting it commonly loses funds. A standard (SEP-29) lets an account flag this in its data entries. [Likely, **verify** exact key] | Not an attack, yet probably the most frequent real loss, and the warning is non-accusatory (ideal under the language policy). | `G-MEMO-REQUIRED`: read the destination's flag via RPC and warn when no memo is present. | **v1, high value** |
| EC7 | **Address poisoning.** Attackers send dust from addresses that mimic the first/last characters of an address the victim uses, hoping it gets copied from history. [Likely: documented on other chains; long addresses are often shown truncated] | A reputation list cannot catch fresh addresses. | Wallet passes optional `known_counterparties[]`; `G-DEST-LOOKALIKE` when prefix/suffix match but the address is not in the set. | v1.x |
| EC8 | **Padding and swapped XDR.** Burying one dangerous operation among many benign ones; or analyzing XDR that differs from what is finally signed. | UIs that truncate or sort by operation order hide the finding; analysis of the wrong bytes is worthless. | See "Pipeline rules added by HQ2" (§5.1): analyze signed bytes, show tx hash, severity-ordered findings, never truncate. | v1 |
| EC9 | **Untrusted strings in our own UI.** Memo text, asset codes, `stellar.toml` fields and domains can carry deceptive text, URLs, or bidirectional/control characters. | Phishing through our warning UI; XSS on the lookup page. | Escape, strip control/bidi characters, render untrusted text visibly as such, no linkification. | v1 |
| EC10 | **Unknown network.** Mainnet and testnet are identified by passphrase; futurenet, standalone and forked networks have none of our data. | Naive `no_signals` implies reassurance where we have no data. Absence of data is not safety. | `G-NETWORK-UNKNOWN` → `partial`. | v1 |

#### Soroban

| # | Edge case | Why it breaks us | Response | When |
|---|---|---|---|---|
| EC11 | **Contract-reported effects.** Events and custom-token balances are whatever the contract says. A hostile token can emit transfer events that don't match real state. [Certain by design] | Effects built from events are spoofable. | `assurance`: `ledger` (classic ops, ledger-entry diffs, Stellar Asset Contract balances) vs `contract_reported` (custom tokens, events). UI says "reported by the contract." | v1 |
| EC12 | **Contract accounts, smart wallets, passkeys.** The signer may be a contract account with custom authorization logic. Source-account credentials authorize via the transaction signature; address credentials via separate signed entries. [Certain: both credential types; Likely: passkey wallets] | Assuming the signer is a `G…` account misattributes effects for these users. | Treat the signer as an address (`G…` or `C…`); handle both credential types; unsupported account type → `partial`. | credentials v1; contract accounts Later |
| EC13 | **Bait-and-switch upgrade.** A contract is benign when scanned, then upgraded. Verdicts tied to the old WASM hash become false reassurance. | `no_signals` on a contract goes stale silently. | Track each contract's current WASM; on an upgrade event, re-scan and recompute; every contract verdict records the hash and `as_of` it was computed for. | v1 |
| EC14 | **Spec and metadata are claims.** Custom sections can be absent, wrong or oversized; behavior also depends on instance storage (e.g., who is admin), not just code. | `S-SEP41-DEVIATION` trusts the spec; "upgradeable" matters only if someone can still upgrade. | Treat the spec as a claim; add `S-NO-SPEC`; read instance admin/storage later. | spec v1; storage Later |
| EC15 | **Absurd fees.** A transaction can declare a very large fee or resource fee. | User may pay far more than needed. (Refund rules: [Guessing], verify.) | `G-FEE-HIGH` vs. simulated minimum. | v1.x |

#### Assets, identity, domains

| # | Edge case | Why it breaks us | Response | When |
|---|---|---|---|---|
| EC16 | **Lookalikes differ by medium.** Asset codes are ASCII alphanumerics [Certain], so confusables are 0/O, I/l/1, case, and suffixes ("USDC" vs "USDCx"). Domains can use Unicode/punycode homoglyphs. Several legitimate issuers can also share a code (regional anchors). | One "homoglyph" detector is wrong for both, and flags legitimate multi-issuer assets. | Two detectors (ASCII code-confusables, IDN domain-confusables); reference set keyed `code → {known issuers}` with issuer-relationship data. | v1 |
| EC17 | **Issuer state drifts.** `home_domain` can change or lapse and be re-registered; flags can change; clawback is tracked per trustline as well as per issuer account. [Likely, **verify**] | `consistent` today can be wrong next month. | Re-verify on a schedule and on `home_domain` change; store history; alert on change; evaluate trustline-level flags. | v1 |

#### Intel lifecycle and platform

| # | Edge case | Why it breaks us | Response | When |
|---|---|---|---|---|
| EC18 | **Re-flag loops after dispute.** An overturned verdict is re-created by the same evidence on the next run. | Ping-pong damages credibility and legal posture. | Overturn stores suppressed evidence fingerprints; engine ignores them unless new evidence arrives. Disputers prove control via a `stellar.toml` challenge, not identity documents. | v1 |
| EC19 | **Attacker feedback oracle.** Public per-entity lookups let attackers test whether their scam is detected and iterate. | Free adversarial testing. | Rate limits; no per-detector detail on the public tier. Residual risk accepted: transparency and evasion-resistance conflict. | Later |
| EC20 | **Cross-language key canonicalization.** `CODE:ISSUER`, muxed forms and padding can encode differently across Go, Rust and TypeScript. | Different hashes → silent snapshot misses. | One canonical-encoding spec plus shared test vectors in `schemas/`, run in all three CIs. | v1 |
| EC21 | **Personal data vs. immutable retention.** Reports carry reporter contact data; write-once evidence conflicts with erasure rights under privacy laws (e.g., GDPR). [Likely] | Cannot both retain forever and erase on request. | Evidence store holds only public on-chain/public-web data; reporter PII lives in a separate erasable store; retention policy per data class; counsel review. | v1 |
| EC22 | **Device clock skew.** Snapshot staleness checks use the client clock. | Wrong clock → false "stale" or false "fresh." | Prefer the latest ledger close time from RPC as the reference. | Later |

---

### HQ3 — What is overengineered?

**Verdict:** the target-state design is sound, but **v1 was designed for a product with no users yet**. Eleven components below are cut or simplified for v1. Items marked *Applied* are engineering decisions I made (see the override notice at the top of this file). Items marked *Open* are strategic and need your decision. Some of the cuts are against my own earlier additions.

| # | Overbuilt | Why it's too much for v1 | v1 replacement | Status |
|---|---|---|---|---|
| OE1 | **Numeric score** (`weight × source.trust × decay`) | With ~7 detectors and no labeled data, the weights are invented precision. It is also why HQ1 T6 needed an `as_of` patch. | Rule table: level = f(which detectors fired, evidence classes, analyst confirmation); evidence has an expiry date. Keep `as_of` for expiry and replay. | **Applied** |
| OE2 | **Five verdict statuses** | `proposed` is just a review-queue item; `expired` is derivable from `valid_until < as_of`. | `active` / `revoked` plus a `disputed` flag; separate review queue. | **Applied** |
| OE3 | **Scan as an HTTP service** (API, job table, signed callbacks, cross-service tracing) | Adds a deployable, an auth surface and a failure mode for a component whose efficacy is unproven. | Rust **library + CLI**. Intel runs it as a one-shot sandboxed container job and reads the JSON result. Same repo, same sandbox, no server. | **Applied** |
| OE4 | **Snapshot machinery:** deltas, bloom/cuckoo option, truncated-hash + API confirm step, two active keys, signed keyset manifest | At this size none are needed. With 128-bit truncated hashes and ≤10⁷ entries, collision probability is about 10⁻²⁵, so the confirm step only leaks privacy. [Certain: birthday bound] | Full snapshot of sorted 128-bit hashes, one KMS key plus one offline backup key pinned in the SDK, max-age check. Add deltas and a manifest when measured size or rotation need appears. | **Applied** |
| OE5 | **Redis** | Postgres plus an in-process cache serves v1 volumes; rate limits belong at the gateway. | Remove Redis. | **Applied** |
| OE6 | **Partitioned evidence table** | Lazy entity creation keeps rows few. | Plain table; revisit if it reaches tens of millions of rows. [Guessing] | **Applied** |
| OE7 | **`wording_template` DB table, locales, DB-held approval status** (my addition last round) | Two sources of truth (git and DB) for text that must not drift. | Templates live in git; counsel is a required reviewer on that path; compiled into service and SDK; English only. **Keep** the fail-closed renderer, blocklist lint, attribution block and `public_statement` history. | **Applied** |
| OE8 | **`entity_link` with four relations** | Muxed is an input normalization, not a graph edge; `same_issuer` has no consumer. | Keep only `sac_of`; current WASM hash stored in contract `attrs`. | **Applied** |
| OE9 | **Report, dispute and webhook tables and workflows** | There are no reporters or disputers yet. The *process* is required; the tooling isn't. | Mailbox/form plus a manual log written to `verdict_events`; build tables when real volume arrives. The 72 h acknowledgement target stays. | **Applied** |
| OE10 | **Distributed tracing across services** | Only matters if Scan is a service (OE3). | Structured logs with correlation IDs; basic metrics. | **Applied** |
| OE11 | **Guard effect derivation for every operation; SEP-43-style adapter; UI component; local-only mode** | Maximum surface before one wallet has asked for any of it. | Derive effects for ~7 operations (payment, path payments, create account, change trust, set options, account merge, contract invoke); decode all, mark the rest `unanalyzable` with a generic summary. SDK = core library + one reference adapter; no local-only mode. | **Applied** |
| OE12 | **Three repos in three languages from day one** | Highest coordination cost in the project. | **Kept: your decision.** Note: if Scan is deferred (below), the stack is two languages. | Kept |
| OE13 | **Roadmap fantasies:** dynamic analysis (S-9), fuzzy similarity, browser extension, origin checks, partner imports, SARIF/HTML reports | Phase 2–3 items consume design attention without evidence they matter. | Move to a "parking lot" list; remove from the v1 roadmap. | **Applied** |
| OE14 | **Building Scan at all before E3** | Scout, Certora Sunbeam and Almanax already cover pre-deployment analysis [Certain]; Scan's differentiator is unvalidated. | Recommended: build only the minimal pieces other components need (known-bad hash, upgradeable check, spec presence) inside the library and **defer the rest until E3 shows signal**. | **Open decision** |

**What is not overengineered (keep):** the fail-closed renderer and blocklist lint, immutable evidence and statement history, lazy entity creation, the `as_of` input, sandboxing of WASM parsing (one-shot container, cheap), contract tests between repos, effect-first Guard analysis, a simple signed snapshot, and the append-only `verdict_events` log. Each costs little and protects against mistakes that are expensive or irreversible (legal exposure, security, silent data corruption).
