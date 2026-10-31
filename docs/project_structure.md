<!-- GENERATED: edit sorosentinel-intel/docs/project_structure.md, then run scripts/sync-docs.sh. -->

# project_structure.md — SoroSentinel

| | |
|---|---|
| **Status** | Draft v0.1 (proposal; nothing is scaffolded yet) |
| **Date** | 2026-10-31 |
| **Applies to** | `sorosentinel-intel` (Go), `sorosentinel-scan` (Rust), `sorosentinel-guard` (TypeScript) |
| **Reads with** | `ARCHITECTURE_ESSENTIALS.md` (v1 cut list overrides full architecture), `AGENTS.md` |

Org: **SoroSentinel**. Repos are `sorosentinel-intel`, `sorosentinel-scan`, `sorosentinel-guard`. Package names derive from the org (`@sorosentinel/*` on npm, `sorosentinel-*` crates); Go module paths are not yet decided. Brand/trademark clearance and registry-name availability are unchecked. GitHub is assumed (Actions, CODEOWNERS).

---

## 1. Principles

1. **One owner per artifact.** Schemas, wording templates, canonical key encoding, and the docs each have exactly one home (Intel). Everyone else consumes pinned, read-only copies.
2. **Identical developer interface across repos.** Same `make` targets in all three, so an agent or human never has to guess commands.
3. **Fixtures live next to the code that needs them;** the labeled corpus lives where verdicts are made (Intel).
4. **Match v1 scope.** The tree contains only what the v1 cut list needs. Parking-lot items (extension, dynamic analysis, webhooks, dispute tables) have **no directories yet.**
5. **Structure enforces policy:** CODEOWNERS and CI make the legal/security rules mechanical (§2.5).

## 2. Cross-repo conventions

### 2.1 Where the docs live

| Artifact | Canonical location | Copies |
|---|---|---|
| `PRD.md`, `ARCHITECTURE.md`, `ARCHITECTURE_ESSENTIALS.md`, `project_structure.md` | `sorosentinel-intel/docs/` | Read-only copies in `docs/` of Scan and Guard, stamped `GENERATED: edit in sorosentinel-intel` |
| ADRs, runbooks, public methodology | `sorosentinel-intel/docs/{adr,runbooks,methodology}/` | Copied the same way |
| `AGENTS.md` shared core + per-repo profiles | `sorosentinel-intel/docs/agents/{core.md,profile-intel.md,profile-scan.md,profile-guard.md}` | Each repo's root `AGENTS.md` is **generated** (core + its profile) |
| `CLAUDE.md` | Each repo root (identical: it only imports `AGENTS.md`) | Same file in all three |

**Sync mechanism (v1):** a script `scripts/sync-docs.sh` in Intel copies docs and generates the other repos' `AGENTS.md`, then opens PRs. Run manually or by a scheduled job. Automate further only if drift is observed.

**Alternatives discarded:** a fourth `sorosentinel-docs` repo (you asked for three); git submodules (painful for agents and CI); manual copying (silent drift).

### 2.2 Standard `make` targets (every repo)

| Target | Meaning |
|---|---|
| `make deps` | Install pinned dependencies |
| `make fmt` | Format |
| `make lint` | Lint/type-check (Intel and Guard also run the blocklist/wording lint) |
| `make test` | Unit tests |
| `make test-contract` | Contract tests against the pinned schema version (Scan, Guard) / provider tests (Intel) |
| `make gen` | Code generation (Intel: schemas → packages; Scan/Guard: no-op or fetch pinned schema package) |
| `make verify` | `lint` + `test` + `test-contract` + (repo-specific checks). **The command an agent runs before saying "done."** |
| `make fuzz` | Scan only: run fuzz targets for a bounded time |
| `make gen-alerts` | Intel only: rewrite `deploy/monitoring/` from the alert table in `internal/monitoring` (a test fails if the committed files and the table disagree) |

The Makefile is a thin wrapper over native tooling (`go`, `cargo`, `pnpm`). Native commands stay usable.

### 2.3 Versioning

- **Schemas:** SemVer; additive changes within a major; breaking → new `/v2` (see ARCHITECTURE §3.1).
- **Packages:** `@sorosentinel/schemas`, `@sorosentinel/wording` (npm), `sorosentinel-schemas` (crate), Go package from the Intel module.
- **`ruleset_version`:** a single string stamped into evidence, verdicts, and scan reports. Proposal: `YYYY.MM.N`. It changes whenever detectors, thresholds, or templates change.
- **Pre-release channel:** Intel publishes `-next.N` builds so Guard/Scan can develop against unreleased schemas/templates without waiting for a stable release.
- **Distribution (open question):** private registry vs. git tags. Cargo and Go can consume git tags directly; npm can use git dependencies or a private registry. Decide in Phase 0.

### 2.4 Branching and commits

Trunk-based, short-lived branches, squash merge. Conventional commits (`type(scope): summary`). No force-push to `main`.

### 2.5 CODEOWNERS (mechanical enforcement)

| Path | Required reviewers |
|---|---|
| `wording/**` (Intel) | Counsel/legal reviewer **and** a maintainer |
| `schemas/**` (Intel) | A maintainer from each consuming repo |
| `internal/verdict/**` (Intel) | Two maintainers (two-person rule for verdict logic) |
| `internal/fetcher/**`, `internal/snapshot/**`, `deploy/**` | Security reviewer |
| `sandbox/**` (Scan) | Security reviewer |
| `docs/**` (Intel) | A maintainer; changes to invariants need an ADR |

### 2.6 CI (per repo, `.github/workflows/`)

| Workflow | Runs |
|---|---|
| `ci.yml` | `make verify` on every PR |
| `schemas-publish.yml` (Intel) | Generate and publish schema/wording packages on tag |
| `release.yml` | Tag, build artifacts (Intel: images; Scan: sandbox image; Guard: npm) |
| `docs-sync.yml` (optional, Intel) | Opens sync PRs to Scan/Guard when `docs/` changes |
| Scheduled | Dependency audit, testnet replay (Intel/Guard), protocol-release watcher |

---

## 3. `sorosentinel-intel` (Go)

```
sorosentinel-intel/
├── AGENTS.md                  # generated (core + profile-intel)
├── CLAUDE.md                  # imports AGENTS.md
├── README.md
├── Makefile
├── go.mod / go.sum
├── .github/
│   ├── CODEOWNERS
│   └── workflows/             # ci, schemas-publish, release, docs-sync
│
├── cmd/
│   ├── intel-api/             # REST API server
│   ├── intel-ingest/          # ingestion worker (single writer, leader lock)
│   ├── intel-worker/          # verdict recompute, snapshot publish, domain re-verify, scan-job dispatch
│   ├── intelctl/              # admin CLI: review queue, verdict actions, dispute log (manual process)
│   ├── intel-fuzz-seeds/      # one-shot: harvest contract WASM from RPC into fuzz seed corpora
│   ├── gen-alerts/            # rewrite deploy/monitoring/ from internal/monitoring's alert table
│   └── wordlint/              # template + blocklist lint (also run in CI)
│
├── internal/
│   ├── ingest/
│   │   ├── source/            # rpc/ (live tail), lake/ (Galexie/Hubble backfill)
│   │   ├── checkpoint/        # per-network progress, gap detector
│   │   └── xdrcompat/         # pinned XDR handling; halts on unknown variants
│   ├── entity/                # canonical key encoding, muxed→G normalization, sac_of linking
│   ├── detectors/             # one dir per detector:
│   │   ├── assetlookalike/    #   (ASCII code confusables, code → {known issuers})
│   │   ├── domainconfusable/  #   (IDN/punycode)
│   │   ├── homedomain/        #   (stellar.toml consistency, drift history)
│   │   ├── flags/             #   (issuer + trustline clawback/revocable flags)
│   │   ├── trustlinespam/
│   │   ├── takeover/          #   (signer/threshold takeover pattern)
│   │   └── scanevidence/      #   (turns ScanReport into evidence)
│   ├── evidence/              # evidence model + immutable artifact store refs
│   ├── verdict/               # rule table, engine(as_of), events, replay, dispute-suppression
│   ├── wording/               # renderer + loader (templates compiled in; fail-closed)
│   ├── fetcher/               # isolated outbound fetcher (SSRF guard, caps)
│   ├── scanjob/               # run Scan as one-shot sandboxed job; read ScanReport
│   ├── snapshot/              # build, sign (KMS), publish
│   ├── api/                   # handlers, auth (API keys), rate limiting
│   ├── store/                 # postgres/, objectstore/
│   ├── monitoring/            # alert table: ids, log fields, thresholds; generates deploy/monitoring/
│   └── platform/              # config, logging, kms, clock (injectable; no wall clock in verdict code)
│
├── schemas/                   # THE source of truth for cross-repo contracts
│   ├── openapi/intel.v1.yaml
│   ├── jsonschema/            # Entity, Verdict, Evidence, Finding, AnalysisResult, ScanReport, Snapshot
│   ├── vectors/               # canonical-key and snapshot test vectors (consumed by all 3 repos)
│   ├── generated/             # gitignored build output: go/ ts/ rust/
│   └── README.md              # compatibility rules
│
├── wording/                   # approved public text (git is the only source of truth)
│   ├── templates/en/          # *.yaml (one file per template id/version)
│   ├── attribution/           # standard_v1.yaml
│   ├── blocklist.yaml
│   └── vectors/               # render test vectors (shared with Guard's renderer)
│
├── migrations/                # forward-only SQL (0001_init.sql, ...)
├── corpus/                    # golden labeled set (see §3.1)
├── testdata/                  # ledger ranges, stellar.toml samples, hostile responses
├── deploy/
│   ├── docker/                # Dockerfiles per cmd/
│   ├── monitoring/            # GENERATED log-metrics.json + alert-policies.json (make gen-alerts)
│   └── terraform/             # single-cloud IaC (provider TBD)
├── scripts/                   # sync-docs.sh, local-dev helpers
└── docs/                      # CANONICAL docs (§2.1)
    ├── PRD.md  ARCHITECTURE.md  ARCHITECTURE_ESSENTIALS.md  project_structure.md
    ├── agents/                # core.md + three profiles
    ├── adr/                   # 0001-title.md ...
    ├── runbooks/              # protocol-upgrade.md, snapshot-key-rotation.md, ingest-gap-recovery.md, oncall-alerts.md
    └── methodology/           # PUBLIC page source: what each signal means, how to request a review
```

**Notes**
- `docs/methodology/` is **required before launch**: every public statement links to it (language policy L4). It isn't optional documentation.
- `internal/` is intentional: nothing in Intel is importable by other repos; contracts go through `schemas/`.
- Only `intel-api` takes inbound traffic. `intel-ingest` must run as a single writer per network.

### 3.1 `corpus/` rules

- Format: JSON Lines, one entity per line: `{network, type, key, label, internal_category, source, labeled_by, labeled_at, evidence_refs[]}`.
- Labels use **internal** categories (never public wording) and are for tests/precision tracking only.
- Includes a **benign set** (top assets, legitimate multi-issuer codes, legitimate upgradeable contracts); false-positive control is half the value.
- No personal data. If Intel is ever open-sourced, **keep the corpus private**: labels about named assets are a legal exposure.

---

## 4. `sorosentinel-scan` (Rust)

```
sorosentinel-scan/
├── AGENTS.md  CLAUDE.md  README.md  Makefile
├── Cargo.toml                 # workspace
├── rust-toolchain.toml        # pinned toolchain
├── deny.toml                  # dependency/license policy (cargo-deny)
├── .github/                   # CODEOWNERS, workflows
│
├── crates/
│   ├── scan-core/             # library
│   │   └── src/
│   │       ├── parse/         # wasm parsing with size/section caps
│   │       ├── spec/          # contract spec/meta extraction (treated as untrusted claims)
│   │       ├── imports/       # host-import mapping   (verify mapping source; see ARCHITECTURE F8)
│   │       ├── detectors/     # upgradeable, creates-contracts, cross-call, no-spec, old-sdk, known-bad-hash
│   │       ├── report.rs      # ScanReport (conforms to pinned sorosentinel-schemas)
│   │       └── limits.rs      # module size, section counts, timeouts
│   └── scan-cli/              # binary `sorosentinel-scan <file.wasm>` → JSON on stdout
│
├── fuzz/                      # cargo-fuzz targets, one per parser path
├── fixtures/
│   ├── wasm/benign/           # real-world-style benign modules
│   ├── wasm/synthetic/        # hand-built hostile/malformed modules (no real malware needed)
│   └── expected/              # expected ScanReport JSON per fixture
├── sandbox/
│   ├── Dockerfile             # minimal image, non-root
│   ├── seccomp.json           # syscall allowlist
│   └── run.sh                 # no network, memory/CPU/time limits, read-only FS, tmpfs workspace
└── docs/                      # generated copies from Intel
```

**Notes**
- **No network code in Scan.** Intel acquires the WASM (it already talks to RPC) and passes a file path/stdin. This keeps the sandbox trivial: no network namespace at all.
- Detector output is **indicators, never verdicts**; the CLI always emits `not_checked[]`.
- `known-bad-hash` reads a hash list supplied by Intel at run time (file argument), not baked in.
- Schema types come from the `sorosentinel-schemas` crate published by Intel; **never vendored or hand-edited.**

---

## 5. `sorosentinel-guard` (TypeScript)

```
sorosentinel-guard/
├── AGENTS.md  CLAUDE.md  README.md  Makefile
├── package.json               # pnpm workspace root (pnpm is a proposal, not verified as your preference)
├── pnpm-workspace.yaml
├── tsconfig.base.json         # strict
├── .github/                   # CODEOWNERS, workflows
│
├── packages/
│   ├── core/                  # @sorosentinel/guard-core  (the SDK)
│   │   ├── src/
│   │   │   ├── index.ts       # the package's public surface
│   │   │   ├── analyze.ts     # analyze(xdr, ctx) → AnalysisResult
│   │   │   ├── assert-never.ts# the exhaustive-switch guard for protocol unions
│   │   │   ├── decode/        # envelope, fee-bump, per-operation decoders, soroban auth entries/credentials
│   │   │   ├── effects/       # per-account effects, bounds (min/max), assurance (ledger | contract_reported)
│   │   │   ├── memo/          # SEP-29 memo-required destination lookup
│   │   │   ├── rpc/           # the transport callers, tests and the example inject
│   │   │   ├── rules/         # one file per finding code (G-*), severity ordering
│   │   │   ├── simulate/      # RPC simulateTransaction wrapper, timeouts → partial
│   │   │   ├── intel/         # snapshot fetch/verify (Ed25519), local lookup, API fallback
│   │   │   ├── canonical/     # canonical key encoding (must pass shared vectors)
│   │   │   ├── wording/       # renderer + compiled templates (from @sorosentinel/wording), sanitizers
│   │   │   └── ui/            # reference findings view: plain DOM, writes no prose of its own
│   │   ├── types/             # node-shim.d.ts: the Node built-ins `test/` and `scripts/` may use; `src/` must not
│   │   ├── scripts/           # gen-fixtures, replay, export-rpc-txs, demo-findings, bench
│   │   └── test/              # unit tests, plus `test/contract/` = the pinned shared vectors
│   └── adapter-reference/     # @sorosentinel/guard-adapter-reference: the reference SEP-43 wallet adapter
│
├── intel-schemas/             # Intel's pinned schemas, wording vectors, blocklist + SHA256SUMS
├── fixtures/
│   ├── tx/benign/             # *.json: {xdr, network, signer, expected}
│   ├── tx/hostile/            # padding, hashX signer, no time bounds, memo-required, fee-bump, muxed, unknown network
│   ├── auth_entry/benign/     # Soroban authorization entries: each address kind an entry can name, each credential arm, nested invocations
│   ├── auth_entry/hostile/    # truncated XDR, malformed base64, oversized, empty passphrase, a pre-filled signature
│   └── snapshots/             # signed test snapshots (test keys only)
├── examples/                  # analyze-transaction/ (the reference integrator) and wallet-adapter/
├── scripts/                   # repo scripts
├── media/                     # the film linked from README.md, and its poster frame
└── docs/                      # generated copies from Intel
```

**Notes**
- **Not a server.** No deployable in v1; the artifact is an npm package.
- One fixture per operation/credential type, enforced by a test that enumerates the XDR enum and fails if a case has no fixture. The same guarantee holds for Soroban authorization entries: `test/auth-entry.test.ts` asserts coverage of every credential arm and every address kind an entry can name.
- The renderer here is a **second implementation** of Intel's renderer (needed offline). Both must pass `wording/vectors/`.
- `ui/` writes no prose: sentences arrive only through the injected renderer hook, and a missing or failed render degrades to the finding's structured facts (AGENTS.md §5). It takes `Document` as an option and uses `createTextNode`, never `innerHTML`, so it needs no DOM dependency and is testable without a browser. Approved display rules live there, not in each integrator's copy.
- `adapter-reference/` is the SEP-43 signing surface only (`signTransaction`, `signAuthEntry`), typed against `stellar/stellar-protocol@62a67297ea14 ecosystem/sep-0043.md` v1.2.1 rather than any wallet's typings. That spec contradicts itself on `signAuthEntry` — the interface types an `authEntry`/`signedAuthEntry` string pair while the prose calls the parameter the entry's *preimage* and links `HashIdPreimageSorobanAuthorization` — and Freighter (`stellar/freighter@b237323ccf55`) implements the preimage reading: it returns a bare 64-byte signature. `src/sep43.ts` records both readings with those pins. It analyzes before asking the wallet for anything, checks that what came back is the bytes it analyzed, and reports three distinct results rather than one: a matching entry is `signed`, a different entry is `signed_other_bytes`, and bytes that are not an entry at all are `signed_unverifiable` with the shape observed. All three keep status `partial` when the analysis was `partial`; nothing that failed to match is ever presented as a clean result, and a bare signature is never called a mismatch it is not (§3.8). It returns reason **codes** instead of sentences so the integrator owns the wording, holds no key and submits nothing (AGENTS.md §3.4, §5).
- Test keys used for fixtures are clearly labeled and never valid for production.

---

## 6. Shared artifact flows

| Artifact | Source | Flows to | Mechanism | Guard against drift |
|---|---|---|---|---|
| JSON Schema / OpenAPI | `intel/schemas/` | Scan (crate), Guard (npm), Intel (Go) | `make gen`; publish on tag | Consumer contract tests pinned to a version |
| Canonical key encoding | `intel/schemas/vectors/` | All three | Test vectors | All three CIs run the vectors |
| Wording templates | `intel/wording/templates/` | Intel renderer (compiled in), Guard (`@sorosentinel/wording`) | Publish on tag | `wordlint` in CI; shared render vectors |
| Docs + agent instructions | `intel/docs/` | Scan, Guard | `scripts/sync-docs.sh` | Stamped generated headers; periodic sync |
| Snapshot format | Intel `internal/snapshot` + `schemas/` | Guard | Signed file | Snapshot vectors + signature tests |
| Hash list for known-bad WASM | Intel DB | Scan (run-time file arg) | Passed per job | n/a |

**Ordering for a cross-repo change (example: new Guard finding with new wording)**
1. Intel PR: template(s) + vectors → counsel review → merge → publish `-next.N`.
2. Guard PR: rule + fixtures, depending on `@sorosentinel/wording@-next` → merge after step 1 is stable-published.
3. Release Intel stable, then bump Guard's pin.

This is slower than a monorepo; it is the cost of three repos. Pre-release builds keep development unblocked.

---

## 7. Where does X go? (lookup for agents)

| Task | Where (and what else you must add) |
|---|---|
| New Intel detector | `intel/internal/detectors/<name>/` + template(s) in `intel/wording/templates/` + cases in `intel/corpus/` + unit test + ruleset_version bump |
| New public wording | `intel/wording/templates/en/` + vectors + `wordlint` pass; **separate PR; counsel review** |
| New Guard finding code | `guard/packages/core/src/rules/` + template in Intel + fixture(s) under `guard/fixtures/tx/` |
| New operation/credential decoder | `guard/packages/core/src/decode/` + a fixture (`fixtures/tx/` for envelopes, `fixtures/auth_entry/` for authorization entries) + (if effects) `effects/` |
| New or changed adapter behaviour (which bytes it analyzes, when it refuses to sign) | `guard/packages/adapter-reference/src/` + its test in `packages/adapter-reference/test/` + re-run `guard/examples/wallet-adapter/sign.mts` with and without `--approve` (and with `--tamper`, and on `--path auth_entry` with `--signature`) so the declined, byte-mismatch and bare-signature paths still show the findings |
| New or changed Guard display rule (order, truncation, wording fallback) | `guard/packages/core/src/ui/` + a structure test in `packages/core/test/ui-findings.test.ts` + re-open the generated page (`packages/core/scripts/demo-findings.ts`) in a browser to re-check focus order and the accessibility tree |
| New Scan indicator | `scan/crates/scan-core/src/detectors/` + fixture + expected JSON; indicator enum change goes through `intel/schemas/` first |
| New schema field/endpoint | `intel/schemas/` (additive) → `make gen` → publish → consumers bump |
| DB change | `intel/migrations/NNNN_*.sql` (forward-only) + migration test |
| New decision or changed invariant | `intel/docs/adr/NNNN-title.md` + update `ARCHITECTURE*.md`; sync |
| Protocol upgrade work | Follow `intel/docs/runbooks/protocol-upgrade.md`; touches XDR pins in all three repos |
| Infra change | `intel/deploy/` (security reviewer) |
| Public methodology change | `intel/docs/methodology/` (counsel review) |
| Anything on the v1 "do NOT build" list | Stop and ask |

---

## 8. Phase 0 scaffold order

1. Decide: repo/module names, package registry approach, cloud provider (open questions §10).
2. Create three repos with `Makefile` stubs, CI running `make verify` (can be a no-op), CODEOWNERS.
3. Intel: `schemas/` skeleton + `vectors/` + `make gen`; publish first `-next` packages.
4. Intel: `wording/` skeleton, `wordlint`, blocklist, one real template; renderer with vectors.
5. Guard: decoder + one fixture per operation type for the ~7 v1 operations; replay harness (experiment E2).
6. Intel: `corpus/` skeleton with labeling rules; start collecting (experiment E3).
7. Intel: ingest spike for cost (experiment E4).
8. `scripts/sync-docs.sh`; generate each repo's `AGENTS.md`; fill the TODO commands in the profiles with the real `make` targets.
9. Scan: library skeleton + sandbox image + fuzz targets (minimal, per HQ3 open decision).
10. Draft `docs/methodology/` and engage counsel on the first template set.

## 9. Weak points of this structure

1. **Intel becomes a hub.** Docs and agent instructions are edited in one repo; people working in Scan/Guard can't change them locally. Mitigation: pre-release channel, small sync PRs, clear ownership.
2. **Two renderers (Go and TypeScript).** Drift risk. Mitigation: shared `wording/vectors/`; if drift appears, consider moving the renderer to a shared compiled core (Rust→WASM) later.
3. **Cross-repo changes are multi-step** (§6). Accepted cost of three repos.
4. **Corpus placement.** Keeping labeled data in Intel couples labeling to the code repo and creates legal exposure if that repo is ever public. A separate private repo is cleaner but violates "three repos."
5. **Generated packages need a distribution decision** (registry vs. git tags) before the first cross-repo build.
6. **`docs-sync` automation** may be unnecessary if the team stays small; the manual script is the v1 default.

## 10. Open questions

1. Brand/trademark clearance for "SoroSentinel" (it evokes Soroban); availability of the GitHub org, npm scope `@sorosentinel`, and crate names; Go module path.
2. Package distribution: private registries or git-tag dependencies?
3. GitHub (assumed) vs. another host (changes CODEOWNERS/Actions details).
4. Will Intel (or any repo) ever be open source? (decides corpus and wording visibility)
5. pnpm vs. npm/yarn for Guard (proposal only).
6. Who are the counsel/security reviewers named in CODEOWNERS?
