<!-- GENERATED: edit sorosentinel-intel/docs/PRD.md, then run scripts/sync-docs.sh. -->

# PRD — SoroSentinel: Security Layer for the Stellar Ecosystem

| | |
|---|---|
| **Status** | Draft v0.1 |
| **Date** | 2026-10-26 |
| **Org structure** | One org (**SoroSentinel**), three repos: `sorosentinel-intel`, `sorosentinel-guard`, `sorosentinel-scan` |
| **Product name** | SoroSentinel. Brand/trademark clearance pending: the name evokes Soroban, so check Stellar/SDF brand guidelines before public use. |

> Note on "malware": Stellar's classic transaction layer has no arbitrary code, so "anti-malware" in the endpoint-antivirus sense mostly does not apply. The real threats are (1) malicious or vulnerable Soroban contracts, (2) deceptive transactions and signing requests, (3) scam assets, accounts and domains. This PRD uses "threat" instead of "malware" for that reason.

---

## 1. Summary

Three products that share one threat-intelligence backbone:

| Product | Repo | One-line description | Primary user |
|---|---|---|---|
| **Intel** | `sorosentinel-intel` | Reputation + evidence database for accounts, assets, contracts, WASM hashes and domains, exposed via API and signed snapshots | Exchanges, anchors, wallets, analysts |
| **Guard** | `sorosentinel-guard` | Pre-signing transaction analysis: decode, simulate, explain, warn | Wallet and dApp developers (SDK), end users (indirectly) |
| **Scan** | `sorosentinel-scan` | Static analysis of deployed Soroban WASM, continuously triaging new deployments and on-demand scans | Soroban developers, auditors, Intel itself |

**Dependency direction:** Scan → (evidence) → Intel → (verdicts, snapshots) → Guard. Intel is the foundation; it ships first.

## 2. Problem

1. **Users sign things they cannot read.** Signing prompts show raw or poorly summarized XDR. Account-takeover operations (e.g., changing signers or thresholds) and malicious trustlines look routine.
2. **Impersonation is cheap.** Anyone can issue an asset with a familiar code (e.g., a lookalike of a well-known stablecoin) from a different issuer. Distinguishing the real one requires checking issuer + home-domain data.
3. **Soroban adds code-level risk.** New contracts can be upgradeable, admin-controlled, or hostile. Few users or integrators can assess deployed bytecode.
4. **Defenders lack a shared source of truth.** Each wallet/exchange maintains its own ad-hoc lists, with no evidence trail or dispute process.

## 3. Users & personas

| Persona | Needs | Which product |
|---|---|---|
| **P1 Wallet/dApp developer** | Drop-in signing protection without building an analysis engine | Guard (+ Intel) |
| **P2 Exchange / anchor risk analyst** | Query "is this asset/account/contract flagged, and why?" with evidence | Intel |
| **P3 Soroban developer / auditor** | Fast triage of a WASM or contract ID, CI-friendly output | Scan |
| **P4 End user** | Understandable warning before signing; a lookup page | Guard UI / Intel lookup |
| **P5 Security researcher / community reporter** | Submit reports, see outcomes, appeal wrong verdicts | Intel |

**Primary buyer/adopter hypothesis:** P1 and P2 (B2B / B2B2C). End users will not install a security tool on their own at scale. *(Hypothesis, not validated.)*

## 4. Goals and non-goals

### Goals
- G1. Prevent a user from signing a harmful transaction without a clear, specific warning.
- G2. Provide evidence-backed reputation for Stellar entities with an auditable history.
- G3. Triage every newly deployed Soroban contract/WASM automatically and surface risk indicators.
- G4. Make integration trivial (SDK + REST API) for wallets and dApps.

### Non-goals (v1)
- NG1. Endpoint antivirus or OS-level malware scanning.
- NG2. Replacing manual audits or formal verification. Scan produces risk indicators, never a "safe" certification.
- NG3. Custody, key management, or anything that touches private keys. Guard must never see secret keys.
- NG4. On-chain enforcement or blocking (not possible; the product advises, it does not control the network).
- NG5. Cross-chain coverage.
- NG6. ML-based detection in v1 (rules + evidence first; ML only once a labeled corpus exists).

## 5. Verdict model (shared across products)

| Level | Meaning | Who may set it |
|---|---|---|
| `benign` | Consistent with the entity's own published data (e.g., issuer/home-domain match), or confirmed legitimate by an analyst. **A published-data match is not proof of trustworthiness**: an attacker can control a domain and its `stellar.toml`. | Curated/human, or automated consistency check |
| `unknown` | No evidence either way (default) | System |
| `suspicious` | Risk indicators present, not conclusive | Automated rules allowed |
| `malicious` | Strong evidence of harm | **Human-confirmed, or ≥2 independent evidence classes** |

Every verdict carries: category, confidence, evidence list, source(s), validity window, and status (`active` / `disputed` / `revoked`).
**Product principle:** the system never outputs "safe." The best Guard/Scan result is "no issues found," plus a statement of what was not checked.

### 5.1 Public language policy (legal-risk control)

**Goal:** no public-facing statement (API, Guard UI, lookup page, snapshot metadata) may accuse an entity of intent or wrongdoing. Public text states **verifiable observations**, with time, source and method. Wording reduces legal risk; it does not remove it, and counsel must approve the template set (not legal advice).

**Rules**

| # | Rule |
|---|---|
| L1 | **Facts, not verdicts.** Say what was observed ("the issuer's `stellar.toml` does not list this asset, checked 2026-10-26 14:02 UTC"), never what the entity *is* ("scam", "fake"). |
| L2 | **Describe effects, not character.** Guard warns about what the transaction *does* ("adds a signer who could approve transactions from your account"), not who is behind it. |
| L3 | **Never assert intent, identity or ownership.** No "designed to steal", no real-world names, no "owned by". Only on-chain behavior and published data. |
| L4 | **Mandatory attribution block on every statement:** observation time (`as_of`), method/source, "indicator, not a determination of intent or wrongdoing", link to methodology, link to request a review. |
| L5 | **Controlled vocabulary.** Public text comes only from a versioned, counsel-approved template registry. Analysts' free-text notes are internal and never serialized publicly. |
| L6 | **Blocklisted terms** in public text: scam, scammer, fraud/fraudulent, fake, stolen, theft/thief, hack/hacker, criminal, illegal, malicious, rug pull, Ponzi, "designed to", "tries to". Enforced by CI lint and a runtime check. |
| L7 | **Public signal names are neutral:** `consistent`, `no_signals`, `caution`, `high_caution` (internal levels `benign/unknown/suspicious/malicious` are never shown). |
| L8 | **Corrections are fast and visible:** review acknowledgement target (proposed: 72 h), revocation propagates via the next snapshot, and the statement history is kept. |
| L9 | **Prove it later:** store immutable evidence (fetched `stellar.toml` hash and content, ledger/tx references, scan input hash) so every published fact can be demonstrated as of its timestamp. |

**Mapping (internal → public)**

| Internal level | Public `signal_level` | Meaning shown to users |
|---|---|---|
| `benign` | `consistent` | "Matches information published by the issuer as of {date}. This does not verify identity or trustworthiness." |
| `unknown` | `no_signals` | "No risk signals observed as of {date}. This is not an assurance of safety." |
| `suspicious` | `caution` | "Observed signals worth checking: {facts}." |
| `malicious` | `high_caution` | "Multiple independent signals observed: {facts}. Reviewed by an analyst on {date}." |

**Example rewrites**

| Instead of | Public text |
|---|---|
| "Scam asset impersonating USDC" | "This asset uses the same code as {Known asset} but a different issuer account. The issuer of {Known asset} is {G…}. Observed {date}." |
| "Malicious contract" | "This contract's code can be replaced by its admin after deployment (upgrade capability present). Analyzed {date}, ruleset {v}." |
| "Phishing domain" | "This domain's name is similar to {known domain}. It is not the domain published by {issuer} in its `stellar.toml`. Checked {date}." |
| "Account takeover attempt" (Guard) | "This transaction would add a new signer and change signing thresholds. The new signer could approve transactions from your account." |

**Known tradeoff:** neutral wording is weaker than blunt wording, so some users will ignore it. Guard's effect-based text is the mitigation; blunt language is not an option.

**Questions for counsel (answers may change this policy):** is `high_caution` itself acceptable in your jurisdiction(s); required disclaimers/ToS for API consumers who re-display text; liability posture for integrators who alter wording; whether media-liability / E&O insurance is advisable.

## 6. Functional requirements

Priority: **P0** = required for v1 launch, **P1** = v1.x, **P2** = later.

### 6.1 Intel (`sorosentinel-intel`)

| ID | Requirement | Pri |
|---|---|---|
| I-1 | Ingest Stellar ledger data (live tail + historical backfill) for classic ops and Soroban events/deployments | P0 |
| I-2 | Maintain entities: account, asset, contract, wasm_hash, domain | P0 |
| I-3 | Heuristic detectors: lookalike asset codes, issuer/home-domain mismatch, clawback/revocable-flag issuers, trustline spam patterns, suspicious signer/threshold changes | P0 |
| I-4 | Verdict engine with evidence: rule table over detectors, evidence classes and analyst confirmation, evidence expiry, `active`/`revoked` status plus a `disputed` flag (v1 cut list; trust weights and decay are deferred) | P0 |
| I-5 | Read API: `GET /v1/entities/{type}/{id}` returning verdict + evidence summary | P0 |
| I-6 | Signed snapshot (compact list of `suspicious`/`malicious` entities) published on a schedule for offline/local checks | P0 |
| I-7 | Ingest Scan results as evidence | P0 |
| I-8 | Submission API + review queue for community reports | P1 |
| I-9 | Dispute/appeal workflow with SLA and audit trail | P1 |
| I-10 | Webhook/feed subscriptions for new malicious verdicts | P1 |
| I-11 | Public lookup web page | P2 |
| I-12 | Partner data import (third-party lists) with per-source trust weights | P2 |
| I-13 | Public language layer (§5.1): template registry, renderer as the only path to public text, attribution block, blocklist lint, immutable evidence retention | **P0** |

### 6.2 Guard (`sorosentinel-guard`)

| ID | Requirement | Pri |
|---|---|---|
| G-1 | Decode transaction envelopes and Soroban authorization entries from base64 XDR | P0 |
| G-2 | Classify operations; flag account-control changes (signer/threshold/master-weight), account merge, trustline additions, clawback/flag changes | P0 |
| G-3 | For Soroban invocations: simulate via RPC, extract auth tree, footprint, and token movements | P0 |
| G-4 | Compute net asset effects for the signing account (balance deltas, trustline changes, approvals) | P0 |
| G-5 | Enrich with Intel (local snapshot first, API fallback) and produce findings with codes, severity, human-readable text | P0 |
| G-6 | Flag over-broad Soroban authorizations (deep sub-invocation trees, long expiry) | P0 |
| G-7 | **Fail-safe behavior:** if analysis fails or times out, show "could not analyze," never a clean result | P0 |
| G-8 | TypeScript SDK; integrates as a middleware around wallet `signTransaction` / auth-entry signing paths | P0 |
| G-9 | Origin/domain check: dApp origin vs. known-malicious or lookalike domains | P1 |
| G-10 | Browser extension (standalone) | P2 |
| G-11 | Local-only analysis mode (no network calls except RPC for simulation) | P1 |
| G-12 | All user-visible text comes from the template registry (§5.1); warnings describe the transaction's effect, not the character of an entity; SDK UI component ships approved wording | **P0** |

### 6.3 Scan (`sorosentinel-scan`)

| ID | Requirement | Pri |
|---|---|---|
| S-1 | Fetch deployed WASM by contract ID or hash; accept uploaded WASM | P0 |
| S-2 | Parse WASM safely; extract exports, imports, embedded contract spec/meta, size, SDK/protocol versions | P0 |
| S-3 | Feature-based detectors: upgradeability, contract-creation capability, cross-contract call surface, token-interface (SEP-41) conformance deviations, known-bad hashes, outdated SDK | P0 |
| S-4 | Report with indicators, evidence, and "not checked" statement; JSON + SARIF-compatible output | P0 |
| S-5 | Automatic triage of every new WASM/contract seen by Intel | P0 |
| S-6 | Isolation: analysis of untrusted WASM runs in a sandbox (no network, CPU/memory/time limits) | P0 |
| S-7 | CLI for developers/CI | P1 |
| S-8 | Function-level similarity against known malicious WASM (fuzzy match) | P1 |
| S-9 | Dynamic analysis: fuzzed invocations in a simulated host environment | P2 |
| S-10 | Source-level (Rust) analysis | **Out of scope**, since existing tools cover it (see §10) |

## 7. Non-functional requirements (proposed targets, not yet measured)

| Area | Target |
|---|---|
| Guard latency | p95 < 800 ms end-to-end (including RPC simulation); local-snapshot path < 100 ms |
| Intel API | p95 < 150 ms read; 99.9% availability |
| Freshness | New malicious verdict reaches snapshot ≤ 5 min; new deployment scanned ≤ 10 min |
| Precision | `malicious` verdict precision ≥ 98% on the labeled corpus; false-warning rate on benign transactions < 1% |
| Privacy | Guard must not send the user's full transaction or account to third parties by default; snapshot-first design |
| Safety of scanner | No analyzed WASM may execute outside the sandbox |
| Auditability | Every verdict change is logged with actor, evidence, timestamp |

## 8. Success metrics

- Number of integrated wallets/dApps (Guard SDK) and monthly analyzed signings.
- Warnings shown vs. warnings overridden vs. confirmed-true (via feedback).
- Intel: verdict count by level; dispute rate; dispute-overturn rate (**the key quality metric**).
- Scan: % of new deployments triaged within target; indicator precision per detector.
- Coverage: % of top-N assets by volume with a non-`unknown` verdict.

## 9. Phasing (inside "all three")

| Phase | Scope | Exit criterion |
|---|---|---|
| **0 — Foundations** | Shared schema package, ingestion pipeline, seed data, labeled golden corpus | Corpus of ≥ N labeled entities exists; ingestion keeps up with live ledgers |
| **1 — Core loop** | Intel P0, Guard P0 (SDK), Scan P0 | One wallet integration in test; end-to-end flow: scam asset flagged → Guard warns |
| **2 — Community & scale** | Reports, disputes, feeds, CLI, fuzzy similarity | Dispute SLA met; second integrator |
| **3 — Expansion** | Extension, dynamic analysis, partner imports | Based on Phase 1–2 data |

Timeline estimates are intentionally omitted: they depend on team size, which is unknown.

Phase 2 and 3 scope was approved on 2026-10-29 (ADR 0007). It starts after the Phase 1 exit criterion is met.

## 10. Competitive / landscape notes

- Soroban security tooling already exists: Scout (CoinFabrik, static analysis on Rust source), Certora Sunbeam (formal verification on Wasm), Almanax (LLM-based). Stellar also funds audits through the Soroban Security Audit Bank. [Certain]
- **Implication:** competing on "audit tooling for developers" is a losing position. Scan's differentiator is **continuous triage of deployed bytecode at ledger scale feeding a reputation system**, which is a different job from pre-deployment auditing. This is a hypothesis to validate with early users.
- Guard overlaps in concept with signing-simulation features common in other ecosystems, but Stellar-specific operations (SetOptions, trustlines, clawback, Soroban auth entries) need Stellar-specific logic.

## 11. Risks (weakest parts, in order)

1. **Distribution of Guard.** A standalone extension likely cannot reliably intercept signing inside other wallets' UIs. Real protection requires wallet integration, which means business development, not just code. [Guessing, needs validation with wallet teams]
2. **False positives = reputational/legal harm.** Calling a legitimate project "malicious" is costly. Mitigation: evidence requirements, human confirmation for `malicious`, dispute process, controlled public wording that states verifiable observations, not accusations (§5.1). Wording lowers but does not eliminate legal risk; counsel review of the template set is required before launch.
3. **Scan efficacy is unproven.** Binary-level indicators for Soroban are coarse; no labeled corpus of malicious Soroban contracts is known to exist. Mitigation: build the corpus first; ship indicators, not verdicts.
4. **Cold-start trust.** A new reputation source has no credibility with exchanges. Mitigation: transparent evidence, open methodology, start with objectively verifiable checks (issuer/home-domain mismatch, flag analysis).
5. **Three languages, three repos, two or three engineers?** Coordination cost is real. Mitigation: shared schema package and strict API contracts (see ARCHITECTURE.md).
6. **Protocol churn.** Protocol 30 ("Bell") is scheduled: mainnet vote 2026-11-23. Raw-ledger consumers must update XDR definitions beforehand. [Certain, per SDF guide dated 2026-10-20]
7. **Scanner is itself an attack surface.** Parsing hostile WASM and XDR at scale invites DoS and parser exploits.

## 12. Open questions (answers would change the design)

1. Team size and skills (Go / Rust / TypeScript)? Drives language split and phasing.
2. Business model: free public good, SaaS API tiers, or grant-funded (e.g., Stellar Community Fund)? Drives API tiering, SLA, and how much dispute-handling you can staff.
3. Who has final authority to label an entity `malicious`? A named human/team is required operationally.
4. Is there an existing wallet partner for Guard's first integration?
5. Is there existing labeled data (known scams, known benign) to seed the corpus?
6. Jurisdiction/legal posture for publishing "malicious" labels.
7. Mainnet only, or mainnet + testnet?

## 13. Out of scope for this document

Pricing, brand, detailed UI design, hiring plan, compliance (AML/sanctions screening is a different product with different legal obligations).

---

## 14. Hard Questions

Numbered so more can be appended. Technical counterparts live in `ARCHITECTURE.md` §17. Likelihood/impact rankings are my judgment, not measured data. [Guessing]

### HQ1 — What would break?

Method: pre-mortem. Assume it is 12 months from now and the project failed. Ranked by likelihood × impact. "Status" says whether the docs already changed because of the finding.

#### Product / business breaks

| # | What breaks | Why I expect it | Tripwire (proposed) | Response | Status |
|---|---|---|---|---|---|
| P1 | **No wallet integrates Guard.** Guard's value is zero unless it sits in the signing path. | Wallets own their roadmaps and support burden; integrating a third-party warning engine adds liability for them; they may build their own simulation. [Likely] | No committed pilot partner within 6 weeks of starting | Get a pilot partner **before** building beyond the decoder + effect analysis. Fallback channel needing zero integration: a web "paste XDR, see what it does" checker. | Open |
| P2 | **Intel verdicts aren't trusted or used.** Exchanges and anchors already have lists and vendors; a new source has no track record. | Trust is earned by accuracy over time, and you start with none. [Likely] | No external consumer querying the API N weeks after launch; dispute-overturn rate above ~10% | Launch with objectively checkable signals only (issuer/home-domain, flags, lookalike). Publish methodology and corpus precision. Don't sell reputation; sell evidence. | Open |
| P3 | **Intel is late for new threats.** `high_caution` needs human review, but fresh scam assets are mostly dangerous in their first hours-to-days. [Likely] | Review latency exceeds the attack window, so the reputation layer misses exactly the cases that hurt most. | Median time-to-flag longer than the typical active life of a flagged asset (measure it) | Fast automatic `caution` path; make Guard's effect-based warnings independent of Intel so they work on day zero. Decide whether to reorder phases Guard-first (see decision below). | **Applied** (ADR 0002) |
| P4 | **Alert fatigue.** Legit multisig users change signers; legit DeFi contracts are upgradeable; shared WASM templates are used by many legitimate contracts. | If benign activity triggers warnings, users and wallets turn the product off. | Warning override rate above ~90% for a finding code; `caution` on top-volume legitimate assets | Per-code severity tuning; user-trusted-signer allowlist; informational-only status for common benign indicators. | **Applied** (Scan indicators capped, see ARCH §4.2) |
| P5 | **Review/dispute desk is unstaffed.** Human confirmation and a 72 h dispute SLA are people, not code. | Small teams build the engine and forget the operations. | Queue age above SLA for 2 consecutive weeks | Name an owner before launch. If none, ship `caution` + effect warnings only and defer `high_caution`. | Open |
| P6 | **`verified` overstated trust.** An attacker can own a domain and publish a matching `stellar.toml`, so "verified" would label a scam asset reassuringly. This was a defect in my first draft. | Consistency with self-published data proves nothing about honesty. | n/a | Renamed to `consistent`; text states it does not verify identity or trustworthiness. | **Applied** |
| P7 | **Unfunded running costs.** Lake/BigQuery reads, RPC, KMS, Postgres, plus counsel and insurance. | Costs are recurring; no revenue model is defined. | Monthly cost projection exceeds funded runway | Build a cost model in Phase 0 from a real one-week ingest run. | Open |
| P8 | **Counsel is the launch bottleneck.** No approved templates means no public prose (fail-closed by design). | Legal review is slow and each new detector needs a template. | Template approval lead time exceeds detector build time | Engage counsel in Phase 0; ship a small, fixed template set first. | Open |

**Decision needed (P3 + P1):** my pick is to make the Phase 1 vertical slice **Guard's effect analysis plus a minimal Intel (lookalike + home-domain checks only)** instead of full Intel first. Reasons: effect analysis is the only part that works on day zero without reputation data; it is also what a wallet pilot partner needs to see. Alternatives discarded: *Intel-first* (value arrives late and needs trust you don't have yet); *Scan-first* (crowded space, unproven efficacy, no user-facing value alone). This is **not yet applied** to §9 until you confirm. **Accepted 2026-10-27 (ADR 0002).**

#### First experiments (cheapest tests of the riskiest assumptions)

| # | Experiment | Learns | Kill / pivot signal |
|---|---|---|---|
| E1 | Talk to ≥3 wallet teams; seek one pilot commitment | P1 | Zero interest → pivot Guard to web checker |
| E2 | Replay ≥10k historical mainnet transactions through the decoder | Unanalyzable rate, benign-warning rate (P4) | Unanalyzable > ~2% or benign warnings > ~1% |
| E3 | Build the labeled corpus; measure each detector's precision before enabling public output | Whether detectors are usable at all | Detector precision below target → keep internal |
| E4 | Run one week of ledgers through the chosen ingest path; extrapolate cost | P7, ARCH T4 | Projected cost above runway |
| E5 | Spike: can an auth entry be analyzed without the full transaction? | Guard scope for dApp-signing flows | Not feasible → state it in `not_checked` |

### HQ2 — What edge cases are we missing? (product)

The 22 technical edge cases are in `ARCHITECTURE.md` §17 HQ2. These are the product-level ones.

| # | Edge case | Impact | Response |
|---|---|---|---|
| PE1 | **The most valuable warning isn't about attackers.** Missing-memo sends to exchanges are likely the most frequent real loss, and the warning needs no accusation. [Likely, verify frequency] | Our scoped value proposition ("anti-malware") may undersell what users need | Add **G-13: memo-required warning** to the P0 list (below); lead pilot conversations with it |
| PE2 | **Legitimate lookalikes.** Several legitimate issuers can share an asset code (regional anchors, wrapped versions). | `caution` on legitimate assets, disputes, lost credibility | Reference set keyed `code → known issuers`; review top-volume assets by hand before enabling the detector |
| PE3 | **Power users and organizations.** Multisig managers change signers routinely; issuers sign clawback/flag operations; market makers sign many offers. | Alert fatigue (see P4) → disabled by integrators | Perspective-aware analysis (signer vs. issuer); user-trusted-signer allowlists; per-code tuning |
| PE4 | **Testnet and developers.** Developers sign odd transactions on testnet and unknown networks, where we have no data. | Noise or false reassurance | Testnet treated as a separate, quieter profile; unknown network → `partial`, never `no_signals` |
| PE5 | **Consumers using Intel as the sole basis for adverse action** (auto-blocking deposits, freezing accounts) on `caution`/`high_caution`. | Harm to innocent holders; shifts legal exposure back to us | API terms: signals are not a determination and must not be the sole basis for adverse action; counsel to confirm wording |
| PE6 | **Non-English users.** A global wallet base needs localized warnings, and each language needs counsel-approved templates. | Cost and delay per language | English only at v1; add languages one at a time with approval; record as cost line in P7 |
| PE7 | **Disputers who are the actual bad actor.** | A dispute process that rewards persistence helps attackers | Facts-based review; control-of-domain challenge (`stellar.toml`) rather than identity documents; suppressed-evidence rule so overturned facts don't re-flag |

**New requirement (from PE1):** `G-13` **memo-required warning**: when the destination account declares it requires a memo and none is present, Guard warns. Priority **P0**.

### HQ3 — What is overengineered? (product)

The 11 technical cuts are in `ARCHITECTURE.md` §17 HQ3. Product-level:

| # | Overbuilt | Why | v1 replacement | Status |
|---|---|---|---|---|
| PO1 | **Five personas** | P4 (end user) and P5 (reporter) have no distribution or workflow in v1 | v1 targets **P1 (wallet/dApp developer)** and **P2 (exchange/anchor analyst)**; P3 only via library/CLI | **Applied** |
| PO2 | **99.9% availability and p95 < 150 ms for Intel** | No customer, no SLA, one team | Best effort (target ~99.5%) until first integrated customer; keep Guard's local-snapshot latency goal (it protects user experience) | **Applied** |
| PO3 | **Community reports, partner imports, webhooks, public lookup page** (I-8 to I-12) | Already P1/P2; no reporters or partners exist | Parking lot; mailbox for reports | **Applied** |
| PO4 | **Three full products at once** | Triples surface before any product has users | Per HQ1: Phase 1 slice = Guard effect analysis + minimal Intel (lookalike, home-domain) | **Applied** (ADR 0002) |
| PO5 | **Scan as a product** | See ARCH OE14 | Library/CLI feeding Intel; defer the rest until E3 | **Open decision** |

**Decisions:** (1) Phase 1 slice = Guard effect analysis + minimal Intel: **accepted** (ADR 0002). (2) Defer Scan beyond the minimal library until E3 shows signal: **still open**.

---

## 15. Repo Guard (planned; parked until the Phase 1 exit test passes)

Added 2026-10-27 by the project owner. Decision record: ADR 0003. **Do not build before the Phase 1 exit criterion in §9 is met.**

### 15.1 Problem
People sign transactions built by Stellar projects: wallets, dApps, deploy scripts. A contributor or collaborator can change what those projects do in ways reviewers miss: swap a payment destination or contract ID, commit a contract binary that does not match its source, add a dependency that runs code at install time, or edit CI so it leaks secrets. Generic tools catch some of this for any language; none look for the Stellar-specific versions.

### 15.2 What it is
A GitHub Action that runs on pull requests in Stellar and Soroban projects and reports risky changes in the diff. It **advises**: it posts findings as check annotations and a summary, and blocks merging only if the maintainer makes the check required.

| ID | Requirement | Pri |
|---|---|---|
| R-1 | **WASM provenance:** flag a committed or released `.wasm` whose SHA-256 differs from a reproducible build of the source in the same commit, and any new or changed `.wasm` with no buildable source. Reuses Scan's parser for indicators on changed contracts. TODO(verify): Soroban build reproducibility and the pinned toolchain it needs. | P0 |
| R-2 | **Secrets:** flag Stellar secret seeds (`S…` strkeys with a valid checksum) and BIP-39-style recovery phrases added in the diff. Never print the secret; report file and line only. | P0 |
| R-3 | **Install-time code:** flag new or changed dependencies that run code at install or build time (npm `preinstall`/`install`/`postinstall`, new Cargo crates with `build.rs`), and lockfile changes that switch a package's source. | P0 |
| R-4 | **Changed addresses and IDs:** flag added, removed or changed `G…`, `M…` and `C…` strkeys and network passphrases, with extra weight in deploy scripts, configuration and frontend constants. | P0 |
| R-5 | **Workflow changes:** flag edits under `.github/workflows/`, especially `pull_request_target`, new secret use, and actions not pinned to a commit SHA. | P0 |
| R-6 | **Output:** severity-ordered findings with file and line, built only from approved templates (§5.1). Never says "safe"; a clean run says no issues were found and lists what was not checked. | P0 |
| R-7 | **Fail loud:** any error, timeout or unsupported input yields "could not analyze", never a passing result. | P0 |
| R-8 | Optional Intel lookup of changed addresses and contract IDs against the signed snapshot. | P1 |

### 15.3 Non-goals
- General malware or virus detection, signature scanning, or scanning non-Stellar projects (NG1 still holds).
- Executing code from the pull request with access to secrets. The reproducible build in R-1 runs sandboxed, with no network and no secrets.
- Scanning full repository history, or replacing GitHub secret scanning, Dependabot or code review.
- Judging contributors. Findings describe **what the change does** (§5.1 L2), never who made it or why.

### 15.4 Risks
- **False positives:** legitimate releases change addresses and workflows. Mitigation: per-rule severity, allowlists in a reviewed config file, and informational-only rules.
- **Reproducible builds may not be reproducible** across toolchains; R-1 depends on verifying this first.
- **The Action itself is an attack surface** (`pull_request_target` misuse). It must run with a read-only token on untrusted PRs.
- **Crowded space:** the value is only the Stellar-specific rules; generic checks stay in existing tools.

### 15.5 Success metrics
Pilot repos installed; findings confirmed by maintainers vs. dismissed (dismiss rate per rule); zero leaked secrets in Action output.
