<!-- GENERATED: edit sorosentinel-intel/docs/adr/0007-phase2-3-scope-approved.md, then run scripts/sync-docs.sh. -->

# ADR 0007: Phase 2 and Phase 3 scope is approved, sequenced after the Phase 1 exit

Status: accepted · Date: 2026-10-29 · Decided by: project owner

## Context

PRD §9 defines four phases. Phases 0 and 1 are the v1 build. AGENTS.md §4
lists items that must not be built in v1 "unless a human says so", and most of
them are Phase 2 and Phase 3 requirements from PRD §6.

On 2026-10-29 the roadmap was filed as issues with one milestone per phase.
The owner then approved the Phase 2 and Phase 3 scope.

## Decision

1. These PRD requirements are **approved scope**:
   - **Phase 2:**
     - Intel: I-8 reports, I-9 disputes, I-10 feeds and webhooks
     - Guard: G-9 origin check, G-11 local-only mode, plus a second integrator
     - Scan: S-7 CLI and CI action, S-8 fuzzy similarity
   - **Phase 3:**
     - Intel: I-11 public lookup page, I-12 partner imports
     - Guard: G-10 browser extension
     - Scan: S-9 dynamic analysis
2. **Sequencing is unchanged.**
   - Work on these items starts after the Phase 1 exit criterion in PRD §9 is
     met: a wallet integration in test, plus the end-to-end flow.
   - Until then, the AGENTS.md §4 list still governs what is built, including
     the matching tables (report, dispute and webhook).
3. **Approval of scope is not approval of design.** Each PR still asks first
   for anything listed in AGENTS.md §10:
   - a new dependency
   - a schema or migration
   - an endpoint, finding code, detector or template
   - a threshold
   - KMS code
4. Repo Guard (ADR 0003) stays separate: it is still parked until the Phase 1
   exit, and its scope is still PRD §15.

## Consequences

- The issues in the "Phase 2: Community & scale" and "Phase 3: Expansion"
  milestones carry a scope-approved note instead of a needs-approval banner.
- Open decision 2 (defer Scan beyond a minimal library until E3 shows signal)
  is **not** settled by this ADR. Scan's S-8 and S-9 still wait on the E3
  result (Scan issue #29), unless the owner decides otherwise.
- Non-English text, numeric weight×trust×decay scoring, Redis and the other
  infrastructure items in AGENTS.md §4 are not PRD phase requirements and are
  not approved by this ADR.
