<!-- GENERATED: edit sorosentinel-intel/docs/adr/0005-guard-integrator-contract.md, then run scripts/sync-docs.sh. -->

# ADR 0005 (DRAFT): Guard's integrator contract — what a host application must show

Status: proposed, draft for review · Date: 2026-10-28 · Decided by: not yet decided

Do not treat this as accepted. It is the written form of the third acceptance
criterion of Sorosentinel-guard issue #38 ("an integrator contract that makes
these non-suppressible, because silence is the failure mode"). The wallet pilot
itself, and experiment E1 with ≥3 wallet teams, are human work this document
cannot substitute for.

## Context

Guard is a library: `analyze(xdr, ctx)` returns a structured result and the host
application decides what a signer actually sees (ADR 0003, ARCHITECTURE §5).
Every invariant Guard upholds in code can be undone one layer up by an integrator
that renders only `findings` when `status === "findings_present"` and nothing
otherwise. That is the failure mode HQ1 ranks as the project's highest-impact
unknown, and no CI check in any repo can see it.

The SDK side is finished and tested. What is missing is a contract with the host,
so that "we advise, we never reassure" survives contact with a real signing flow.

## Decision (proposed)

An integrator of Guard must, at minimum, satisfy these six obligations. Each is
listed with the guarantee the SDK already provides, so the contract only adds
what a host can break.

1. **A stale or unverifiable snapshot is shown as a visible "protection data
   stale" state, never omitted.** `snapshotStatus` is returned on every result
   and `checkSnapshot` rejects the whole snapshot on any failure - malformed,
   unknown key, bad signature, wrong network, too old, from the future
   (`packages/core/src/intel/snapshot.ts:31-37`, `:101-124`; "it is never
   partially trusted", `:5-6`). The host must render the non-`verified` value.
2. **`NC-COUNTERPARTY-SIGNALS` is rendered whenever reputation lookup did not
   run**, so Intel downtime makes warnings visibly quieter, not quietly normal.
   Any `snapshotStatus` other than `verified` adds that code
   (`packages/core/src/analyze.ts:68-71`, `:221-222`).
3. **`partial` and `unanalyzable` stay visible to the signer.** Only a complete
   check may produce `findings_present` or `no_issues_found`; every gap - and
   any code added later - degrades to `partial`
   (`packages/core/src/analyze.ts:20`, `:243-250`). A decode or size failure
   returns `unanalyzable` with a reason and no effects
   (`packages/core/src/decode/envelope.ts:22-44`, `packages/core/src/analyze.ts:163-172`).
4. **Findings are shown severity-ordered and untruncated**, with the operation
   count. The SDK sorts most-severe-first and never truncates
   (`packages/core/src/rules/types.ts:46-55`, `packages/core/src/analyze.ts:80-81`).
   A host that paginates or collapses must not drop the highest-severity item.
5. **`not_checked` and the transaction hash appear in the host UI.** `txHash` is
   the hash of exactly the bytes being signed (`packages/core/src/analyze.ts:75-76`,
   `packages/core/src/decode/envelope.ts:50-62`; inner hash for fee bumps at
   `:87-88`), and `notChecked` is sorted (`packages/core/src/analyze.ts:236`).
6. **No telemetry by default; the only outbound calls are the configured RPC
   endpoint and Intel.** Guard has no default endpoint and sends the envelope,
   the ledger keys the caller named, and the SEP-29 data keys, and "nothing else
   is sent" (`packages/core/src/rpc/transport.ts:1-9`,
   `packages/core/src/analyze.ts:57-62`). A host must not add a third destination.

The reference integrator, `examples/analyze-transaction`, already prints all of
this (`status`, `snapshotStatus`, `not_checked` at
`examples/analyze-transaction/analyze.mts:74-91`).
It is a script, not a signer UI, which is exactly why the issue is still open.

## Consequences

- The contract becomes a checklist applied to a named pilot integration before
  it can be counted as PRD §9's "one wallet integration in test". E1's notes are
  the evidence; this document is not.
- The `stale` threshold is a product value, not a technical one:
  `DEFAULT_MAX_AGE_SECONDS` is 3600 with `TODO(verify)`
  (`packages/core/src/intel/snapshot.ts:10-12`). Deciding it belongs with the
  same review as this ADR.
- Wording shown to a signer still comes only from the renderer and the approved
  registry (AGENTS.md §5). This ADR does not add or change a template; the
  example renders `statement: null` fields through `wording/` and shows no
  free-text sentence.
- If a pilot host cannot meet an obligation, the honest output is that the
  integration is not Phase 1 complete - not a weaker contract.

## Open questions for the owner

1. Where does the contract live: this ADR only, or an enforced
   `docs/integration.md` in Guard plus a signed acceptance note per integrator?
2. Should Guard add a lint or test that fails when a new finding code or
   `NotChecked` code has no rendering path in the example? (It would catch
   drift, not a host that ignores the example.)
3. Which wallet teams are contacted for E1, and who speaks to them?
