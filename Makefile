# Standard targets shared by all SoroSentinel repos (docs/project_structure.md §2.2).
# Phase 0 stub: the TypeScript workspace arrives in scaffold step 5 (decoder + fixtures).

.PHONY: deps fmt lint test test-contract gen verify

deps fmt lint test test-contract gen:
	@echo "$@: nothing to run yet (TypeScript workspace not scaffolded)"

verify: lint test test-contract
