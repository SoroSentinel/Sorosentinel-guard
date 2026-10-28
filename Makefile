# Standard targets shared by all SoroSentinel repos (docs/project_structure.md §2.2).
# Thin wrapper over pnpm; native commands stay usable.

PNPM ?= pnpm

.PHONY: deps fmt lint test test-contract gen fixtures-check schemas-check pin-schemas replay verify

deps:
	$(PNPM) install --frozen-lockfile

# TODO: no formatter chosen yet (adding one needs dependency approval).
fmt:
	@echo "fmt: no formatter configured"

lint:
	$(PNPM) -r typecheck

test:
	$(PNPM) -r test

# Intel's pinned vectors (canonical keys, snapshot signing, wording render) must pass.
test-contract: schemas-check
	cd packages/core && $(PNPM) exec vitest run test/contract

# Pinned Intel files match their recorded checksums (offline; no hand edits).
schemas-check:
	cd intel-schemas && shasum -a 256 -c SHA256SUMS
	@grep -q "^tag $(INTEL_SCHEMAS_TAG)$$" intel-schemas/PINNED || { echo "intel-schemas is not pinned at $(INTEL_SCHEMAS_TAG); run make pin-schemas"; exit 1; }

# Re-pin Intel's schemas, vectors and blocklist at a tag (needs network).
INTEL_SCHEMAS_TAG ?= v0.1.0-next.0
pin-schemas:
	scripts/pin-intel-schemas.sh $(INTEL_SCHEMAS_TAG)

# Regenerates fixtures/tx from packages/core/scripts/gen-fixtures.ts.
gen:
	cd packages/core && node scripts/gen-fixtures.ts

# Fails if committed fixtures differ from what the generator produces.
fixtures-check: gen
	git diff --exit-code -- fixtures
	@test -z "$$(git ls-files --others --exclude-standard -- fixtures)" || { echo "untracked fixtures:"; git ls-files --others --exclude-standard -- fixtures; exit 1; }

# Experiment E2: make replay FILE=txs.jsonl [MAX_RATE=0.02]. Prints aggregates only.
MAX_RATE ?= 0.02
replay:
	@test -n "$(FILE)" || { echo "usage: make replay FILE=<txs.jsonl> [MAX_RATE=0.02]"; exit 2; }
	cd packages/core && node scripts/replay.ts "$(abspath $(FILE))" --max-unanalyzable-rate $(MAX_RATE)

verify: lint test test-contract fixtures-check
