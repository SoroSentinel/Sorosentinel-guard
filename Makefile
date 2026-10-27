# Standard targets shared by all SoroSentinel repos (docs/project_structure.md §2.2).
# Thin wrapper over pnpm; native commands stay usable.

PNPM ?= pnpm

.PHONY: deps fmt lint test test-contract gen fixtures-check verify

deps:
	$(PNPM) install --frozen-lockfile

# TODO: no formatter chosen yet (adding one needs dependency approval).
fmt:
	@echo "fmt: no formatter configured"

lint:
	$(PNPM) -r typecheck

test:
	$(PNPM) -r test

# TODO: run Intel's canonical-key and render vectors once a schemas tag is pinned.
test-contract:
	@echo "test-contract: no pinned sorosentinel-intel schemas tag yet"

# Regenerates fixtures/tx from packages/core/scripts/gen-fixtures.ts.
gen:
	cd packages/core && node scripts/gen-fixtures.ts

# Fails if committed fixtures differ from what the generator produces.
fixtures-check: gen
	git diff --exit-code -- fixtures
	@test -z "$$(git ls-files --others --exclude-standard -- fixtures)" || { echo "untracked fixtures:"; git ls-files --others --exclude-standard -- fixtures; exit 1; }

verify: lint test test-contract fixtures-check
