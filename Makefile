# ExSwan monorepo orchestration
#
# Local/workspace builds use path deps via EXSWAN_MONOREPO=true.
# Leave EXSWAN_MONOREPO unset (or set to anything other than "true") to resolve
# published Hex versions of sibling packages — useful for catching unreleased API usage.

export EXSWAN_MONOREPO ?= true

PACKAGES := $(wildcard packages/*)

.PHONY: deps compile test format format-check credo docs clean hex-build compatibility-fixtures compatibility-check help

help:
	@echo "ExSwan monorepo targets:"
	@echo "  make deps          - mix deps.get for every package"
	@echo "  make compile       - mix compile --warnings-as-errors for every package"
	@echo "  make test          - mix test for every package (workspace path deps)"
	@echo "  make format        - mix format for every package"
	@echo "  make format-check  - mix format --check-formatted for every package"
	@echo "  make credo         - mix credo --strict for every package"
	@echo "  make docs          - mix docs for every package"
	@echo "  make hex-build     - mix hex.build for every package"
	@echo "  make compatibility-fixtures - regenerate pinned SimpleWebAuthn fixtures"
	@echo "  make compatibility-check    - verify generated fixtures and browser types"
	@echo "  make clean         - remove _build and deps in every package"
	@echo ""
	@echo "EXSWAN_MONOREPO=$(EXSWAN_MONOREPO) (set to true for path deps)"

deps:
	@for p in $(PACKAGES); do \
	  echo "==> deps.get $$p"; \
	  (cd $$p && mix deps.get) || exit 1; \
	done

compile: deps
	@for p in $(PACKAGES); do \
	  echo "==> compile $$p"; \
	  (cd $$p && mix compile --warnings-as-errors) || exit 1; \
	done

test: deps
	@for p in $(PACKAGES); do \
	  echo "==> test $$p"; \
	  (cd $$p && mix test) || exit 1; \
	done

format:
	@for p in $(PACKAGES); do \
	  echo "==> format $$p"; \
	  (cd $$p && mix format) || exit 1; \
	done

format-check:
	@for p in $(PACKAGES); do \
	  echo "==> format --check-formatted $$p"; \
	  (cd $$p && mix format --check-formatted) || exit 1; \
	done

credo: deps
	@for p in $(PACKAGES); do \
	  echo "==> credo $$p"; \
	  (cd $$p && mix credo --strict) || exit 1; \
	done

docs: deps
	@for p in $(PACKAGES); do \
	  echo "==> docs $$p"; \
	  (cd $$p && mix docs) || exit 1; \
	done

# Validate standalone Hex package metadata/artifacts.
# EXSWAN_MONOREPO is forced off so mix.exs declares Hex deps (path deps cannot be published).
hex-build:
	@for p in $(PACKAGES); do \
	  echo "==> hex.build $$p"; \
	  (cd $$p && EXSWAN_MONOREPO=false mix hex.build) || exit 1; \
	done

compatibility-fixtures:
	cd test/compatibility && bun install --frozen-lockfile && bun run generate

compatibility-check:
	cd test/compatibility && bun install --frozen-lockfile && bun run check
	@git diff --exit-code -- test/compatibility/fixtures
	cd packages/exswan && mix test test/exswan/compatibility_options_test.exs

clean:
	@for p in $(PACKAGES); do \
	  echo "==> clean $$p"; \
	  rm -rf $$p/_build $$p/deps $$p/doc $$p/cover; \
	done
