# Thin wrappers over the everyday workflow, so the whole emulator family is
# driven the same way. Nothing here is required — every target shows the
# command it runs.
#
#   make run     # build and run natively (compat mode, https://localhost:8443)
#   make up      # …or run the published image in the background
#   make status  # is it actually serving? (exit non-zero if not)
#
# Unlike its siblings this repo ships no docker-compose.yml, because the
# emulator is a SINGLE container with no peers to wire up — entra is the thing
# everything else depends on, not a thing that depends on anything. `up`/`down`
# therefore wrap `docker run`/`docker rm` rather than compose, and keep the same
# verbs the rest of the family uses. To run entra as part of a stack, use the
# compose file in azure-keyvault-emulator or fabric-emulator.
#
# Linux, macOS and Windows. On Windows the recipes run under a POSIX shell —
# `sh.exe` from Git for Windows, which also supplies the grep/awk/curl the
# scripts use. Install once and everything below works from PowerShell or cmd:
#
#   winget install Git.Git         # provides sh.exe + grep/awk/cut/curl
#   winget install ezwinports.make # GNU Make itself (no admin needed)
#
# `make doctor` checks the whole toolchain and prints what is missing.
# Prefixed on purpose. Make imports the ENVIRONMENT as variables, and `?=` does
# not override an inherited one — so a bare `NAME ?= entra-emulator` silently
# loses to any `NAME` already exported in the caller's shell, and `make up`
# then names the container something else entirely. That is not hypothetical:
# it showed up here as `docker run --name calvinxwin`. `PORT` is an even more
# common thing to have exported. Command-line overrides still work:
#   make up ENTRA_PORT=9443
ENTRA_IMAGE ?= ghcr.io/calvinchengx/entra-emulator:latest
ENTRA_NAME  ?= entra-emulator
ENTRA_PORT  ?= 8443

# Windows: force the recipes onto sh.exe. GNU Make on Windows falls back to
# cmd.exe when it cannot find a shell, and cmd cannot run a single line of what
# is below. Make searches PATH for this itself, so the spaces in
# "C:\Program Files\Git\bin" are its problem, not ours.
ifeq ($(OS),Windows_NT)
  SHELL := sh.exe
  .SHELLFLAGS := -c
endif

# Which interpreter is "python3" is not a given. On Windows `python3` normally
# resolves to the Microsoft Store *alias stub*: it exists on PATH, so
# `command -v python3` succeeds, and then it exits 49 with a "not found, install
# from the Store" message. Detection therefore has to RUN each candidate, not
# merely locate it. Override with PY= if you keep python somewhere unusual.
PY ?= $(shell for c in python3 python py; do if "$$c" -c '' >/dev/null 2>&1; then echo "$$c"; break; fi; done)

.PHONY: help doctor build run up down status logs ps test smoke e2e clean docs-build docs-serve

help: ## Show the available targets
	@# [a-z0-9-] not [a-z-]: `e2e` has a digit in it, and the narrower class
	@# silently omitted it from this listing rather than failing visibly.
	@grep -hE '^[a-z0-9-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  %-14s %s\n", $$1, $$2}'

doctor: ## Check the toolchain this Makefile needs
	@sh scripts/doctor.sh

build: ## Compile the binary into ./entra-emulator
	go build ./cmd/entra-emulator

run: build ## Run natively in compat mode (foreground, Ctrl-C to stop)
	ORIGIN_MODE=compat ./entra-emulator

up: ## Run the published image in the background (ENTRA_PORT=8443 by default)
	docker run -d --name $(ENTRA_NAME) -p $(ENTRA_PORT):8443 -e ORIGIN_MODE=compat $(ENTRA_IMAGE)

down: ## Stop and remove that container
	docker rm -f $(ENTRA_NAME)

status: ## Report whether the emulator is serving (non-zero exit if not)
	@sh scripts/status.sh

ps: ## Container state
	@# Anchored: docker's name filter is a substring match, so an unanchored
	@# `entra-emulator` also lists fabric-emulator-entra-emulator-1.
	@docker ps -a --filter "name=^$(ENTRA_NAME)$$" --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'

logs: ## Tail container logs
	docker logs -f --tail 100 $(ENTRA_NAME)

test: ## Go build, vet and unit tests
	go build ./... && go vet ./... && go test ./...

smoke: ## Build the image and assert it serves (scripts/docker-smoke.sh)
	@# bash, not sh: that script declares `#!/usr/bin/env bash` and uses
	@# `set -o pipefail`, which dash does not have. Invoking it as `sh` worked
	@# on Windows and macOS, where sh IS bash, and failed only on Linux.
	@bash scripts/docker-smoke.sh

e2e: ## Real-SDK e2e matrix (MSAL Node/Python/Go/.NET/Java, Graph SDK)
	@test -n "$(PY)" || { echo "no working python found (tried python3, python, py); set PY=" >&2; exit 1; }
	$(PY) e2e/run.py

clean: ## Remove the built binary and the local ./data store (full reset)
	rm -rf ./entra-emulator ./entra-emulator.exe ./data

# ---------------------------------------------------------------------------
# The documentation site.
#
# Not called `docs`: there is a docs/ DIRECTORY here, and a target sharing its
# name is satisfied by the directory existing. `make docs` would print
# "nothing to be done" and exit 0, which is the failure that looks like
# success. .PHONY below would also fix it; a name that cannot collide fixes it
# whether or not someone remembers .PHONY.
#
# `pnpm --filter $(DOCS_PKG) dev` is the fast inner loop for PROSE, and it is
# not this. It is based at the docs subpath and knows nothing about the tree around
# it, so under it the landing page does not exist, the redirect stubs do not
# exist, and the badge endpoints the landing page fetches do not exist. Use it
# to write a page; use `make docs-serve` before believing the site works.
#
# CI runs `make docs-build` and publishes exactly what it leaves in ./_site, so
# the thing previewed here is the thing that deploys.
DOCS_PKG  ?= entra-emulator-docs
DOCS_PORT ?= 8099
# The interpreter CI uses, pinned. These scripts are stdlib-only, hence
# --no-project: no environment to resolve, and a local 3.9 cannot pass
# something 3.12 would reject.
UVPY ?= uv run --no-project --python 3.12 python

docs-build: ## Build the published site into ./_site (what CI deploys)
	@command -v uv >/dev/null 2>&1 || { echo "uv is not on PATH: https://docs.astral.sh/uv/" >&2; exit 1; }
	pnpm install --frozen-lockfile
	$(UVPY) scripts/check_docs_links.py --strict
	pnpm --filter $(DOCS_PKG) build
	$(UVPY) scripts/assemble_site.py --self-test
	$(UVPY) scripts/assemble_site.py --out _site
	$(UVPY) scripts/check_landing_page.py --site _site

docs-serve: docs-build ## …and serve it locally at its published URLs (DOCS_PORT=8099)
	$(UVPY) scripts/assemble_site.py --serve --site _site --port $(DOCS_PORT)
