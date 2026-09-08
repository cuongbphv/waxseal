# Local shortcuts. GNU make 3.81 (what macOS ships) — no .ONESHELL, no
# $(file ...), no .RECIPEPREFIX.
#
# This file adds no tool the project did not already need: `make` is on every
# developer machine and every CI runner, which is why it is here rather than a
# justfile. It also does not reimplement server/scripts/*.sh — those already
# know how to build the server and its UI, and a second copy of that knowledge
# would be a second thing to keep correct.
#
#   make            list the targets
#   make ci         the same three commands the root Dockerfile runs
#   make image      the CLI runtime image
#   make pyz        the single-file zipapp

SHELL := /bin/sh

UV ?= uv
DOCKER ?= docker

# The version the wheel and the image are labelled with. Read from the one
# place that states it (pyproject.toml) rather than repeated here — a second
# place to state the version is a second place to get it wrong, which is what
# TestVersionIsStatedOnce exists to catch.
VERSION := $(shell $(UV) run --extra dev python -c "import tomllib,pathlib; print(tomllib.loads(pathlib.Path('pyproject.toml').read_text())['project']['version'])" 2>/dev/null)
REVISION := $(shell git rev-parse HEAD 2>/dev/null || echo unknown)

IMAGE ?= ghcr.io/cuongbphv/waxseal
SERVER_IMAGE ?= ghcr.io/cuongbphv/waxseal-server
TAG ?= dev

# Extras baked into the image. Empty by default, which keeps the default image
# stdlib-only (see deploy/docker/Dockerfile).
EXTRAS ?=

CHART_DIR := deploy/helm

.PHONY: help test lint typecheck cov build pyz image image-server \
        install-sh-check compose-up compose-down ci helm-lint helm-template clean

help:
	@echo 'waxseal — make targets'
	@echo ''
	@echo '  test              pytest with the coverage floor'
	@echo '  lint              ruff check + ruff format --check'
	@echo '  typecheck         mypy over src/ and tests/, both platform views'
	@echo '  cov               alias for test (the floor IS the coverage gate)'
	@echo '  ci                the three commands the root Dockerfile runs, in order'
	@echo ''
	@echo '  build             wheel + sdist into dist/'
	@echo '  pyz               dist/waxseal-$(VERSION).pyz (single-file verifier)'
	@echo '  image             $(IMAGE):$(TAG) from deploy/docker/Dockerfile'
	@echo '  image-server      $(SERVER_IMAGE):$(TAG) from server/Dockerfile'
	@echo ''
	@echo '  install-sh-check  shellcheck deploy/install.sh and server/scripts/*.sh'
	@echo '  helm-lint         helm lint every chart under $(CHART_DIR)'
	@echo '  helm-template     helm template every chart under $(CHART_DIR)'
	@echo '  compose-up        docker compose up -d (server stack)'
	@echo '  compose-down      docker compose down'
	@echo ''
	@echo '  clean             remove dist/ and the caches'

# ---- checks ------------------------------------------------------------------

test:
	$(UV) run --extra dev pytest --cov=waxseal

lint:
	$(UV) run --extra dev ruff check .
	$(UV) run --extra dev ruff format --check .

# Both platform views, both trees — exactly the set ci.yml runs. fcntl/msvcrt
# attribute gating in typeshed differs per --platform, and the 0.1.5 release
# only surfaced six win32-only errors after three other masked failures were
# peeled off one at a time.
typecheck:
	$(UV) run --extra dev mypy
	$(UV) run --extra dev mypy tests/
	$(UV) run --extra dev mypy --platform win32
	$(UV) run --extra dev mypy --platform win32 tests/
	$(UV) run --extra dev mypy --platform linux
	$(UV) run --extra dev mypy --platform linux tests/

cov: test

# EXACTLY the three commands the root Dockerfile runs, in that order. The
# container build is the 100%-pass proof; this is the local shortcut to the
# same proof, and the two must not drift — if you change one, change the
# other in the same commit.
ci:
	$(UV) run --extra dev pytest --cov=waxseal
	$(UV) run --extra dev mypy
	$(UV) run --extra dev ruff check .
	$(UV) run --extra dev ruff format --check .

# ---- artifacts ---------------------------------------------------------------

build:
	$(UV) build

pyz:
	$(UV) run --extra dev python tools/build_pyz.py

image:
	$(DOCKER) build \
	  -f deploy/docker/Dockerfile \
	  --build-arg VERSION=$(VERSION) \
	  --build-arg REVISION=$(REVISION) \
	  --build-arg EXTRAS=$(EXTRAS) \
	  -t $(IMAGE):$(TAG) .

# Context is the repository root, as server/Dockerfile's own header requires:
# the image installs waxseal from THIS tree, so the server and the library it
# verifies with are the same commit.
image-server:
	$(DOCKER) build -f server/Dockerfile -t $(SERVER_IMAGE):$(TAG) .

# ---- shell -------------------------------------------------------------------

# shellcheck is not installed on the development machine this was written on,
# so the target says which check it could not run instead of passing silently.
# CLAUDE.md rule 6: a degradation is recorded in the output. CI has the tool
# and runs it for real (.github/workflows/ci.yml, job `shell`).
install-sh-check:
	@sh -n deploy/install.sh && echo 'sh -n deploy/install.sh: ok'
	@if command -v shellcheck >/dev/null 2>&1; then \
	  shellcheck --shell=sh deploy/install.sh && shellcheck server/scripts/*.sh; \
	else \
	  echo 'NOTICE [unverified]: shellcheck is not installed — only `sh -n` ran,'; \
	  echo '            which checks syntax and nothing else.'; \
	  echo '            remedy: brew install shellcheck (CI job `shell` runs it regardless).'; \
	fi

# ---- helm --------------------------------------------------------------------
# Tolerant of a missing chart directory on purpose: the charts land in their own
# change, and `helm` is not installed on every developer machine. A target that
# exploded on either would just get commented out.

helm-lint:
	@if [ ! -d $(CHART_DIR) ]; then \
	  echo 'NOTICE: no $(CHART_DIR) in this tree — nothing to lint.'; \
	elif ! command -v helm >/dev/null 2>&1; then \
	  echo 'NOTICE [unverified]: helm is not installed — charts NOT linted.'; \
	  echo '            remedy: brew install helm (CI runs it regardless).'; \
	else \
	  for c in $(CHART_DIR)/*/; do \
	    [ -f "$$c/Chart.yaml" ] || continue; \
	    echo "==> helm lint $$c"; helm lint "$$c" || exit 1; \
	  done; \
	fi

helm-template:
	@if [ ! -d $(CHART_DIR) ]; then \
	  echo 'NOTICE: no $(CHART_DIR) in this tree — nothing to template.'; \
	elif ! command -v helm >/dev/null 2>&1; then \
	  echo 'NOTICE [unverified]: helm is not installed — charts NOT rendered.'; \
	  echo '            remedy: brew install helm (CI runs it regardless).'; \
	else \
	  for c in $(CHART_DIR)/*/; do \
	    [ -f "$$c/Chart.yaml" ] || continue; \
	    echo "==> helm template $$c"; helm template "$$c" >/dev/null || exit 1; \
	  done; \
	fi

# ---- compose -----------------------------------------------------------------
# server/docker-compose.yml is the existing, working stack; this only saves the
# typing. Run from the repository root because the build context is the root.

compose-up:
	$(DOCKER) compose -f server/docker-compose.yml up -d

compose-down:
	$(DOCKER) compose -f server/docker-compose.yml down

# ---- housekeeping ------------------------------------------------------------

clean:
	rm -rf dist build .pytest_cache .ruff_cache .mypy_cache
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
