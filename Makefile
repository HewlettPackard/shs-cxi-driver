# SPDX-License-Identifier: GPL-2.0
# Copyright 2020 Hewlett Packard Enterprise Development LP

export TOPDIR := $(if $(TOPDIR),$(TOPDIR),$(shell readlink -e .))

SUBDIRS = drivers/net/ethernet/hpe/ss1 ucxi tests/pkt_test
SUBDIRS = drivers/net/ethernet/hpe/ss1 ucxi
CHECKPATCH ?= ./contrib/checkpatch.pl
CHECKPATCH_BASE ?= HEAD
CHECKPATCH_FLAGS ?= --no-tree --no-signoff --summary-file --ignore FILE_PATH_CHANGES,LINUX_VERSION_CODE

all clean: $(SUBDIRS)
	rm -rf WORKSPACE
	rm -rf RPMS
	rm -f vars.sh

$(SUBDIRS)::
	$(MAKE) -C $@ $(MAKECMDGOALS)

# Run the testsuite
check:
	make -C tests prove

# Fast preflight for local and AI loops: build only (no VM tests)
check-smoke:
	$(MAKE) -C drivers/net/ethernet/hpe/ss1 build
	$(MAKE) -C ucxi all

# Run checkpatch on current diff versus CHECKPATCH_BASE
check-style:
	@if ! git rev-parse --git-dir >/dev/null 2>&1; then \
		echo "Error: check-style must run from inside a git repository."; \
		exit 1; \
	fi
	@if [ ! -f "$(CHECKPATCH)" ]; then \
		echo "Error: checkpatch script not found at $(CHECKPATCH)."; \
		exit 1; \
	fi
	@if git diff --quiet --no-ext-diff "$(CHECKPATCH_BASE)"; then \
		echo "No changes detected against $(CHECKPATCH_BASE); nothing to lint."; \
		exit 0; \
	fi
	@echo "Running checkpatch against diff from $(CHECKPATCH_BASE)"
	@git diff --no-ext-diff "$(CHECKPATCH_BASE)" | perl "$(CHECKPATCH)" $(CHECKPATCH_FLAGS)

# Validate AI context artifacts are present and well-formed
check-ai-context:
	@echo "=== Checking AI context artifacts ==="
	@errors=0; \
	for f in .github/copilot-instructions.md CONTEXT.md AGENTS.md GLOSSARY.md ARCHITECTURE.md; do \
		if [ ! -f "$$f" ]; then \
			echo "MISSING: $$f"; errors=$$((errors+1)); \
		fi; \
	done; \
	size=$$(wc -c < .github/copilot-instructions.md 2>/dev/null || echo 0); \
	if [ "$$size" -gt 12288 ]; then \
		echo "WARN: .github/copilot-instructions.md is $$size bytes (>12KB); consider splitting"; \
	fi; \
	for f in .github/instructions/*.instructions.md; do \
		[ -f "$$f" ] || continue; \
		if ! grep -q "^applyTo:" "$$f" && ! grep -q "^---" "$$f"; then \
			echo "WARN: $$f may be missing YAML frontmatter (applyTo field)"; \
		fi; \
	done; \
	for ref in $$(grep -oP '\[.*?\]\(\K[^)]+' AGENTS.md 2>/dev/null); do \
		case "$$ref" in http*) continue;; esac; \
		[ -f "$$ref" ] || { echo "BROKEN REF in AGENTS.md: $$ref"; errors=$$((errors+1)); }; \
	done; \
	if [ "$$errors" -gt 0 ]; then \
		echo "$$errors error(s) found in AI context artifacts."; exit 1; \
	else \
		echo "All AI context checks passed."; \
	fi

atu-test:
	make -C tests t0400-atu.t

PACKAGE = cray-cxi-driver
VERSION = 0.9

DIST_FILES = \
	drivers/net/ethernet/hpe/ss1/*.c \
	drivers/net/ethernet/hpe/ss1/*.h \
	drivers/net/ethernet/hpe/ss1/Makefile \
	drivers/net/ethernet/hpe/ss1/Kbuild \
	ucxi/*.c \
	ucxi/*.h \
	ucxi/Makefile \
	include/ \
	cray-cxi-driver.spec \
	dkms.conf.in \
	50-cxi-driver.rules \
	Makefile \
	README \
	README.eth

.PHONY: dist check-smoke check-style check-ai-context

dist: $(DIST_FILES)
	tar czf $(PACKAGE)-$(VERSION).tar.gz --transform 's/^/$(PACKAGE)-$(VERSION)\//' $(DIST_FILES)

$(PACKAGE)-$(VERSION).tar.gz: dist

rpm: $(PACKAGE)-$(VERSION).tar.gz
	BUILD_METADATA='0' rpmbuild -ta $<
