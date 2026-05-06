GOBASE=$(shell pwd)
GOBIN=$(GOBASE)/bin
GO_BUILD_FLAGS := ${GO_BUILD_FLAGS}

.EXPORT_ALL_VARIABLES:

all: validate-all

help:
	@echo "Targets:"
	@echo "    validate-all:    run all validations (lint, format check, tidy check)"
	@echo "    lint:            run golangci-lint"
	@echo "    format:          format Go code using gofmt and goimports"
	@echo "    check-format:    check that formatting does not introduce changes"
	@echo "    tidy:            tidy go mod"
	@echo "    tidy-check:      check that go.mod and go.sum are tidy"
	@echo "    verify:          verify the code compiles"
	@echo "    clean:           clean up golangci-lint and other tools"

tidy:
	@echo "🧹 Tidying go modules..."
	git ls-files go.mod '**/*go.mod' -z | xargs -0 -I{} bash -xc 'cd $$(dirname {}) && go mod tidy'
	@echo "✅ Go modules tidied successfully."

# Check that go mod tidy does not introduce changes
tidy-check: tidy
	@echo "🔍 Checking if go.mod and go.sum are tidy..."
	@git diff --quiet go.mod go.sum || (echo "❌ Detected uncommitted changes after tidy. Run 'make tidy' and commit the result." && git diff go.mod go.sum && exit 1)
	@echo "✅ go.mod and go.sum are tidy."

verify:
	@echo "⚙️ Verifying code compiles..."
	@go build -buildvcs=false $(GO_BUILD_FLAGS) ./...
	@echo "✅ Code compiles successfully."

clean:
	@echo "🗑️ Cleaning tools..."
	- rm -f -r bin
	@echo "✅ Clean complete."

##################### "make lint" support start ##########################
GOLANGCI_LINT_VERSION := v2.12.2
GOLANGCI_LINT := $(GOBIN)/golangci-lint

# Download golangci-lint locally if not already present
$(GOLANGCI_LINT):
	@echo "📦 Installing golangci-lint $(GOLANGCI_LINT_VERSION)..."
	@mkdir -p $(GOBIN)
	curl -sSfL https://golangci-lint.run/install.sh | \
		sh -s -- -b $(GOBIN) $(GOLANGCI_LINT_VERSION)
	@echo "✅ 'golangci-lint' installed successfully."

# Run linter
lint: $(GOLANGCI_LINT)
	@echo "🔍 Running golangci-lint..."
	@$(GOLANGCI_LINT) run --timeout=5m
	@echo "✅ Lint passed successfully!"
##################### "make lint" support end   ##########################

##################### "make format" support start ##########################
GOIMPORTS := $(GOBIN)/goimports

# Install goimports if not already available
$(GOIMPORTS):
	@echo "📦 Installing goimports..."
	@mkdir -p $(GOBIN)
	@go install golang.org/x/tools/cmd/goimports@latest
	@echo "✅ 'goimports' installed successfully."

# Format Go code using gofmt and goimports
format: $(GOIMPORTS)
	@echo "🧹 Formatting Go code..."
	@gofmt -s -w .
	@$(GOIMPORTS) -w .
	@echo "✅ Format complete."

# Check that formatting does not introduce changes
check-format: format
	@echo "🔍 Checking if formatting is up to date..."
	@git diff --quiet || (echo "❌ Detected uncommitted changes after format. Run 'make format' and commit the result." && git status && exit 1)
	@echo "✅ All formatted files are up to date."
##################### "make format" support end   ##########################

validate-all: lint check-format tidy-check

.PHONY: help tidy tidy-check verify clean lint format check-format validate-all

################################################################################
# Emoji Legend for Makefile Targets
#
# Action Type        | Emoji | Description
# -------------------|--------|------------------------------------------------
# Install tool        📦     Installing a dependency or binary
# Running task        ⚙️     Executing tasks like generate, build, etc.
# Linting/validation  🔍     Checking format, lint, static analysis, etc.
# Formatting          🧹     Formatting source code
# Success/complete    ✅     Task completed successfully
# Failure/alert       ❌     An error or failure occurred
# Teardown/cleanup    🗑️     Stopping, removing, or cleaning up resources
################################################################################
