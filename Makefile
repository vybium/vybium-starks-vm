# Vybium STARKs VM Development Makefile
# Provides convenient commands for development, testing, and building

.PHONY: help test build clean lint format check run-examples \
	test-race test-cover test-bench test-verbose test-package \
	build-cli install-cli build-all \
	dev-setup dev dev-deps tidy download \
	vuln-check \
	docs docs-godoc docs-readme \
	version tag clean-all ci-test ci-build ci-local

# Default target
help:
	@echo "Vybium STARKs VM Development Commands:"
	@echo ""
	@echo "Building:"
	@echo "  make build             - Build all binaries (output: bin/)"
	@echo "  make build-cli         - Build CLI tool (output: bin/vybium-starks-vm-prover)"
	@echo "  make build-all         - Build all commands (output: bin/)"
	@echo "  make install-cli       - Install CLI tool globally"
	@echo ""
	@echo "Testing:"
	@echo "  make test              - Run all tests"
	@echo "  make test-race         - Run tests with race detector"
	@echo "  make test-cover        - Run tests with coverage"
	@echo "  make test-bench        - Run benchmarks"
	@echo "  make test-verbose      - Run tests with verbose output"
	@echo "  make test-package PKG  - Run tests for specific package"
	@echo "  make test-integration  - Run integration tests only"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint              - Run linter"
	@echo "  make format            - Format code"
	@echo "  make format-check      - Check code formatting"
	@echo "  make check             - Run all checks (format + lint + test)"
	@echo ""
	@echo "Documentation:"
	@echo "  make docs              - Show documentation info"
	@echo "  make docs-godoc        - Serve godoc on http://localhost:6060"
	@echo "  make docs-readme       - Check README exists"
	@echo ""
	@echo "Examples:"
	@echo "  make run-examples      - Run all examples"
	@echo "  make run-example NAME  - Run specific example"
	@echo ""
	@echo "Development:"
	@echo "  make dev-setup         - Setup development environment"
	@echo "  make dev-deps          - Install development dependencies"
	@echo "  make dev               - Quick dev cycle (format + lint + test)"
	@echo "  make tidy              - Run go mod tidy"
	@echo "  make download          - Download Go modules"
	@echo ""
	@echo "Security:"
	@echo "  make vuln-check        - Check for vulnerabilities"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean             - Clean build artifacts"
	@echo "  make clean-all         - Clean everything (including cache)"
	@echo ""
	@echo "Version:"
	@echo "  make version           - Show current version"
	@echo "  make tag VERSION       - Create git tag"
	@echo ""
	@echo "CI/CD:"
	@echo "  make ci-test           - Run tests for CI"
	@echo "  make ci-build          - Build for CI"
	@echo "  make ci-local          - Run full CI pipeline locally (100% replication)"
	@echo ""

# ============================================================================
# Testing
# ============================================================================

test:
	@echo "Running all tests..."
	@go test ./...

test-race:
	@echo "Running all tests with race detector..."
	@go test -race ./...

test-cover:
	@echo "Running all tests with coverage..."
	@mkdir -p reports
	@go test -race -coverprofile=reports/coverage.out ./...
	@go tool cover -html=reports/coverage.out -o reports/coverage.html
	@echo "Coverage report generated:"
	@echo "  - reports/coverage.out"
	@echo "  - reports/coverage.html"
	@go tool cover -func=reports/coverage.out | tail -1

test-bench:
	@echo "Running benchmarks..."
	@go test -bench=. -benchmem ./...

test-verbose:
	@echo "Running tests with verbose output..."
	@go test -v ./...

test-package:
	@if [ -z "$(PKG)" ]; then \
		echo "Usage: make test-package PKG=<package_path>"; \
		echo "Example: make test-package PKG=./pkg/vybium-starks-vm"; \
		exit 1; \
	fi
	@echo "Running tests for package: $(PKG)"
	@go test -v $(PKG)/...

test-integration:
	@echo "Running integration tests..."
	@if [ -d "./tests/integration" ]; then \
		go test -v -timeout=10m ./tests/integration/...; \
	else \
		echo "No integration tests found"; \
	fi

# ============================================================================
# Building
# ============================================================================

build:
	@echo "Building all binaries..."
	@mkdir -p bin
	@if [ -d "./cmd" ]; then \
		for cmd in ./cmd/*; do \
			if [ -d "$$cmd" ]; then \
				cmd_name=$$(basename "$$cmd"); \
				echo "Building $$cmd_name..."; \
				go build -o "bin/$$cmd_name" "./cmd/$$cmd_name" || exit 1; \
			fi \
		done; \
		echo "✓ All binaries built in bin/"; \
		ls -lh bin/; \
	else \
		echo "No commands found in ./cmd"; \
	fi

build-cli:
	@mkdir -p bin
	@echo "Building vybium-starks-vm-prover CLI..."
	@go build -o bin/vybium-starks-vm-prover ./cmd/vybium-starks-vm-prover
	@echo "✓ CLI built: bin/vybium-starks-vm-prover"

install-cli: build-cli
	@echo "Installing vybium-starks-vm-prover CLI..."
	@go install ./cmd/vybium-starks-vm-prover
	@echo "✓ CLI installed globally"

build-all:
	@echo "Building all binaries..."
	@mkdir -p bin
	@if [ -d "./cmd" ]; then \
		for cmd in ./cmd/*; do \
			if [ -d "$$cmd" ]; then \
				cmd_name=$$(basename "$$cmd"); \
				echo "Building $$cmd_name..."; \
				go build -o "bin/$$cmd_name" "./cmd/$$cmd_name" || exit 1; \
			fi \
		done; \
		echo "✓ All binaries built in bin/"; \
		ls -lh bin/; \
	else \
		echo "No commands found in ./cmd"; \
	fi

# ============================================================================
# Code Quality
# ============================================================================

lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run --timeout=5m; \
	else \
		echo "Warning: golangci-lint not found. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
		exit 1; \
	fi

format:
	@echo "Formatting code..."
	@if command -v gofumpt >/dev/null 2>&1; then \
		gofumpt -w .; \
	else \
		echo "Warning: gofumpt not found. Install with: go install mvdan.cc/gofumpt@latest"; \
	fi
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w .; \
	else \
		echo "Warning: goimports not found. Install with: go install golang.org/x/tools/cmd/goimports@latest"; \
		go fmt ./...; \
	fi
	@echo "✓ Code formatted"

format-check:
	@echo "Checking code formatting..."
	@if command -v gofumpt >/dev/null 2>&1; then \
		unformatted=$$(gofumpt -l . | wc -l); \
		if [ $$unformatted -gt 0 ]; then \
			echo "The following files are not formatted:"; \
			gofumpt -l .; \
			echo ""; \
			echo "Run 'make format' to fix formatting"; \
			exit 1; \
		fi; \
	else \
		echo "Warning: gofumpt not found. Skipping format check."; \
	fi
	@echo "✓ All files are formatted"

check: format-check lint test
	@echo "✓ All checks passed!"

# ============================================================================
# Documentation
# ============================================================================

docs:
	@echo "Documentation:"
	@echo "  - README.md: Main project documentation"
	@echo "  - docs/: Detailed documentation"
	@echo "  - docs/RISC-V_STRATEGY.md: RISC-V optimization strategy"
	@echo "  - examples/README.md: Examples documentation"
	@echo ""
	@echo "Generate godoc:"
	@echo "  make docs-godoc"

docs-godoc:
	@echo "Starting godoc server on http://localhost:6060"
	@echo "Browse to http://localhost:6060/pkg/github.com/vybium/vybium-starks-vm/"
	@echo "Press Ctrl+C to stop"
	@godoc -http=:6060

docs-readme:
	@if [ ! -f "README.md" ]; then \
		echo "✗ README.md not found"; \
		exit 1; \
	fi
	@echo "✓ README.md exists"
	@if [ ! -f "examples/README.md" ]; then \
		echo "✗ examples/README.md not found"; \
		exit 1; \
	fi
	@echo "✓ examples/README.md exists"

# ============================================================================
# Examples
# ============================================================================

run-examples:
	@echo "Running all examples..."
	@if [ -d "./examples" ]; then \
		for example in ./examples/*/main.go; do \
			if [ -f "$$example" ]; then \
				example_dir=$$(dirname "$$example"); \
				example_name=$$(basename "$$example_dir"); \
				echo ""; \
				echo "=== Running example: $$example_name ==="; \
				cd "$$example_dir" && timeout 30s go run main.go || true; \
				cd - > /dev/null; \
			fi \
		done; \
		echo ""; \
		echo "✓ All examples executed"; \
	else \
		echo "No examples found"; \
	fi

run-example:
	@if [ -z "$(NAME)" ]; then \
		echo "Usage: make run-example NAME=<example_name>"; \
		echo "Available examples:"; \
		find ./examples -maxdepth 2 -name "main.go" -type f | while read f; do \
			dir=$$(dirname "$$f"); \
			echo "  - $$(basename "$$dir")"; \
		done; \
		exit 1; \
	fi
	@example_path="./examples/$(NAME)/main.go"; \
	if [ ! -f "$$example_path" ]; then \
		echo "Example $(NAME) not found"; \
		exit 1; \
	fi
	@echo "Running example: $(NAME)"
	@cd examples/$(NAME) && go run main.go

# ============================================================================
# Development
# ============================================================================

dev-setup: tidy download dev-deps
	@echo "✓ Development environment ready!"

dev-deps:
	@echo "Installing development dependencies..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest || echo "golangci-lint already installed or failed"
	@go install mvdan.cc/gofumpt@latest || echo "gofumpt already installed or failed"
	@go install golang.org/x/tools/cmd/goimports@latest || echo "goimports already installed or failed"
	@go install golang.org/x/vuln/cmd/govulncheck@latest || echo "govulncheck already installed or failed"
	@go install honnef.co/go/tools/cmd/staticcheck@latest || echo "staticcheck already installed or failed"
	@echo "✓ Development dependencies installed"

tidy:
	@echo "Running go mod tidy..."
	@go mod tidy
	@echo "✓ Dependencies cleaned"

download:
	@echo "Downloading Go modules..."
	@go mod download
	@echo "✓ Modules downloaded"

dev: format lint test
	@echo "✓ Development cycle complete!"

# ============================================================================
# Security
# ============================================================================

vuln-check:
	@echo "Checking for vulnerabilities..."
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "Installing govulncheck..."; \
		go install golang.org/x/vuln/cmd/govulncheck@latest; \
		govulncheck ./...; \
	fi

# ============================================================================
# Cleanup
# ============================================================================

clean:
	@echo "Cleaning build artifacts..."
	@go clean -cache -testcache
	@rm -rf bin/ coverage.out coverage.html reports/
	@echo "✓ Build artifacts cleaned"

clean-all: clean
	@echo "Cleaning all artifacts and cache..."
	@go clean -modcache || echo "Skipping modcache clean (may be shared)"
	@rm -rf .vscode .idea *.log
	@echo "✓ All artifacts cleaned"

# ============================================================================
# Version and Release
# ============================================================================

version:
	@echo "Current version:"
	@git describe --tags --always --dirty 2>/dev/null || echo "No version tags found"
	@echo ""
	@echo "Go version: $$(go version)"
	@echo "Module: $$(go list -m)"

tag:
	@if [ -z "$(VERSION)" ]; then \
		echo "Usage: make tag VERSION=<version>"; \
		echo "Example: make tag VERSION=v0.1.0"; \
		exit 1; \
	fi
	@echo "Creating tag: $(VERSION)"
	@git tag -a "$(VERSION)" -m "Release $(VERSION)"
	@echo "✓ Tag created: $(VERSION)"
	@echo "Push with: git push origin $(VERSION)"

# ============================================================================
# CI/CD Helpers
# ============================================================================

ci-test:
	@echo "Running CI tests..."
	@go test -race -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out | tail -1

ci-build:
	@echo "Building for CI..."
	@mkdir -p bin
	@if [ -d "./cmd" ]; then \
		for cmd in ./cmd/*; do \
			if [ -d "$$cmd" ]; then \
				cmd_name=$$(basename "$$cmd"); \
				echo "Building $$cmd_name..."; \
				go build -v -ldflags="-s -w" -o "bin/$$cmd_name" "./cmd/$$cmd_name" || exit 1; \
			fi \
		done; \
		echo "✓ All binaries built in bin/"; \
		ls -lh bin/; \
	else \
		echo "No commands found in ./cmd"; \
	fi

ci-local: ## Run full CI/CD pipeline locally
	@echo "Running full CI pipeline locally..."
	@if [ -f "./scripts/ci-local.sh" ]; then \
		bash ./scripts/ci-local.sh; \
	else \
		echo "Error: scripts/ci-local.sh not found"; \
		exit 1; \
	fi

ci: ci-local ## Alias for ci-local
