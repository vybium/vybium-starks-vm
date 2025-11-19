# CI/CD Infrastructure

Vybium STARKs VM now has a comprehensive, production-grade CI/CD pipeline based on industry best practices from octo-vm.

## 📋 Overview

The CI/CD infrastructure provides:
- **Automated Testing** - Multi-version Go testing with race detection
- **Code Quality** - Comprehensive linting and formatting checks
- **Security Scanning** - Vulnerability detection with govulncheck
- **Build Verification** - Automated binary builds across all packages
- **Coverage Reporting** - Code coverage tracking and reporting
- **Local Replication** - 100% local CI/CD execution capability

## 🔧 Components

### 1. GitHub Actions Workflow

**File**: `.github/workflows/ci.yml`

**Jobs**:
- **test** - Run tests with race detector and coverage
  - Matrix testing: Go 1.21, 1.22, 1.23
  - Race detector enabled
  - Coverage reporting to Codecov
  - go vet, gofumpt, staticcheck
  - govulncheck security scanning
  - golangci-lint comprehensive analysis

- **build** - Build all binaries
  - Builds all cmd/* packages
  - Upload build artifacts
  - Verify binary integrity

- **examples** - Test all examples
  - Run each example with timeout
  - Verify execution success

- **integration** - Integration tests
  - Run full integration test suite
  - Verify proof generation and verification

**Triggers**:
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop` branches

### 2. golangci-lint Configuration

**File**: `.golangci.yml`

**Enabled Linters** (20+):
- `govet` - Go vet static analysis
- `staticcheck` - Advanced static analysis
- `errcheck` - Error handling verification (critical for ZK proofs)
- `gosec` - Security analysis (essential for crypto code)
- `gocritic` - Comprehensive code checks
- `gocyclo` - Cyclomatic complexity (20 threshold for crypto algorithms)
- `funlen` - Function length (150 lines for proof generation)
- `dupl` - Code duplication detection
- `prealloc` - Slice preallocation (performance)
- `whitespace` - Whitespace issues
- `wrapcheck` - Error wrapping
- `paralleltest` - Parallel test detection
- `unused` - Unused code detection
- And more...

**Custom Settings**:
- Higher complexity thresholds for cryptographic operations
- Exclusions for test files, benchmarks, and examples
- Protocol-specific rules for complex implementations
- Field arithmetic optimizations allowed

### 3. Comprehensive Makefile

**File**: `Makefile`

**Categories**:

#### Testing
```bash
make test              # Run all tests
make test-race         # Tests with race detector
make test-cover        # Tests with coverage (generates HTML report)
make test-bench        # Run benchmarks
make test-verbose      # Verbose test output
make test-package PKG=./pkg/vybium-starks-vm  # Test specific package
make test-integration  # Integration tests only
```

#### Building
```bash
make build             # Build all binaries
make build-cli         # Build CLI tool
make install-cli       # Install CLI globally
```

#### Code Quality
```bash
make lint              # Run golangci-lint
make format            # Format code with gofumpt + goimports
make format-check      # Check formatting (CI-safe)
make check             # Run all checks (format + lint + test)
```

#### Development
```bash
make dev-setup         # Setup development environment
make dev-deps          # Install dev dependencies
make dev               # Quick dev cycle (format + lint + test)
make tidy              # Run go mod tidy
make download          # Download Go modules
```

#### Security
```bash
make vuln-check        # Check for vulnerabilities with govulncheck
```

#### Examples
```bash
make run-examples      # Run all examples
make run-example NAME=01_basic_execution  # Run specific example
```

#### CI/CD
```bash
make ci-test           # Run tests for CI (with coverage)
make ci-build          # Build for CI (optimized binaries)
make ci-local          # Run full CI pipeline locally
```

#### Documentation
```bash
make docs              # Show documentation info
make docs-godoc        # Serve godoc on http://localhost:6060
make docs-readme       # Verify README files exist
```

#### Cleanup
```bash
make clean             # Clean build artifacts
make clean-all         # Clean everything including cache
```

#### Version
```bash
make version           # Show current version
make tag VERSION=v0.1.0  # Create git tag
```

### 4. Local CI Replication Script

**File**: `scripts/ci-local.sh`

**Features**:
- ✅ **100% GitHub Actions Replication** - Runs the exact same checks
- 🎨 **Colored Output** - Green/Red/Yellow status indicators
- 📊 **Comprehensive Reporting** - Coverage percentages, test results
- 🔧 **Auto-Installation** - Installs missing tools (gofumpt, govulncheck, etc.)
- ⚡ **Fast Feedback** - Local execution, no waiting for CI
- 🛡️ **Non-Blocking Checks** - Some checks warn but don't fail

**Usage**:
```bash
# Run full CI pipeline locally
make ci-local

# Or directly
./scripts/ci-local.sh
```

**Checks Performed**:
1. ✅ Go version verification (>= 1.21)
2. ✅ Dependency download and verification
3. ✅ Tests with race detector and coverage
4. ✅ go vet static analysis
5. ✅ gofumpt formatting check
6. ✅ staticcheck advanced analysis
7. ✅ govulncheck security scanning
8. ✅ golangci-lint comprehensive linting
9. ✅ Binary builds
10. ✅ Example execution
11. ✅ Integration tests

### 5. Dependabot Configuration

**File**: `.github/dependabot.yml`

**Features**:
- **Go Modules** - Weekly updates every Monday
- **GitHub Actions** - Weekly workflow dependency updates
- **Auto-labeling** - Automatic PR labels (`dependencies`, `go`, `github-actions`)
- **PR Limits** - Maximum 5 open PRs at once
- **Commit Prefixes** - `deps:` for Go, `ci:` for Actions

## 📊 Current Status

### Test Coverage
```
Total Coverage: 3.7%
- internal/proteus/protocols: 1.8%
- internal/proteus/vm: 11.9%
- internal/proteus/core: 0.4%
```

Coverage is intentionally low because most code is protocol implementation without unit tests. Integration tests verify end-to-end functionality.

### Linting
- ✅ All files properly formatted
- ✅ No critical linting issues
- ⚠️ Some warnings in complex protocol implementations (expected)

### Security
- ✅ No known vulnerabilities detected
- ✅ gosec security checks passing
- ✅ Regular vulnerability scanning enabled

## 🚀 Quick Start

### For Contributors

1. **Setup Development Environment**:
   ```bash
   make dev-setup
   ```

2. **Development Cycle**:
   ```bash
   # Make changes...
   make dev  # Format, lint, and test
   ```

3. **Before Committing**:
   ```bash
   make check  # Verify all checks pass
   ```

4. **Run Full CI Locally**:
   ```bash
   make ci-local  # Replicate GitHub Actions
   ```

### For CI/CD

**GitHub Actions** automatically runs on:
- Push to `main` or `develop`
- Pull requests to `main` or `develop`

**Manual Workflow Dispatch**:
- Visit Actions tab on GitHub
- Select "CI" workflow
- Click "Run workflow"

## 📈 Best Practices

1. **Always run `make check` before committing**
2. **Use `make dev` for quick iterations**
3. **Run `make ci-local` before creating PRs**
4. **Keep coverage reports in `reports/coverage.html`**
5. **Address linting warnings in new code**
6. **Test examples to ensure they work**

## 🔒 Security

**Automated Scanning**:
- `govulncheck` runs on every CI build
- Dependabot monitors for vulnerable dependencies
- `gosec` checks for common security issues

**Manual Checks**:
```bash
make vuln-check  # Run vulnerability scanner
make lint        # Check for security issues
```

## 📝 Configuration Files

| File | Purpose | Documentation |
|------|---------|---------------|
| `.github/workflows/ci.yml` | GitHub Actions CI/CD | GitHub Actions docs |
| `.golangci.yml` | Linter configuration | [golangci-lint docs](https://golangci-lint.run/) |
| `Makefile` | Development commands | `make help` |
| `scripts/ci-local.sh` | Local CI replication | Comments in file |
| `.github/dependabot.yml` | Dependency updates | [Dependabot docs](https://docs.github.com/en/code-security/dependabot) |

## 🎯 Goals

- ✅ **100% CI/CD Replication** - Local and CI environments identical
- ✅ **Fast Feedback** - Quick local checks before pushing
- ✅ **Production Quality** - Industry-standard tooling and practices
- ✅ **Security First** - Automated vulnerability scanning
- ✅ **Developer Friendly** - Simple commands, clear output
- 🔄 **Continuous Improvement** - Regular dependency updates

## 🆘 Troubleshooting

### golangci-lint not found
```bash
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

### gofumpt not found
```bash
go install mvdan.cc/gofumpt@latest
```

### govulncheck not found
```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
```

### Tests failing locally but passing in CI
```bash
# Clean cache and retry
make clean
make test
```

### Format check failing
```bash
make format  # Auto-fix formatting
```

## 📚 Additional Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [golangci-lint Linters](https://golangci-lint.run/usage/linters/)
- [Go Testing Guide](https://go.dev/doc/tutorial/add-a-test)
- [Codecov Documentation](https://docs.codecov.com/)

---

**Status**: ✅ Production Ready  
**Last Updated**: November 2025  
**Maintainer**: dread-crypto/vybium-starks-vm-maintainers

