#!/bin/bash

# Comprehensive Test Runner for Proteus zkSTARK VM
# This script runs all tests in the correct order and provides a summary

set -e

echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║                    🧪 COMPREHENSIVE TEST SUITE 🧪                        ║"
echo "║                        Proteus zkSTARK VM                               ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to run tests and count results
run_test_suite() {
    local suite_name="$1"
    local test_path="$2"
    local description="$3"

    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Running: $suite_name${NC}"
    echo -e "${BLUE}Path: $test_path${NC}"
    echo -e "${BLUE}Description: $description${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    if go test -v "$test_path" 2>&1; then
        echo -e "${GREEN}✅ $suite_name PASSED${NC}"
        ((PASSED_TESTS++))
    else
        echo -e "${RED}❌ $suite_name FAILED${NC}"
        ((FAILED_TESTS++))
    fi

    ((TOTAL_TESTS++))
    echo ""
}

# Function to run benchmarks
run_benchmark_suite() {
    local suite_name="$1"
    local test_path="$2"

    echo -e "${YELLOW}🏃 Running Benchmarks: $suite_name${NC}"
    echo -e "${YELLOW}Path: $test_path${NC}"

    if go test -bench=. -benchmem "$test_path" 2>&1; then
        echo -e "${GREEN}✅ $suite_name BENCHMARKS PASSED${NC}"
    else
        echo -e "${RED}❌ $suite_name BENCHMARKS FAILED${NC}"
    fi

    echo ""
}

# Function to run fuzz tests
run_fuzz_suite() {
    local suite_name="$1"
    local test_path="$2"

    echo -e "${YELLOW}🔍 Running Fuzz Tests: $suite_name${NC}"
    echo -e "${YELLOW}Path: $test_path${NC}"

    if go test -fuzz=. -fuzztime=10s "$test_path" 2>&1; then
        echo -e "${GREEN}✅ $suite_name FUZZ TESTS PASSED${NC}"
    else
        echo -e "${RED}❌ $suite_name FUZZ TESTS FAILED${NC}"
    fi

    echo ""
}

echo -e "${BLUE}Starting comprehensive test suite...${NC}"
echo ""

# ============================================================================
# VYBIUM-CRYPTO TESTS
# ============================================================================

echo -e "${BLUE}🔐 VYBIUM-CRYPTO CRYPTOGRAPHIC LIBRARY TESTS${NC}"
echo ""

# Field Arithmetic Tests
run_test_suite "Field Arithmetic" "../vybium-crypto/pkg/vybium-crypto/field" "BFieldElement operations with Montgomery arithmetic"

# Field Property Tests
run_test_suite "Field Properties" "../vybium-crypto/pkg/vybium-crypto/field" "Field arithmetic properties (commutativity, associativity, etc.)"

# Field Fuzz Tests
run_fuzz_suite "Field Fuzz" "../vybium-crypto/pkg/vybium-crypto/field"

# Hash Function Tests
run_test_suite "Tip5 Hash" "../vybium-crypto/pkg/vybium-crypto/hash" "Tip5 hash function tests"

run_test_suite "Poseidon Hash" "../vybium-crypto/pkg/vybium-crypto/hash" "Poseidon hash function tests"

# Hash Property Tests
run_test_suite "Hash Properties" "../vybium-crypto/pkg/vybium-crypto/hash" "Hash function properties (deterministic, avalanche effect, etc.)"

# Polynomial Tests
run_test_suite "Polynomial Operations" "../vybium-crypto/pkg/vybium-crypto/polynomial" "Polynomial arithmetic and NTT"

# Polynomial Property Tests
run_test_suite "Polynomial Properties" "../vybium-crypto/pkg/vybium-crypto/polynomial" "Polynomial operation properties"

# NTT Tests
run_test_suite "NTT Operations" "../vybium-crypto/pkg/vybium-crypto/ntt" "Number Theoretic Transform"

# Merkle Tree Tests
run_test_suite "Merkle Trees" "../vybium-crypto/pkg/vybium-crypto/merkle" "Merkle tree operations and proofs"

# Merkle Property Tests
run_test_suite "Merkle Properties" "../vybium-crypto/pkg/vybium-crypto/merkle" "Merkle tree properties and consistency"

# Vybium-Crypto Benchmarks
run_benchmark_suite "Vybium-Crypto" "../vybium-crypto/pkg/vybium-crypto/field"
run_benchmark_suite "Vybium-Crypto" "../vybium-crypto/pkg/vybium-crypto/hash"
run_benchmark_suite "Vybium-Crypto" "../vybium-crypto/pkg/vybium-crypto/polynomial"
run_benchmark_suite "Vybium-Crypto" "../vybium-crypto/pkg/vybium-crypto/merkle"

# ============================================================================
# ZKSTARKS TESTS
# ============================================================================

echo -e "${BLUE}🚀 ZKSTARKS VM TESTS${NC}"
echo ""

# Core Field Tests
run_test_suite "Core Field Operations" "./internal/proteus/core" "Field arithmetic and polynomial operations"

# Core Property Tests
run_test_suite "Core Properties" "./internal/proteus/core" "Field arithmetic properties"

# Core Fuzz Tests
run_fuzz_suite "Core Fuzz" "./internal/proteus/core"

# VM Tests
run_test_suite "VM State" "./internal/proteus/vm" "Virtual machine state operations"

run_test_suite "VM Instructions" "./internal/proteus/vm" "Virtual machine instruction execution"

# VM Integration Tests
run_test_suite "Integration Tests" "./tests/integration" "End-to-end proof generation tests"

# Protocol Tests
run_test_suite "STARK Protocols" "./internal/proteus/protocols" "STARK proof generation and verification"

# Example Tests
run_test_suite "Examples" "./examples" "Example programs and demonstrations"

# Public API Tests
run_test_suite "Public API" "./pkg/vybium-starks-vm" "Public API functionality"

# VM Benchmarks
run_benchmark_suite "VM Benchmarks" "./internal/proteus/vm/benchmarks"

# ============================================================================
# TEST SUMMARY
# ============================================================================

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                           📊 TEST SUMMARY 📊                            ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${BLUE}Total Test Suites: $TOTAL_TESTS${NC}"
echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
echo -e "${RED}Failed: $FAILED_TESTS${NC}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}🎉 ALL TESTS PASSED! 🎉${NC}"
    echo -e "${GREEN}The codebase is ready for production!${NC}"
    exit 0
else
    echo -e "${RED}❌ SOME TESTS FAILED${NC}"
    echo -e "${RED}Please review the failed tests above.${NC}"
    exit 1
fi

