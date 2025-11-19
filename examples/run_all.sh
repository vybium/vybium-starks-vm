#!/bin/bash

# Script to run all Vybium STARKs VM examples

set -e

EXAMPLES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$EXAMPLES_DIR/.."

echo "========================================"
echo "Running All Vybium STARKs VM Examples"
echo "========================================"
echo

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

run_example() {
    local name="$1"
    local dir="$2"
    
    echo -e "${BLUE}=== $name ===${NC}"
    cd "$EXAMPLES_DIR/$dir"
    
    if [ ! -f "example" ]; then
        echo "Building..."
        go build -o example main.go
    fi
    
    ./example
    echo -e "${GREEN}✓ Completed${NC}"
    echo
}

# Run all examples
run_example "Example 1: Basic Execution" "01_basic_execution"
run_example "Example 2: Simple Proof" "02_simple_proof"
run_example "Example 3: Add Numbers (COMPREHENSIVE)" "03_add_numbers"
run_example "Example 4: Secret Input (COMPREHENSIVE)" "04_secret_input"
run_example "Example 5: Stack Operations" "05_stack_operations"
run_example "Example 6: Arithmetic" "06_arithmetic"
run_example "Example 7: Factorial (COMPREHENSIVE)" "07_factorial"

echo "========================================"
echo -e "${GREEN}All examples completed successfully!${NC}"
echo "========================================"

