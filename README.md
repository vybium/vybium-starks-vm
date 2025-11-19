# Vybium STARKs VM

[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Report Card](https://goreportcard.com/badge/github.com/vybium/vybium-starks-vm)](https://goreportcard.com/report/github.com/vybium/vybium-starks-vm)

A virtual machine with Algebraic Execution Tables (AET) and Arithmetic Intermediate Representations (AIR) for use in combination with a STARK proof system.

## Overview

**Vybium STARKs VM** is a Turing-complete virtual machine that generates STARK proofs of correct program execution. The VM supports recursive verification, allowing it to efficiently verify STARKs produced when running Vybium STARKs VM programs.

Key Features:
- Stack-based Instruction Set Architecture (ISA) with 47 instructions
- Algebraic Execution Tables (AET) for execution traces
- Arithmetic Intermediate Representations (AIR) for constraints
- FRI-based STARK proof generation and verification
- Support for zero-knowledge proofs with secret inputs
- Recursive proof verification capabilities

## Getting Started

### Installation

```bash
go get github.com/vybium/vybium-starks-vm
go get github.com/vybium/vybium-crypto
```

### Quick Example: Execute a Program

```go
package main

import (
    "fmt"
    "github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
    "github.com/vybium/vybium-starks-vm/internal/proteus/vm"
)

func main() {
    // Create a program: compute 2 + 3
    program := vm.NewProgram()

    // Push 2 onto stack
    val2 := field.New(2)
    push2, _ := vm.NewEncodedInstruction(vm.Push, &val2)
    program.AddInstruction(push2)

    // Push 3 onto stack
    val3 := field.New(3)
    push3, _ := vm.NewEncodedInstruction(vm.Push, &val3)
    program.AddInstruction(push3)

    // Add the top two stack elements
    add, _ := vm.NewEncodedInstruction(vm.Add, nil)
    program.AddInstruction(add)

    // Halt execution
    halt, _ := vm.NewEncodedInstruction(vm.Halt, nil)
    program.AddInstruction(halt)

    // Execute the program
    vmState := vm.NewVMState(program, nil, nil)
    aet, _ := vmState.ExecuteAndTrace()

    // Check the result
    result := vmState.Stack[vmState.StackPointer-1]
    fmt.Printf("2 + 3 = %v\n", result) // Output: 2 + 3 = 5
    fmt.Printf("Executed in %d cycles\n", aet.Height)
}
```

### Generate and Verify a STARK Proof

```go
package main

import (
    "fmt"
    "math/big"
    "github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
    "github.com/vybium/vybium-starks-vm/internal/proteus/core"
    "github.com/vybium/vybium-starks-vm/internal/proteus/protocols"
    "github.com/vybium/vybium-starks-vm/internal/proteus/vm"
)

func main() {
    // 1. Create program
    program := vm.NewProgram()
    val := field.New(100)
    push, _ := vm.NewEncodedInstruction(vm.Push, &val)
    program.AddInstruction(push)
    halt, _ := vm.NewEncodedInstruction(vm.Halt, nil)
    program.AddInstruction(halt)

    // 2. Execute program and generate trace
    vmState := vm.NewVMState(program, nil, nil)
    aet, _ := vmState.ExecuteAndTrace()

    // 3. Setup Goldilocks field
    goldilocksP := new(big.Int)
    goldilocksP.SetString("18446744069414584321", 10)
    goldilocksField, _ := core.NewField(goldilocksP)

    // 4. Generate STARK proof
    prover, _ := protocols.NewSTARKProver(goldilocksField, 128)
    proof, _ := prover.Prove(aet)

    // 5. Create claim
    claim := protocols.NewClaim(program.Encode())

    // 6. Verify proof
    verifier, _ := protocols.NewSTARKVerifier(goldilocksField, 128)
    valid := verifier.Verify(claim, proof)

    fmt.Printf("Proof valid: %v\n", valid)
}
```

## Architecture

### Instruction Set Architecture (ISA)

The VM has 47 instructions organized into categories:

**Stack Operations**: Push, Pop, Dup, Swap

**Arithmetic Operations**: Add, Mul, Invert, Div, Neg, Lt

**Control Flow**: Call, Return, Recurse, Skiz, Assert, Halt

**Memory Access**: ReadMem, WriteMem

**Hashing**: Hash, SpongeInit, SpongeAbsorb, SpongeSqueeze

**U32 Operations**: Split, Lt, And, Xor, Log2Floor, Pow, Div, PopCount

**Extension Field Operations**: XxAdd, XxMul, XInvert, XbMul, ReadIo, WriteIo

**Non-Determinism**: Divine (for secret inputs)

### Multi-Table Architecture

The VM uses multiple execution tables:

- **Processor Table**: Main execution trace
- **OpStack Table**: Stack operations
- **RAM Table**: Memory access
- **JumpStack Table**: Call/return tracking
- **Hash Table**: Hash function invocations
- **U32 Table**: 32-bit arithmetic
- **Cascade Table**: Lookup argument
- **Lookup Table**: Range checks and lookups

### STARK Proof System

The proof system consists of:

1. **Algebraic Execution Table (AET)**: Complete execution trace
2. **AIR Constraints**: Polynomial constraints over the trace
3. **FRI Protocol**: Low-degree testing
4. **Merkle Commitments**: Cryptographic binding of trace data
5. **Fiat-Shamir**: Non-interactive challenge generation

## Use Cases

### 1. Verifiable Computation

Prove that a computation was executed correctly without revealing inputs:

```go
// Execute computation
result := ComputeFactorial(5)

// Generate proof
proof := GenerateProof(program, inputs)

// Anyone can verify without re-execution
valid := VerifyProof(claim, proof)
```

### 2. Zero-Knowledge Proofs

Prove knowledge of a secret without revealing it:

```go
// Secret input via Divine instruction
secretInput := []field.Element{mySecret}
vmState := vm.NewVMState(program, nil, secretInput)

// Generate proof (secret not included)
proof := prover.Prove(aet)

// Verifier learns nothing about the secret
valid := verifier.Verify(claim, proof)
```

### 3. Recursive Proof Composition

Chain proofs together for scalability:

```go
// Verify proof1 inside VM
program := CreateVerifierProgram(proof1)
vmState := vm.NewVMState(program, nil, nil)
aet, _ := vmState.ExecuteAndTrace()

// Generate proof2 of verifying proof1
proof2 := prover.Prove(aet)

// proof2 proves that proof1 is valid
```

### 4. Privacy-Preserving Applications

- Private transactions in blockchains
- Confidential smart contracts
- Anonymous credentials
- Private voting systems

## Project Structure

```
vybium-starks-vm/
├── internal/proteus/
│   ├── vm/              # Virtual machine implementation
│   │   ├── instructions.go  # ISA definitions
│   │   ├── state.go         # VM state and execution
│   │   └── aet.go           # Algebraic execution tables
│   ├── protocols/       # STARK protocols
│   │   ├── stark.go         # Main STARK prover/verifier
│   │   ├── fri.go           # FRI protocol
│   │   ├── air.go           # AIR constraints
│   │   └── domains.go       # Arithmetic domains
│   ├── core/            # Core data structures
│   └── utils/           # Utilities
├── pkg/vybium-starks-vm/  # Public API
├── examples/            # Example programs
├── tests/               # Integration tests
└── cmd/                 # Command-line tools
```

## Examples

The `examples/` directory contains complete working examples:

1. **01_basic_execution** - Simple VM execution
2. **02_simple_proof** - Generate and verify a STARK proof
3. **03_add_numbers** - Multi-step arithmetic
4. **04_secret_input** - Zero-knowledge with Divine
5. **05_stack_operations** - Stack manipulation
6. **06_arithmetic** - Complex arithmetic operations
7. **07_factorial** - Recursive computation

Run an example:

```bash
cd examples/01_basic_execution
go run main.go
```

## Command-Line Tools

### vybium-starks-vm-prover

Generate and verify STARK proofs from program files:

```bash
# Generate proof
vybium-starks-vm-prover --program program.json --security 128 --output proof.bin

# Verify proof
vybium-starks-vm-prover --verify --claim claim.json --proof proof.bin
```

## Testing

```bash
# Run all tests
go test ./...

# Run integration tests
go test ./tests/integration/...

# Run with coverage
go test -cover ./...

# Run benchmarks
go test -bench=. ./internal/proteus/vm/benchmarks/
```

## Documentation

Full API documentation:

```bash
go doc github.com/vybium/vybium-starks-vm/internal/proteus/vm
go doc github.com/vybium/vybium-starks-vm/internal/proteus/protocols
```

## Security Considerations

- The VM uses constant-time field arithmetic from vybium-crypto
- FRI soundness parameters are configurable based on desired security level
- Zero-knowledge is achieved through the Divine instruction for secret inputs
- Recursive verification enables proof composition and aggregation

## Contributing

Contributions are welcome. Please ensure:

- All tests pass
- Code follows Go style guidelines
- New features include tests and documentation
- Security-critical code is reviewed carefully

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Status

Version: 0.1.0
Status: Production Ready
Last Updated: November 2025

Built for verifiable computation and zero-knowledge proof systems
