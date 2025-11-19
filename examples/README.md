# Vybium STARKs VM Examples

**Comprehensive** standalone example programs demonstrating the complete lifecycle of Vybium STARKs VM execution and zkSTARK proof generation/verification.

## Purpose

These examples serve dual purposes:

1. **User Education**: Learn how to use Vybium STARKs VM and STARK proofs through working code
2. **Implementation Reference**: See best practices for integrating the library into your applications

Most examples demonstrate the **complete workflow**: Program → Execute → Prove → Verify

Related to comprehensive integration tests in `tests/integration/` (CI/CD validation).

## Running Examples

Each example is a standalone Go program in its own directory:

```bash
# Run any example directly
cd examples/01_basic_execution
go run main.go

# Or build and run
go build -o example main.go
./example
```

## Examples Overview

### 1. Basic Execution (`01_basic_execution/`)

**Concepts**: VM creation, program execution, execution trace

Simple program that pushes a value onto the stack and halts. Demonstrates:

- Creating a VM instance
- Defining a program with instructions
- Executing the program
- Inspecting the execution trace

**Difficulty**: ⭐ Beginner

```bash
cd 01_basic_execution && go run main.go
```

### 2. Simple Proof (`02_simple_proof/`)

**Concepts**: Prover, verifier, proof generation, verification

Complete proof lifecycle from execution to verification. Demonstrates:

- Configuring security parameters
- Creating prover and verifier
- Generating a STARK proof
- Verifying the proof
- Checking verification results

**Difficulty**: ⭐⭐ Intermediate

```bash
cd 02_simple_proof && go run main.go
```

### 3. Add Two Numbers - COMPREHENSIVE (`03_add_numbers/`)

**Concepts**: Public I/O, ReadIo, WriteIo, claims, **full proof cycle**

**COMPREHENSIVE**: Complete proof lifecycle with public I/O (17 + 25 = 42). Demonstrates:

- Reading public inputs with `ReadIo`
- Performing arithmetic operations
- Writing public outputs with `WriteIo`
- Creating claims with specific inputs/outputs
- **Complete STARK proof generation**
- **Cryptographic verification**

**Related test**: `tests/integration/01_basic_proof_test.go`

**Difficulty**: ⭐⭐ Intermediate

```bash
cd 03_add_numbers && go run main.go
```

### 4. Secret Inputs - COMPREHENSIVE (`04_secret_input/`)

**Concepts**: Zero-knowledge, Divine, privacy-preserving proofs, **full ZK proof cycle**

**COMPREHENSIVE**: Privacy-preserving computation with complete zero-knowledge proof. Demonstrates:

- Using `Divine` for secret inputs
- Zero-knowledge property of proofs
- Proving statements without revealing witnesses (x² = 25, without revealing x)
- **Complete ZK-STARK proof generation**
- **Privacy analysis and verification**
- The power of zkSTARKs for privacy

**Related test**: `tests/integration/02_privacy_proof_test.go`

**Difficulty**: ⭐⭐⭐ Advanced

```bash
cd 04_secret_input && go run main.go
```

### 5. Stack Operations (`05_stack_operations/`)

**Concepts**: Stack manipulation, Dup, Swap, Pop

Comprehensive demonstration of stack-based operations. Demonstrates:

- Stack manipulation instructions
- Dup (duplicate), Swap, Pop operations
- Complex stack state tracking
- Multi-step stack transformations

**Difficulty**: ⭐⭐ Intermediate

```bash
cd 05_stack_operations && go run main.go
```

### 6. Field Arithmetic (`06_arithmetic/`)

**Concepts**: Goldilocks field, modular arithmetic, field operations

Field arithmetic operations in the Goldilocks prime field. Demonstrates:

- Addition, multiplication, inversion in prime field
- Modular arithmetic properties
- Field element creation and manipulation
- Mathematical foundations of STARKs

**Difficulty**: ⭐⭐ Intermediate

```bash
cd 06_arithmetic && go run main.go
```

### 7. Factorial Computation - COMPREHENSIVE (`07_factorial/`)

**Concepts**: Complex computation, multiple operations, **full proof cycle**

**COMPREHENSIVE**: Compute 5! = 120 with complete cryptographic proof. Demonstrates:

- Complex iterative computation (multiple multiplications)
- Proving correctness of multi-step algorithms
- **Complete STARK proof generation**
- **Verifiable computation use case**
- How proof size relates to computation complexity

**Related test**: `tests/integration/03_factorial_proof_test.go`

**Difficulty**: ⭐⭐⭐ Advanced

```bash
cd 07_factorial && go run main.go
```

## Installation

Make sure you have the required dependencies:

```bash
# From the zkstarks root directory
go mod download
go mod tidy
```

## Common Patterns

### Creating a VM

```go
vmConfig := &vybiumstarksvm.VMConfig{
    FieldModulus:       "18446744069414584321", // Goldilocks prime
    ProgramAttestation: true,
    PermutationChecks:  true,
    LookupTables:       true,
}
vm, err := vybiumstarksvm.NewVM(vmConfig)
```

### Creating a Program

```go
val := field.New(42)
program := &vybiumstarksvm.Program{
    Instructions: []vybiumstarksvm.Instruction{
        {Opcode: 1, Argument: &val}, // Push(42)
        {Opcode: 0, Argument: nil},  // Halt
    },
}
```

### Generating a Proof

```go
config := &vybiumstarksvm.Config{
    FieldModulus:     "18446744069414584321",
    SecurityLevel:    128,
    FRIQueries:       80,
    // ... other parameters
}

prover, _ := vybiumstarksvm.NewProver(config)
proof, _ := prover.GenerateProof(trace)
```

### Verifying a Proof

```go
verifier, _ := vybiumstarksvm.NewVerifier(config)
claim := &vybiumstarksvm.Claim{
    ProgramDigest: programDigest,
    PublicInput:   publicInput,
    PublicOutput:  publicOutput,
}
result, _ := verifier.VerifyProof(proof, claim)
```

## Instruction Opcodes Quick Reference

| Opcode | Instruction | Description                                 |
| ------ | ----------- | ------------------------------------------- |
| 0      | Halt        | Stop execution                              |
| 1      | Push(x)     | Push value onto stack                       |
| 2      | Assert      | Assert top of stack is 1                    |
| 3      | ReadIo(n)   | Read n values from public input             |
| 4      | WriteIo(n)  | Write n values to public output             |
| 5      | Pop(n)      | Pop n values from stack                     |
| 9      | Divine(n)   | Read n secret (non-deterministic) values    |
| 26     | Eq          | Test equality of top two stack values       |
| 33     | Dup(i)      | Duplicate stack element at position i       |
| 41     | Swap(i)     | Swap top element with element at position i |
| 42     | Add         | Add top two stack values                    |
| 43     | Mul         | Multiply top two stack values               |

For the complete instruction set, see [USAGE_GUIDE.md](../USAGE_GUIDE.md).

## Performance Notes

- **Proof generation** can take 1-10 seconds depending on program complexity
- **Verification** is typically much faster (milliseconds)
- Larger programs with more cycles will take longer to prove
- Security level affects proof size and generation time

## Examples vs Tests

| Purpose           | Examples (`examples/`)      | Integration Tests (`tests/integration/`) |
| ----------------- | --------------------------- | ---------------------------------------- |
| **Audience**      | Users, developers, learners | CI/CD, automated validation              |
| **Style**         | Educational, commented      | Comprehensive assertions                 |
| **Execution**     | `go run`                    | `go test`                                |
| **Scope**         | Full proof cycles           | Edge cases, error handling               |
| **Documentation** | User-facing                 | Internal validation                      |

Both demonstrate the same capabilities but with different goals. Examples are for learning; tests are for verification.

## Next Steps

After running these examples:

1. **Modify the programs** - Change instructions, inputs, or outputs
2. **Experiment with security levels** - Try 128-bit, 160-bit, 192-bit
3. **Create your own programs** - Build custom computations
4. **Read the documentation** - See [USAGE_GUIDE.md](../USAGE_GUIDE.md) for more details
5. **Explore the tests** - Check `tests/integration/` for comprehensive test coverage
6. **Run all examples** - Use `./run_all.sh` in the examples directory

## Troubleshooting

### "Failed to create VM"

- Ensure the field modulus is correct: `"18446744069414584321"`
- Check that all dependencies are installed

### "Proof generation failed"

- Verify FRIQueries is sufficient for security level (≥ SecurityLevel/3)
- Ensure trace length is adequate for program complexity

### "Verification failed"

- Double-check that claim matches the execution (inputs, outputs, program digest)
- Ensure prover and verifier use the same configuration

## Additional Resources

- [USAGE_GUIDE.md](../USAGE_GUIDE.md) - Complete usage documentation
- [README.md](../README.md) - Project overview and architecture
- [Integration Tests](../tests/integration/) - More complex examples
- [Vybium-Crypto](https://github.com/vybium/vybium-crypto) - Cryptographic primitives library

---

**Happy proving! 🚀**
