package main

import (
	"fmt"
	"log"
	"math/big"
	"strings"

	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/protocols"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/vm"
)

// Example 4: Secret Inputs with Divine - COMPREHENSIVE
// Demonstrates: Privacy-preserving computation AND full zero-knowledge STARK proof
// Related test: tests/integration/02_privacy_proof_test.go

func main() {
	// Catch panics and provide clear error message
	defer func() {
		if r := recover(); r != nil {
			log.Fatalf("\n❌ FATAL ERROR (panic): %v\n", r)
		}
	}()

	fmt.Println("=== Vybium STARKs VM Example 4: Secret Inputs (Zero-Knowledge) ===")
	fmt.Println("Scenario: Prove x² = 25 WITHOUT revealing x!")

	// Create program: Divine(1), Dup(0), Mul, Push(25), Eq, Assert, Halt
	program := vm.NewProgram()

	// Divine(1) - read secret input
	one := field.New(1)
	divine, _ := vm.NewEncodedInstruction(vm.Divine, &one)
	program.AddInstruction(divine)

	// Dup(0) - duplicate top of stack
	zero := field.New(0)
	dup, _ := vm.NewEncodedInstruction(vm.Dup, &zero)
	program.AddInstruction(dup)

	// Mul - multiply (x * x)
	mul, _ := vm.NewEncodedInstruction(vm.Mul, nil)
	program.AddInstruction(mul)

	// Push(25) - expected result
	val25 := field.New(25)
	push25, _ := vm.NewEncodedInstruction(vm.Push, &val25)
	program.AddInstruction(push25)

	// Eq - check equality
	eq, _ := vm.NewEncodedInstruction(vm.Eq, nil)
	program.AddInstruction(eq)

	// Assert - must be 1 (true)
	assert, _ := vm.NewEncodedInstruction(vm.Assert, nil)
	program.AddInstruction(assert)

	// Halt
	halt, _ := vm.NewEncodedInstruction(vm.Halt, nil)
	program.AddInstruction(halt)

	// Secret: x = 5 (NOT revealed in proof!)
	secretX := field.New(5)
	secretInput := []field.Element{secretX}

	fmt.Printf("Secret value (known only to prover): x = %s\n", secretX.String())
	fmt.Println("Public statement: x² = 25")
	fmt.Println()

	// Execute with secret input
	vmState := vm.NewVMState(program, nil, secretInput)

	aet, err := vmState.ExecuteAndTrace()
	if err != nil {
		log.Fatalf("Execution failed: %v", err)
	}

	fmt.Printf("✓ Program executed: %d cycles\n", vmState.CycleCount)
	fmt.Println("✓ Assertion passed: x² = 25 is correct")

	// === ZERO-KNOWLEDGE PROOF GENERATION ===
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("GENERATING ZERO-KNOWLEDGE STARK PROOF")
	fmt.Println(strings.Repeat("=", 60))

	fmt.Println("\n[1/5] Creating STARK parameters...")
	params := protocols.DefaultSTARKParameters()
	if err := params.Validate(); err != nil {
		log.Fatalf("Invalid parameters: %v", err)
	}
	fmt.Printf("✓ Parameters validated (Security: %d-bit)\n", params.SecurityLevel)

	fmt.Println("\n[2/5] Creating prover...")
	prover, err := protocols.NewProver(params)
	if err != nil {
		log.Fatalf("Failed to create prover: %v", err)
	}
	fmt.Println("✓ Prover initialized")

	fmt.Println("\n[3/5] Creating claim (WITHOUT secret input)...")
	claim := protocols.NewClaim(aet.ProgramDigest[:])
	// NOTE: Secret input is NOT included in the claim!
	claim = claim.WithInput(nil).WithOutput(vmState.PublicOutput)
	if err := claim.Validate(); err != nil {
		log.Fatalf("Invalid claim: %v", err)
	}
	fmt.Println("✓ Claim created:")
	fmt.Printf("  - Program digest: %x...\n", aet.ProgramDigest[:4])
	fmt.Println("  - Public input: NONE")
	fmt.Println("  - Secret input: NOT in claim ✓")
	fmt.Printf("  - Public output: %d elements\n", len(vmState.PublicOutput))

	fmt.Println("\n[4/5] Generating zero-knowledge proof...")
	fmt.Println("    (Proof will NOT reveal the secret value!)")
	proof, err := prover.Prove(claim, aet)
	if err != nil {
		log.Fatalf("Proof generation failed: %v", err)
	}
	fmt.Printf("✓ ZK proof generated: %d bytes\n", proof.Size())

	fmt.Println("\n[5/5] Verifying proof (verifier does NOT know secret)...")
	goldilocksPrime := new(big.Int)
	goldilocksPrime.SetString("18446744069414584321", 10)
	coreField, err := core.NewField(goldilocksPrime)
	if err != nil {
		log.Fatalf("Failed to create field: %v", err)
	}

	verifier, err := protocols.NewVerifier(coreField, params)
	if err != nil {
		log.Fatalf("Failed to create verifier: %v", err)
	}

	err = verifier.Verify(claim, proof)
	if err != nil {
		log.Fatalf("❌ VERIFICATION FAILED: %v", err)
	}

	// === VALIDATE PRIVACY PROPERTIES ===
	// Verify that secret is NOT in the claim
	if claim.PublicInput != nil && len(claim.PublicInput) > 0 {
		log.Fatalf("❌ PRIVACY VIOLATION: Secret input found in public claim!")
	}
	// Verify the assertion passed (program would have failed otherwise, but double-check)
	if !vmState.Halting {
		log.Fatalf("❌ VALIDATION FAILED: Program did not complete (assertion may have failed)")
	}

	// === ONLY REACHED IF ALL OPERATIONS SUCCEEDED ===
	// If we reach here, ALL of the following succeeded:
	// 1. Program execution with secret input ✓
	// 2. Assertion (x² = 25) passed ✓
	// 3. Secret NOT in public claim ✓
	// 4. ZK proof generation ✓
	// 5. Proof verification ✓

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("✅ ZERO-KNOWLEDGE PROOF VERIFIED!")
	fmt.Println(strings.Repeat("=", 60))

	fmt.Println("\n🔒 Zero-Knowledge Property Demonstrated:")
	fmt.Println("   ✓ Prover knows: x = 5")
	fmt.Println("   ✓ Public claim: 'I know x such that x² = 25'")
	fmt.Println("   ✓ Verifier confirmed: Statement is TRUE")
	fmt.Println("   ✓ Verifier learned: NOTHING about x!")
	fmt.Println("   ✓ Privacy validated: Secret NOT in claim")

	fmt.Println("\n📊 What's in the proof?")
	fmt.Println("   • Program digest: YES (public)")
	fmt.Printf("   • Proof size: %d bytes\n", proof.Size())
	fmt.Println("   • Secret value x: NO ✓")
	fmt.Println("   • Computation result: YES (x² = 25)")

	fmt.Println("\n🎯 Privacy Guarantees:")
	fmt.Println("   1. Computational hiding (FRI commitments)")
	fmt.Println("   2. STARK protocol security")
	fmt.Println("   3. No secret in public claim/output (validated above)")

	fmt.Println("\n🎉 This is the power of zero-knowledge proofs!")
	fmt.Println("   Prove you know something without revealing what it is.")
	fmt.Println("\n💡 All operations completed successfully!")
	fmt.Println("   (If any step failed, execution would have stopped)")
}
