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

// Example 3: Add Two Numbers with Public I/O - COMPREHENSIVE
// Demonstrates: ReadIo, Add, WriteIo, AND full STARK proof generation/verification
// Related test: tests/integration/01_basic_proof_test.go

func main() {
	// Catch panics and provide clear error message
	defer func() {
		if r := recover(); r != nil {
			log.Fatalf("\n❌ FATAL ERROR (panic): %v\n", r)
		}
	}()

	fmt.Println("=== Vybium STARKs VM Example 3: Add Two Numbers ===")

	// Create program: Read two inputs, add them, output result
	program := vm.NewProgram()

	// ReadIo(1) - read first input
	one := field.New(1)
	readIo1, _ := vm.NewEncodedInstruction(vm.ReadIo, &one)
	program.AddInstruction(readIo1)

	// ReadIo(1) - read second input
	readIo2, _ := vm.NewEncodedInstruction(vm.ReadIo, &one)
	program.AddInstruction(readIo2)

	// Add - add top two values
	add, _ := vm.NewEncodedInstruction(vm.Add, nil)
	program.AddInstruction(add)

	// WriteIo(1) - output result
	writeIo, _ := vm.NewEncodedInstruction(vm.WriteIo, &one)
	program.AddInstruction(writeIo)

	// Halt
	halt, _ := vm.NewEncodedInstruction(vm.Halt, nil)
	program.AddInstruction(halt)

	// Define inputs
	a := field.New(17)
	b := field.New(25)
	publicInput := []field.Element{a, b}

	fmt.Printf("Computing: %s + %s\n\n", a.String(), b.String())

	// Execute program
	vmState := vm.NewVMState(program, publicInput, nil)

	aet, err := vmState.ExecuteAndTrace()
	if err != nil {
		log.Fatalf("Execution failed: %v", err)
	}

	fmt.Printf("✓ Program executed: %d cycles\n", vmState.CycleCount)
	fmt.Printf("✓ Public output: %d elements\n", len(vmState.PublicOutput))

	// Check result (skip first 5 elements - program digest)
	if len(vmState.PublicOutput) > 5 {
		result := vmState.PublicOutput[len(vmState.PublicOutput)-1]
		expected := field.New(42)
		fmt.Printf("\nResult: %s\n", result.String())
		if result.Equal(expected) {
			fmt.Println("✅ Computation correct: 17 + 25 = 42")
		}
	}

	fmt.Printf("\nAET generated: %d rows (padded: %d)\n", aet.Height, aet.PaddedHeight)

	// === PROOF GENERATION ===
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("GENERATING STARK PROOF")
	fmt.Println(strings.Repeat("=", 60))

	// Step 1: Create STARK parameters
	fmt.Println("\n[1/5] Creating STARK parameters...")
	params := protocols.DefaultSTARKParameters()
	if err := params.Validate(); err != nil {
		log.Fatalf("Invalid parameters: %v", err)
	}
	fmt.Printf("✓ Parameters validated (Security: %d-bit)\n", params.SecurityLevel)

	// Step 2: Create prover
	fmt.Println("\n[2/5] Creating prover...")
	prover, err := protocols.NewProver(params)
	if err != nil {
		log.Fatalf("Failed to create prover: %v", err)
	}
	fmt.Println("✓ Prover initialized")

	// Step 3: Create claim
	fmt.Println("\n[3/5] Creating claim...")
	claim := protocols.NewClaim(aet.ProgramDigest[:])
	claim = claim.WithInput(publicInput).WithOutput(vmState.PublicOutput)
	if err := claim.Validate(); err != nil {
		log.Fatalf("Invalid claim: %v", err)
	}
	fmt.Printf("✓ Claim created:\n")
	fmt.Printf("  - Program: %x...\n", aet.ProgramDigest[:4])
	fmt.Printf("  - Input: [%s, %s]\n", a.String(), b.String())
	fmt.Printf("  - Output: %d elements\n", len(vmState.PublicOutput))

	// Step 4: Generate proof
	fmt.Println("\n[4/5] Generating STARK proof (this may take a moment)...")
	proof, err := prover.Prove(claim, aet)
	if err != nil {
		log.Fatalf("Proof generation failed: %v", err)
	}
	fmt.Printf("✓ Proof generated: %d bytes\n", proof.Size())

	// Step 5: Verify proof
	fmt.Println("\n[5/5] Verifying proof...")
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

	// === VALIDATE RESULTS BEFORE DECLARING SUCCESS ===
	// Double-check the computation result
	if len(vmState.PublicOutput) < 6 {
		log.Fatalf("❌ VALIDATION FAILED: Expected at least 6 output elements, got %d", len(vmState.PublicOutput))
	}
	finalResult := vmState.PublicOutput[len(vmState.PublicOutput)-1]
	expected := field.New(42)
	if !finalResult.Equal(expected) {
		log.Fatalf("❌ VALIDATION FAILED: Expected result 42, got %s", finalResult.String())
	}

	// === ONLY REACHED IF ALL OPERATIONS SUCCEEDED ===
	// If we reach here, ALL of the following succeeded:
	// 1. Program execution ✓
	// 2. Correct computation (17 + 25 = 42) ✓
	// 3. AET generation ✓
	// 4. Proof generation ✓
	// 5. Proof verification ✓

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("✅ ALL OPERATIONS SUCCESSFUL!")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("\n🎉 Complete workflow demonstrated:")
	fmt.Println("   ✓ Program with public I/O (ReadIo, WriteIo)")
	fmt.Println("   ✓ Execution: 17 + 25 = 42 (result validated)")
	fmt.Println("   ✓ Algebraic Execution Trace generated")
	fmt.Println("   ✓ STARK proof generated")
	fmt.Println("   ✓ Proof cryptographically verified")
	fmt.Println("\n💡 This proves the computation was done correctly!")
	fmt.Println("   (If any step failed, execution would have stopped)")
}
