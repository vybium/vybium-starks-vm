package main

import (
	"fmt"
	"log"
	"math/big"
	"strings"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/protocols"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/vm"
	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
)

// Example 7: Factorial Computation - COMPREHENSIVE
// Demonstrates: Complex computation with multiple operations AND full STARK proof
// Related test: tests/integration/03_factorial_proof_test.go

func main() {
	// Catch panics and provide clear error message
	defer func() {
		if r := recover(); r != nil {
			log.Fatalf("\n❌ FATAL ERROR (panic): %v\n", r)
		}
	}()

	fmt.Println("=== Vybium STARKs VM Example 7: Factorial Computation ===")
	fmt.Println("Computing: 5! = 1 × 2 × 3 × 4 × 5 = 120")

	// Create program: Compute factorial iteratively
	program := vm.NewProgram()

	// Initialize accumulator = 1
	arg1 := field.New(1)
	push1, err := vm.NewEncodedInstruction(vm.Push, &arg1)
	if err != nil {
		log.Fatalf("Failed to create instruction: %v", err)
	}
	program.AddInstruction(push1)

	// Multiply by 2
	arg2 := field.New(2)
	push2, _ := vm.NewEncodedInstruction(vm.Push, &arg2)
	program.AddInstruction(push2)
	mul1, _ := vm.NewEncodedInstruction(vm.Mul, nil)
	program.AddInstruction(mul1)

	// Multiply by 3
	arg3 := field.New(3)
	push3, _ := vm.NewEncodedInstruction(vm.Push, &arg3)
	program.AddInstruction(push3)
	mul2, _ := vm.NewEncodedInstruction(vm.Mul, nil)
	program.AddInstruction(mul2)

	// Multiply by 4
	arg4 := field.New(4)
	push4, _ := vm.NewEncodedInstruction(vm.Push, &arg4)
	program.AddInstruction(push4)
	mul3, _ := vm.NewEncodedInstruction(vm.Mul, nil)
	program.AddInstruction(mul3)

	// Multiply by 5
	arg5 := field.New(5)
	push5, _ := vm.NewEncodedInstruction(vm.Push, &arg5)
	program.AddInstruction(push5)
	mul4, _ := vm.NewEncodedInstruction(vm.Mul, nil)
	program.AddInstruction(mul4)

	// Write output
	argWriteIo := field.New(1)
	writeIo, _ := vm.NewEncodedInstruction(vm.WriteIo, &argWriteIo)
	program.AddInstruction(writeIo)

	// Halt
	halt, _ := vm.NewEncodedInstruction(vm.Halt, nil)
	program.AddInstruction(halt)

	fmt.Printf("✓ Program created: %d instructions\n", len(program.Instructions))
	fmt.Println("  Instructions: Push(1) → Push(2) → Mul → Push(3) → Mul → ...")
	fmt.Println()

	// === EXECUTION ===
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("EXECUTING PROGRAM")
	fmt.Println(strings.Repeat("=", 60))

	vmState := vm.NewVMState(program, nil, nil)
	aet, err := vmState.ExecuteAndTrace()
	if err != nil {
		log.Fatalf("Execution failed: %v", err)
	}

	fmt.Printf("\n✓ Execution completed: %d cycles\n", vmState.CycleCount)
	fmt.Printf("✓ AET generated: %d rows (padded: %d)\n", aet.Height, aet.PaddedHeight)

	// Verify result
	if len(vmState.PublicOutput) < 6 {
		log.Fatalf("Expected at least 6 elements in output, got %d", len(vmState.PublicOutput))
	}
	result := vmState.PublicOutput[5] // Skip 5 program digest elements
	expected := field.New(120)

	fmt.Printf("\n📊 Result: %s\n", result.String())
	if result.Equal(expected) {
		fmt.Println("✅ Factorial computed correctly: 5! = 120")
	} else {
		log.Fatalf("❌ Expected 120, got %s", result.String())
	}

	// === PROOF GENERATION ===
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("GENERATING STARK PROOF OF CORRECTNESS")
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

	fmt.Println("\n[3/5] Creating claim...")
	claim := protocols.NewClaim(aet.ProgramDigest[:])
	claim = claim.WithInput(nil).WithOutput(vmState.PublicOutput)
	if err := claim.Validate(); err != nil {
		log.Fatalf("Invalid claim: %v", err)
	}
	fmt.Println("✓ Claim created:")
	fmt.Printf("  - Program: %x...\n", aet.ProgramDigest[:4])
	fmt.Printf("  - Output: 5! = %s\n", result.String())

	fmt.Println("\n[4/5] Generating STARK proof...")
	fmt.Println("    (This proves the computation was done correctly)")
	proof, err := prover.Prove(claim, aet)
	if err != nil {
		log.Fatalf("Proof generation failed: %v", err)
	}
	fmt.Printf("✓ Proof generated: %d bytes\n", proof.Size())

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
	// Double-check the factorial result
	if len(vmState.PublicOutput) < 6 {
		log.Fatalf("❌ VALIDATION FAILED: Expected at least 6 output elements, got %d", len(vmState.PublicOutput))
	}
	finalResult := vmState.PublicOutput[5] // Skip 5 program digest elements
	expectedResult := field.New(120)
	if !finalResult.Equal(expectedResult) {
		log.Fatalf("❌ VALIDATION FAILED: Expected 5! = 120, got %s", finalResult.String())
	}

	// === ONLY REACHED IF ALL OPERATIONS SUCCEEDED ===
	// If we reach here, ALL of the following succeeded:
	// 1. Program execution ✓
	// 2. Correct factorial computation (5! = 120) ✓
	// 3. AET generation ✓
	// 4. Proof generation ✓
	// 5. Proof verification ✓

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("✅ ALL OPERATIONS SUCCESSFUL!")
	fmt.Println(strings.Repeat("=", 60))

	fmt.Println("\n🎉 Complete workflow demonstrated:")
	fmt.Println("   ✓ Complex computation: 5! = 120 (result validated)")
	fmt.Println("   ✓ Multiple arithmetic operations (4 multiplications)")
	fmt.Printf("   ✓ Execution trace: %d rows\n", aet.Height)
	fmt.Printf("   ✓ STARK proof: %d bytes\n", proof.Size())
	fmt.Println("   ✓ Cryptographic verification: PASSED")

	fmt.Println("\n💡 This proves:")
	fmt.Println("   • The program was executed correctly")
	fmt.Println("   • All intermediate steps were valid")
	fmt.Println("   • The result 120 is genuinely 5!")
	fmt.Println("   • The verifier doesn't need to re-execute")

	fmt.Println("\n📈 Use cases:")
	fmt.Println("   • Verifiable computation")
	fmt.Println("   • Computational integrity proofs")
	fmt.Println("   • Outsourced computation verification")

	fmt.Println("\n✅ All operations completed successfully!")
	fmt.Println("   (If any step failed, execution would have stopped)")
}
