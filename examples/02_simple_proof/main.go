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

// Example 2: Simple STARK Proof Generation and Verification
// Demonstrates the complete workflow: execute → prove → verify

func main() {
	// Catch panics and provide clear error message
	defer func() {
		if r := recover(); r != nil {
			log.Fatalf("\n❌ FATAL ERROR (panic): %v\n", r)
		}
	}()

	fmt.Println("=== Vybium STARKs VM Example 2: STARK Proof Generation ===")

	// Step 1: Create program
	program := vm.NewProgram()

	val100 := field.New(100)
	push, _ := vm.NewEncodedInstruction(vm.Push, &val100)
	program.AddInstruction(push)

	halt, _ := vm.NewEncodedInstruction(vm.Halt, nil)
	program.AddInstruction(halt)

	fmt.Println("✓ Program: Push(100), Halt")

	// Step 2: Execute and generate AET
	fmt.Println("\nExecuting program...")
	vmState := vm.NewVMState(program, nil, nil)

	aet, err := vmState.ExecuteAndTrace()
	if err != nil {
		log.Fatalf("Execution failed: %v", err)
	}
	fmt.Printf("✓ Execution completed: %d cycles\n", vmState.CycleCount)

	// Step 3: Create STARK prover
	fmt.Println("\nCreating STARK prover...")
	params := protocols.DefaultSTARKParameters()

	if err := params.Validate(); err != nil {
		log.Fatalf("Invalid STARK parameters: %v", err)
	}

	prover, err := protocols.NewProver(params)
	if err != nil {
		log.Fatalf("Failed to create prover: %v", err)
	}
	fmt.Printf("✓ Prover created (Security: %d-bit)\n", params.SecurityLevel)

	// Step 4: Create claim
	claim := protocols.NewClaim(aet.ProgramDigest[:])
	claim = claim.WithInput(nil).WithOutput(vmState.PublicOutput)

	// Step 5: Generate proof
	fmt.Println("\nGenerating STARK proof (this may take a few seconds)...")
	proof, err := prover.Prove(claim, aet)
	if err != nil {
		log.Fatalf("Proof generation failed: %v", err)
	}
	fmt.Printf("✓ Proof generated: %d bytes\n", proof.Size())

	// Step 6: Create verifier
	fmt.Println("\nCreating verifier...")
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
	fmt.Println("✓ Verifier created")

	// Step 7: Verify proof
	fmt.Println("\nVerifying proof...")
	err = verifier.Verify(claim, proof)
	if err != nil {
		// Verification failed - exit immediately
		log.Fatalf("❌ VERIFICATION FAILED: %v", err)
	}

	// === ONLY REACHED IF ALL OPERATIONS SUCCEEDED ===
	// If we reach here, ALL of the following succeeded:
	// 1. Program execution ✓
	// 2. AET generation ✓
	// 3. Prover creation ✓
	// 4. Proof generation ✓
	// 5. Verifier creation ✓
	// 6. Proof verification ✓

	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("✅ PROOF VERIFIED SUCCESSFULLY!")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Println("\n🎉 Complete STARK proof lifecycle demonstrated:")
	fmt.Println("   ✓ Program executed")
	fmt.Println("   ✓ Algebraic Execution Trace (AET) generated")
	fmt.Println("   ✓ STARK proof generated")
	fmt.Println("   ✓ Proof cryptographically verified")
	fmt.Println("\n💡 All operations completed successfully!")
	fmt.Println("   (If any step failed, execution would have stopped)")
}
