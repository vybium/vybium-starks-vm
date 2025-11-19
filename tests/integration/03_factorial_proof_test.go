package integration_test

import (
	"math/big"
	"testing"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/protocols"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/vm"
	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
)

// Test03_FactorialProof tests proving complex computation:
// Compute factorial(5) = 120 and prove correctness
//
// Related example: examples/07_factorial/main.go (user-facing demonstration)
func Test03_FactorialProof(t *testing.T) {
	t.Log("=== Test 03: Factorial Computation Proof ===")

	t.Log("Step 1: Creating factorial program...")
	t.Log("  Program: Compute 5! = 1*2*3*4*5 = 120")

	program := vm.NewProgram()

	// For simplicity, compute factorial iteratively: 1*2*3*4*5
	// Initialize accumulator = 1
	arg1 := field.New(1)
	push1, _ := vm.NewEncodedInstruction(vm.Push, &arg1)
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

	t.Logf("  Program has %d instructions", len(program.Instructions))

	// Step 2: Execute VM
	t.Log("Step 2: Executing factorial computation...")
	vmState := vm.NewVMState(program, nil, nil)

	aet, err := vmState.ExecuteAndTrace()
	if err != nil {
		t.Fatalf("Failed to execute and trace: %v", err)
	}

	t.Logf("  AET generated: height=%d, cycles=%d", aet.Height, vmState.CycleCount)

	// Verify output is 120
	if len(vmState.PublicOutput) < 6 {
		t.Fatalf("Expected at least 6 elements in PublicOutput, got %d", len(vmState.PublicOutput))
	}
	result := vmState.PublicOutput[5]
	expected := field.New(120)
	if !result.Equal(expected) {
		t.Fatalf("Expected result %v, got %v", expected, result)
	}
	t.Logf("  ✓ Factorial computed correctly: 5! = %d", result.Value())

	// Step 3: Generate proof
	t.Log("Step 3: Generating STARK proof of factorial computation...")
	params := protocols.DefaultSTARKParameters()

	prover, err := protocols.NewProver(params)
	if err != nil {
		t.Fatalf("Failed to create prover: %v", err)
	}

	claim := protocols.NewClaim(aet.ProgramDigest[:])
	claim = claim.WithInput(nil).WithOutput(vmState.PublicOutput)

	proof, err := prover.Prove(claim, aet)
	if err != nil {
		t.Fatalf("Failed to generate proof: %v", err)
	}

	t.Logf("  ✓ Proof generated! Size: ~%d bytes", proof.Size())

	// Step 4: Verify proof
	t.Log("Step 4: Verifying proof...")
	goldilocksP := new(big.Int)
	goldilocksP.SetString("18446744069414584321", 10)
	tempField, _ := core.NewField(goldilocksP)
	verifier, _ := protocols.NewVerifier(tempField, params)

	err = verifier.Verify(claim, proof)
	if err != nil {
		t.Fatalf("Proof verification failed: %v", err)
	}

	t.Log("  ✓ Proof verified!")
	t.Log("")
	t.Log("🎉 SUCCESS: Complex computation proof works!")
	t.Log("   Proved correct execution of factorial(5) = 120")
}
