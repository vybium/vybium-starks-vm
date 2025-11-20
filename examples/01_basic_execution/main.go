package main

import (
	"fmt"
	"log"

	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/vm"
)

// Example 1: Basic Program Execution
// Demonstrates creating a simple program, executing it, and inspecting the VM state

func main() {
	fmt.Println("=== Vybium STARKs VM Example 1: Basic Program Execution ===")

	// Create a simple program: Push 42, Halt
	program := vm.NewProgram()
	fmt.Println("✓ Program created")

	// Push 42 onto the stack
	val42 := field.New(42)
	push, err := vm.NewEncodedInstruction(vm.Push, &val42)
	if err != nil {
		log.Fatalf("Failed to create push instruction: %v", err)
	}
	program.AddInstruction(push)

	// Halt execution
	halt, err := vm.NewEncodedInstruction(vm.Halt, nil)
	if err != nil {
		log.Fatalf("Failed to create halt instruction: %v", err)
	}
	program.AddInstruction(halt)

	fmt.Printf("✓ Program has %d instructions: Push(42), Halt\n\n", len(program.Instructions))

	// Execute the program
	fmt.Println("Executing program...")
	vmState := vm.NewVMState(program, nil, nil) // No public/secret inputs

	// Execute and generate trace
	aet, err := vmState.ExecuteAndTrace()
	if err != nil {
		log.Fatalf("Program execution failed: %v", err)
	}

	fmt.Println("✓ Program executed successfully!")

	// Inspect the results
	fmt.Println("Execution Results:")
	fmt.Printf("  - Cycles: %d\n", vmState.CycleCount)
	fmt.Printf("  - Final IP: %d\n", vmState.InstructionPointer)
	fmt.Printf("  - Stack Pointer: %d\n", vmState.StackPointer)
	fmt.Printf("  - Halted: %v\n", vmState.Halting)

	if vmState.StackPointer > 0 {
		fmt.Printf("  - Top of stack: %s\n", vmState.Stack[vmState.StackPointer-1].String())
	}

	fmt.Printf("\nAET (Algebraic Execution Trace):\n")
	fmt.Printf("  - Height: %d rows\n", aet.Height)
	fmt.Printf("  - Padded Height: %d (power of 2)\n", aet.PaddedHeight)
	fmt.Printf("  - Program Digest: [%d elements]\n", len(aet.ProgramDigest))

	fmt.Println("\n✅ Execution trace captured!")
	fmt.Println("This trace can now be used to generate a zero-knowledge STARK proof.")
}
