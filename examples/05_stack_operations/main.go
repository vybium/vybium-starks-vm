package main

import (
	"fmt"
	"log"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/vm"
	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
)

// Example 5: Stack Operations
// Demonstrates Push, Dup, Swap, Pop instructions

func main() {
	fmt.Println("=== Vybium STARKs VM Example 5: Stack Operations ===")

	// Create program demonstrating various stack operations
	program := vm.NewProgram()

	// Push three values
	val10 := field.New(10)
	push1, _ := vm.NewEncodedInstruction(vm.Push, &val10)
	program.AddInstruction(push1)

	val20 := field.New(20)
	push2, _ := vm.NewEncodedInstruction(vm.Push, &val20)
	program.AddInstruction(push2)

	val30 := field.New(30)
	push3, _ := vm.NewEncodedInstruction(vm.Push, &val30)
	program.AddInstruction(push3)

	// Duplicate top value
	zero := field.New(0)
	dup, _ := vm.NewEncodedInstruction(vm.Dup, &zero)
	program.AddInstruction(dup)

	// Swap with position 1
	one := field.New(1)
	swap, _ := vm.NewEncodedInstruction(vm.Swap, &one)
	program.AddInstruction(swap)

	// Add top two
	add, _ := vm.NewEncodedInstruction(vm.Add, nil)
	program.AddInstruction(add)

	// Pop one value
	pop, _ := vm.NewEncodedInstruction(vm.Pop, &one)
	program.AddInstruction(pop)

	// Halt
	halt, _ := vm.NewEncodedInstruction(vm.Halt, nil)
	program.AddInstruction(halt)

	fmt.Println("Program instructions:")
	fmt.Println("  1. Push(10), Push(20), Push(30)")
	fmt.Println("  2. Dup(0) - duplicate top")
	fmt.Println("  3. Swap(1) - swap with position 1")
	fmt.Println("  4. Add - add top two")
	fmt.Println("  5. Pop(1) - pop one value")
	fmt.Println()

	// Execute program
	vmState := vm.NewVMState(program, nil, nil)

	aet, err := vmState.ExecuteAndTrace()
	if err != nil {
		log.Fatalf("Execution failed: %v", err)
	}

	fmt.Printf("✓ Program executed: %d cycles\n", vmState.CycleCount)
	fmt.Printf("✓ Final stack pointer: %d\n", vmState.StackPointer)
	fmt.Printf("✓ AET height: %d rows\n", aet.Height)

	fmt.Println("\n✅ Stack operations completed!")
	fmt.Println("\n💡 All stack manipulations are recorded in the execution trace")
	fmt.Println("   and can be proven correct with a STARK proof.")
}
