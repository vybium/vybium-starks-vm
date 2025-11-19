package main

import (
	"fmt"
	"log"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/vm"
	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
)

// Example 6: Field Arithmetic Operations
// Demonstrates Add, Mul operations in Goldilocks field

func main() {
	fmt.Println("=== Vybium STARKs VM Example 6: Field Arithmetic ===")
	fmt.Println("Goldilocks Field: P = 2^64 - 2^32 + 1 = 18446744069414584321")

	// Create program: (3 + 5) * 7
	program := vm.NewProgram()

	// Push 3
	val3 := field.New(3)
	push1, _ := vm.NewEncodedInstruction(vm.Push, &val3)
	program.AddInstruction(push1)

	// Push 5
	val5 := field.New(5)
	push2, _ := vm.NewEncodedInstruction(vm.Push, &val5)
	program.AddInstruction(push2)

	// Add: 3 + 5 = 8
	add, _ := vm.NewEncodedInstruction(vm.Add, nil)
	program.AddInstruction(add)

	// Push 7
	val7 := field.New(7)
	push3, _ := vm.NewEncodedInstruction(vm.Push, &val7)
	program.AddInstruction(push3)

	// Mul: 8 * 7 = 56
	mul, _ := vm.NewEncodedInstruction(vm.Mul, nil)
	program.AddInstruction(mul)

	// Halt
	halt, _ := vm.NewEncodedInstruction(vm.Halt, nil)
	program.AddInstruction(halt)

	fmt.Println("Computing: (3 + 5) * 7 = 56")
	fmt.Println()

	// Execute program
	vmState := vm.NewVMState(program, nil, nil)

	_, err := vmState.ExecuteAndTrace()
	if err != nil {
		log.Fatalf("Execution failed: %v", err)
	}

	fmt.Printf("✓ Execution completed: %d cycles\n", vmState.CycleCount)

	// Check top of stack
	if vmState.StackPointer > 0 {
		result := vmState.Stack[vmState.StackPointer-1]
		expected := field.New(56)
		fmt.Printf("✓ Result on stack: %s\n", result.String())
		if result.Equal(expected) {
			fmt.Println("✅ Computation verified!")
		}
	}

	fmt.Println("\n=== Field Arithmetic Examples ===")
	a := field.New(1000)
	b := field.New(2000)

	fmt.Printf("Addition: %s + %s = %s\n", a.String(), b.String(), a.Add(b).String())
	fmt.Printf("Multiplication: %s * %s = %s\n", a.String(), b.String(), a.Mul(b).String())

	val2 := field.New(2)
	fmt.Printf("Division: %s / %s = %s\n", a.String(), val2.String(), a.Div(val2).String())

	fmt.Println("\n💡 All operations are performed in the Goldilocks prime field,")
	fmt.Println("   ensuring all computations are verifiable with STARK proofs!")
}
