package vm

import (
	"testing"

	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
)

// TestStackManipulationInstructions tests all stack operations
func TestStackManipulationInstructions(t *testing.T) {
	t.Run("Push", func(t *testing.T) {
		program := NewProgram()
		val := field.New(42)
		program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &val})
		program.AddInstruction(&EncodedInstruction{Instruction: Halt, Argument: nil})

		vm := NewVMState(program, []field.Element{}, []field.Element{})
		spBefore := vm.StackPointer
		if err := vm.Run(); err != nil {
			t.Fatalf("Run failed: %v", err)
		}

		// Check that stack pointer grew by 1 and top element is correct
		if vm.StackPointer != spBefore+1 {
			t.Errorf("StackPointer = %d, want %d", vm.StackPointer, spBefore+1)
		}
		// The pushed value should be at StackPointer-1
		stackTop := vm.Stack[vm.StackPointer-1]
		if !stackTop.Equal(val) {
			t.Errorf("Push did not push correct value: got %v, want %v", stackTop, val)
		}
	})

	t.Run("Pop", func(t *testing.T) {
		program := NewProgram()
		val1 := field.New(10)
		val2 := field.New(20)
		popCount := field.New(1)
		program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &val1})
		program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &val2})
		program.AddInstruction(&EncodedInstruction{Instruction: Pop, Argument: &popCount})
		program.AddInstruction(&EncodedInstruction{Instruction: Halt, Argument: nil})

		vm := NewVMState(program, []field.Element{}, []field.Element{})
		initialSP := vm.StackPointer
		if err := vm.Run(); err != nil {
			t.Fatalf("Run failed: %v", err)
		}

		// Should have one more element than initial (pushed 2, popped 1)
		expectedSP := initialSP + 1
		if vm.StackPointer != expectedSP {
			t.Errorf("StackPointer = %d, want %d", vm.StackPointer, expectedSP)
		}
	})

	t.Run("Dup", func(t *testing.T) {
		program := NewProgram()
		val := field.New(42)
		dupArg := field.New(0)
		program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &val})
		program.AddInstruction(&EncodedInstruction{Instruction: Dup, Argument: &dupArg})
		program.AddInstruction(&EncodedInstruction{Instruction: Halt, Argument: nil})

		vm := NewVMState(program, []field.Element{}, []field.Element{})
		if err := vm.Run(); err != nil {
			t.Fatalf("Run failed: %v", err)
		}

		// Check that top two elements are equal
		if vm.StackPointer < 2 {
			t.Fatal("Stack pointer too small after Dup")
		}
		top := vm.Stack[vm.StackPointer-1]
		second := vm.Stack[vm.StackPointer-2]
		if !top.Equal(second) {
			t.Error("Dup did not duplicate correctly")
		}
	})

	t.Run("Swap", func(t *testing.T) {
		program := NewProgram()
		val1 := field.New(10)
		val2 := field.New(20)
		swapArg := field.New(1)
		program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &val1})
		program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &val2})
		program.AddInstruction(&EncodedInstruction{Instruction: Swap, Argument: &swapArg})
		program.AddInstruction(&EncodedInstruction{Instruction: Halt, Argument: nil})

		vm := NewVMState(program, []field.Element{}, []field.Element{})
		if err := vm.Run(); err != nil {
			t.Fatalf("Run failed: %v", err)
		}

		// After swap, top should be val1
		if vm.StackPointer < 2 {
			t.Fatal("Stack pointer too small after Swap")
		}
		top := vm.Stack[vm.StackPointer-1]
		if !top.Equal(val1) {
			t.Error("Swap did not swap correctly")
		}
	})
}

// TestArithmeticInstructions tests arithmetic operations
func TestArithmeticInstructions(t *testing.T) {
	t.Run("Add", func(t *testing.T) {
		program := NewProgram()
		val1 := field.New(10)
		val2 := field.New(20)
		program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &val1})
		program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &val2})
		program.AddInstruction(&EncodedInstruction{Instruction: Add, Argument: nil})
		program.AddInstruction(&EncodedInstruction{Instruction: Halt, Argument: nil})

		vm := NewVMState(program, []field.Element{}, []field.Element{})
		if err := vm.Run(); err != nil {
			t.Fatalf("Run failed: %v", err)
		}

		expected := field.New(30)
		stackTop := vm.Stack[vm.StackPointer-1]
		if !stackTop.Equal(expected) {
			t.Errorf("Add result = %v, want %v", stackTop, expected)
		}
	})

	t.Run("Mul", func(t *testing.T) {
		program := NewProgram()
		val1 := field.New(3)
		val2 := field.New(7)
		program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &val1})
		program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &val2})
		program.AddInstruction(&EncodedInstruction{Instruction: Mul, Argument: nil})
		program.AddInstruction(&EncodedInstruction{Instruction: Halt, Argument: nil})

		vm := NewVMState(program, []field.Element{}, []field.Element{})
		if err := vm.Run(); err != nil {
			t.Fatalf("Run failed: %v", err)
		}

		expected := field.New(21)
		stackTop := vm.Stack[vm.StackPointer-1]
		if !stackTop.Equal(expected) {
			t.Errorf("Mul result = %v, want %v", stackTop, expected)
		}
	})

	t.Run("Invert", func(t *testing.T) {
		program := NewProgram()
		val := field.New(5)
		program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &val})
		program.AddInstruction(&EncodedInstruction{Instruction: Invert, Argument: nil})
		program.AddInstruction(&EncodedInstruction{Instruction: Halt, Argument: nil})

		vm := NewVMState(program, []field.Element{}, []field.Element{})
		if err := vm.Run(); err != nil {
			t.Fatalf("Run failed: %v", err)
		}

		stackTop := vm.Stack[vm.StackPointer-1]
		// Verify val * inv = 1
		result := val.Mul(stackTop)
		if !result.IsOne() {
			t.Error("Invert did not produce multiplicative inverse")
		}
	})

	t.Run("Pow", func(t *testing.T) {
		program := NewProgram()
		base := field.New(2)
		exp := field.New(3)
		program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &base})
		program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &exp})
		program.AddInstruction(&EncodedInstruction{Instruction: Pow, Argument: nil})
		program.AddInstruction(&EncodedInstruction{Instruction: Halt, Argument: nil})

		vm := NewVMState(program, []field.Element{}, []field.Element{})
		if err := vm.Run(); err != nil {
			t.Fatalf("Run failed: %v", err)
		}

		expected := field.New(8)
		stackTop := vm.Stack[vm.StackPointer-1]
		if !stackTop.Equal(expected) {
			t.Errorf("Pow result = %v, want %v", stackTop, expected)
		}
	})
}

// TestComparisonInstructions tests comparison operations
func TestComparisonInstructions(t *testing.T) {
	t.Run("Eq - Equal", func(t *testing.T) {
		program := NewProgram()
		val := field.New(42)
		program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &val})
		program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &val})
		program.AddInstruction(&EncodedInstruction{Instruction: Eq, Argument: nil})
		program.AddInstruction(&EncodedInstruction{Instruction: Halt, Argument: nil})

		vm := NewVMState(program, []field.Element{}, []field.Element{})
		if err := vm.Run(); err != nil {
			t.Fatalf("Run failed: %v", err)
		}

		stackTop := vm.Stack[vm.StackPointer-1]
		if !stackTop.IsOne() {
			t.Error("Eq should return 1 for equal values")
		}
	})

	t.Run("Eq - Not Equal", func(t *testing.T) {
		program := NewProgram()
		val1 := field.New(42)
		val2 := field.New(43)
		program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &val1})
		program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &val2})
		program.AddInstruction(&EncodedInstruction{Instruction: Eq, Argument: nil})
		program.AddInstruction(&EncodedInstruction{Instruction: Halt, Argument: nil})

		vm := NewVMState(program, []field.Element{}, []field.Element{})
		if err := vm.Run(); err != nil {
			t.Fatalf("Run failed: %v", err)
		}

		stackTop := vm.Stack[vm.StackPointer-1]
		if !stackTop.IsZero() {
			t.Error("Eq should return 0 for different values")
		}
	})
}

// TestControlFlowInstructions tests control flow operations
func TestControlFlowInstructions(t *testing.T) {
	t.Run("Nop", func(t *testing.T) {
		program := NewProgram()
		val := field.New(42)
		program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &val})
		program.AddInstruction(&EncodedInstruction{Instruction: Nop, Argument: nil})
		program.AddInstruction(&EncodedInstruction{Instruction: Halt, Argument: nil})

		vm := NewVMState(program, []field.Element{}, []field.Element{})
		spBefore := vm.StackPointer
		if err := vm.Run(); err != nil {
			t.Fatalf("Run failed: %v", err)
		}

		// Nop should not change stack pointer (except for initial push)
		if vm.StackPointer != spBefore+1 {
			t.Errorf("Nop changed stack pointer: got %d, want %d", vm.StackPointer, spBefore+1)
		}
	})

	t.Run("Assert - Success", func(t *testing.T) {
		program := NewProgram()
		one := field.One
		program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &one})
		program.AddInstruction(&EncodedInstruction{Instruction: Assert, Argument: nil})
		program.AddInstruction(&EncodedInstruction{Instruction: Halt, Argument: nil})

		vm := NewVMState(program, []field.Element{}, []field.Element{})
		if err := vm.Run(); err != nil {
			t.Fatalf("Run failed: %v", err)
		}
	})

	t.Run("Assert - Failure", func(t *testing.T) {
		program := NewProgram()
		zero := field.Zero
		program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &zero})
		program.AddInstruction(&EncodedInstruction{Instruction: Assert, Argument: nil})
		program.AddInstruction(&EncodedInstruction{Instruction: Halt, Argument: nil})

		vm := NewVMState(program, []field.Element{}, []field.Element{})
		err := vm.Run()
		if err == nil {
			t.Error("Assert should fail when top of stack is not 1")
		}
	})
}

// TestMemoryInstructions tests RAM operations
func TestMemoryInstructions(t *testing.T) {
	t.Run("WriteMem and ReadMem", func(t *testing.T) {
		program := NewProgram()
		addr := field.New(100)
		val := field.New(42)
		count := field.New(1)

		// Write to RAM
		program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &addr})
		program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &val})
		program.AddInstruction(&EncodedInstruction{Instruction: WriteMem, Argument: &count})

		// Read from RAM
		program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &addr})
		program.AddInstruction(&EncodedInstruction{Instruction: ReadMem, Argument: &count})
		program.AddInstruction(&EncodedInstruction{Instruction: Halt, Argument: nil})

		vm := NewVMState(program, []field.Element{}, []field.Element{})
		if err := vm.Run(); err != nil {
			t.Fatalf("Run failed: %v", err)
		}

		// Check that we read the correct value
		stackTop := vm.Stack[vm.StackPointer-1]
		if !stackTop.Equal(val) {
			t.Errorf("ReadMem returned %v, want %v", stackTop, val)
		}
	})
}

// TestIOInstructions tests input/output operations
func TestIOInstructions(t *testing.T) {
	t.Run("ReadIo", func(t *testing.T) {
		program := NewProgram()
		count := field.New(1)
		program.AddInstruction(&EncodedInstruction{Instruction: ReadIo, Argument: &count})
		program.AddInstruction(&EncodedInstruction{Instruction: Halt, Argument: nil})

		publicInput := []field.Element{field.New(42)}
		vm := NewVMState(program, publicInput, []field.Element{})
		if err := vm.Run(); err != nil {
			t.Fatalf("Run failed: %v", err)
		}

		stackTop := vm.Stack[vm.StackPointer-1]
		if !stackTop.Equal(publicInput[0]) {
			t.Errorf("ReadIo returned %v, want %v", stackTop, publicInput[0])
		}
	})

	t.Run("WriteIo", func(t *testing.T) {
		program := NewProgram()
		val := field.New(42)
		count := field.New(1)
		program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &val})
		program.AddInstruction(&EncodedInstruction{Instruction: WriteIo, Argument: &count})
		program.AddInstruction(&EncodedInstruction{Instruction: Halt, Argument: nil})

		vm := NewVMState(program, []field.Element{}, []field.Element{})
		if err := vm.Run(); err != nil {
			t.Fatalf("Run failed: %v", err)
		}

		// PublicOutput starts with 5-element program digest, then our output
		if len(vm.PublicOutput) < 6 {
			t.Fatalf("PublicOutput too short: %d elements", len(vm.PublicOutput))
		}
		writtenValue := vm.PublicOutput[5] // First element after digest
		if !writtenValue.Equal(val) {
			t.Errorf("WriteIo output = %v, want %v", writtenValue, val)
		}
	})

	t.Run("Divine", func(t *testing.T) {
		program := NewProgram()
		count := field.New(1)
		program.AddInstruction(&EncodedInstruction{Instruction: Divine, Argument: &count})
		program.AddInstruction(&EncodedInstruction{Instruction: Halt, Argument: nil})

		secretInput := []field.Element{field.New(12345)}
		vm := NewVMState(program, []field.Element{}, secretInput)
		if err := vm.Run(); err != nil {
			t.Fatalf("Run failed: %v", err)
		}

		stackTop := vm.Stack[vm.StackPointer-1]
		if !stackTop.Equal(secretInput[0]) {
			t.Errorf("Divine returned %v, want %v", stackTop, secretInput[0])
		}
	})
}

// TestDivModInstruction tests the DivMod operation
func TestDivModInstruction(t *testing.T) {
	program := NewProgram()
	dividend := field.New(17)
	divisor := field.New(5)
	program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &dividend})
	program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &divisor})
	program.AddInstruction(&EncodedInstruction{Instruction: DivMod, Argument: nil})
	program.AddInstruction(&EncodedInstruction{Instruction: Halt, Argument: nil})

	vm := NewVMState(program, []field.Element{}, []field.Element{})
	if err := vm.Run(); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// DivMod pushes quotient then remainder
	if vm.StackPointer < 2 {
		t.Fatal("Stack pointer too small after DivMod")
	}

	remainder := vm.Stack[vm.StackPointer-1]
	quotient := vm.Stack[vm.StackPointer-2]

	// 17 / 5 = 3 remainder 2
	expectedQuotient := field.New(3)
	expectedRemainder := field.New(2)

	if !quotient.Equal(expectedQuotient) {
		t.Errorf("Quotient = %v, want %v", quotient, expectedQuotient)
	}
	if !remainder.Equal(expectedRemainder) {
		t.Errorf("Remainder = %v, want %v", remainder, expectedRemainder)
	}
}
