package vm

import (
	"testing"

	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
)

// TestVMStateCreation tests VM state creation for 100% coverage
func TestVMStateCreation(t *testing.T) {
	// Test with empty program
	program := NewProgram()
	vm := NewVMState(program, []field.Element{}, []field.Element{})

	if vm == nil {
		t.Fatal("NewVMState should not return nil")
	}

	if vm.InstructionPointer != 0 {
		t.Errorf("InstructionPointer should be 0, got %d", vm.InstructionPointer)
	}

	// TIP-0006: Stack is initialized with 16 elements (on-chip registers)
	// First 5 elements contain the program digest
	if len(vm.Stack) != 16 {
		t.Errorf("Stack should have 16 elements (on-chip registers), got %d", len(vm.Stack))
	}

	// TIP-0006: Stack pointer starts at 5 (after program digest)
	if vm.StackPointer != 5 {
		t.Errorf("StackPointer should be 5, got %d", vm.StackPointer)
	}
}

// TestVMStateWithInputs tests VM state with inputs for 100% coverage
func TestVMStateWithInputs(t *testing.T) {
	program := NewProgram()
	publicInput := []field.Element{field.New(1), field.New(2)}
	secretInput := []field.Element{field.New(3), field.New(4)}

	vm := NewVMState(program, publicInput, secretInput)

	if len(vm.PublicInput) != 2 {
		t.Errorf("PublicInput length = %d, want 2", len(vm.PublicInput))
	}

	if len(vm.SecretInput) != 2 {
		t.Errorf("SecretInput length = %d, want 2", len(vm.SecretInput))
	}
}

// TestProgramCreation tests program creation for 100% coverage
func TestProgramCreation(t *testing.T) {
	program := NewProgram()

	if program == nil {
		t.Fatal("NewProgram should not return nil")
	}

	if len(program.Instructions) != 0 {
		t.Errorf("New program should have 0 instructions, got %d", len(program.Instructions))
	}
}

// TestProgramAddInstruction tests adding instructions for 100% coverage
func TestProgramAddInstruction(t *testing.T) {
	program := NewProgram()

	arg := field.New(42)
	inst := &EncodedInstruction{
		Instruction: Push,
		Argument:    &arg,
	}

	program.AddInstruction(inst)

	if len(program.Instructions) != 1 {
		t.Errorf("Program should have 1 instruction, got %d", len(program.Instructions))
	}

	if program.Instructions[0] != inst {
		t.Error("Added instruction should match")
	}
}

// TestProgramToWords tests program to words conversion for 100% coverage
func TestProgramToWords(t *testing.T) {
	program := NewProgram()

	arg1 := field.New(5)
	arg2 := field.New(3)
	program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &arg1})
	program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &arg2})
	program.AddInstruction(&EncodedInstruction{Instruction: Add, Argument: nil})

	words := program.ToWords()

	// Push instructions have size 2 (opcode + argument)
	// Add instruction has size 1 (just opcode)
	// So: 2*2 + 1 = 5 words
	expectedWords := 5
	if len(words) != expectedWords {
		t.Errorf("ToWords() length = %d, want %d", len(words), expectedWords)
	}
}

// TestProgramValidate tests program validation for 100% coverage
func TestProgramValidate(t *testing.T) {
	program := NewProgram()

	// Empty program should be valid (no validation method exists)
	// Program with instructions should be valid
	arg := field.New(42)
	program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &arg})
	program.AddInstruction(&EncodedInstruction{Instruction: Halt, Argument: nil})

	// Just test that we can add instructions
	if len(program.Instructions) != 2 {
		t.Errorf("Program should have 2 instructions, got %d", len(program.Instructions))
	}
}

// TestEncodedInstructionCreation tests encoded instruction creation for 100% coverage
func TestEncodedInstructionCreation(t *testing.T) {
	arg := field.New(42)
	inst, err := NewEncodedInstruction(Push, &arg)
	if err != nil {
		t.Fatalf("NewEncodedInstruction failed: %v", err)
	}

	if inst.Instruction != Push {
		t.Errorf("Instruction = %v, want %v", inst.Instruction, Push)
	}

	if inst.Argument == nil || !inst.Argument.Equal(arg) {
		t.Error("Argument should match")
	}
}

// TestEncodedInstructionWords tests Words method for 100% coverage
func TestEncodedInstructionWords(t *testing.T) {
	arg := field.New(42)
	inst := &EncodedInstruction{
		Instruction: Push,
		Argument:    &arg,
	}

	words := inst.Words()

	// Should have 2 words: opcode and argument
	if len(words) != 2 {
		t.Errorf("Words() length = %d, want 2", len(words))
	}

	// First word should be the opcode
	if words[0].Value() != uint64(Push) {
		t.Errorf("First word = %d, want %d", words[0].Value(), uint64(Push))
	}

	// Second word should be the argument
	if !words[1].Equal(arg) {
		t.Errorf("Second word = %v, want %v", words[1], arg)
	}
}

// TestDecodeInstruction tests instruction decoding for 100% coverage
func TestDecodeInstruction(t *testing.T) {
	// Test with valid instruction
	words := []field.Element{
		field.New(uint64(Push)),
		field.New(42),
	}

	inst, err := DecodeInstruction(words, 0)
	if err != nil {
		t.Fatalf("DecodeInstruction failed: %v", err)
	}

	if inst.Instruction != Push {
		t.Errorf("Decoded instruction = %v, want %v", inst.Instruction, Push)
	}

	if inst.Argument == nil || inst.Argument.Value() != 42 {
		t.Error("Decoded argument should be 42")
	}
}

// TestDecodeInstructionError tests error cases for 100% coverage
func TestDecodeInstructionError(t *testing.T) {
	// Test with insufficient words
	words := []field.Element{field.New(uint64(Push))}

	_, err := DecodeInstruction(words, 0)
	if err == nil {
		t.Error("Expected error for insufficient words")
	}

	// Test with invalid offset
	words = []field.Element{field.New(uint64(Push)), field.New(42)}

	_, err = DecodeInstruction(words, 10)
	if err == nil {
		t.Error("Expected error for invalid offset")
	}
}

// TestStackOperations tests stack operations for 100% coverage
func TestStackOperations(t *testing.T) {
	program := NewProgram()
	vm := NewVMState(program, []field.Element{}, []field.Element{})

	// Stack has 16 elements, StackPointer starts at 5 (after program digest)
	initialSP := vm.StackPointer

	// Test push
	val1 := field.New(42)
	if err := vm.StackPush(val1); err != nil {
		t.Fatalf("StackPush failed: %v", err)
	}

	// Stack is fixed size (16 elements), but StackPointer should increment
	if vm.StackPointer != initialSP+1 {
		t.Errorf("StackPointer = %d, want %d", vm.StackPointer, initialSP+1)
	}

	// Test peek
	peeked, err := vm.StackPeek(0)
	if err != nil {
		t.Fatalf("StackPeek failed: %v", err)
	}

	if !peeked.Equal(val1) {
		t.Errorf("StackPeek = %v, want %v", peeked, val1)
	}

	// Test pop
	popped, err := vm.StackPop()
	if err != nil {
		t.Fatalf("StackPop failed: %v", err)
	}

	if !popped.Equal(val1) {
		t.Errorf("StackPop = %v, want %v", popped, val1)
	}

	// StackPointer should be back to initial value
	if vm.StackPointer != initialSP {
		t.Errorf("StackPointer = %d, want %d (back to initial)", vm.StackPointer, initialSP)
	}
}

// TestStackOperationsError tests error cases for 100% coverage
func TestStackOperationsError(t *testing.T) {
	program := NewProgram()
	vm := NewVMState(program, []field.Element{}, []field.Element{})

	// Pop all elements down to StackPointer=0 to test underflow
	for vm.StackPointer > 0 {
		_, _ = vm.StackPop()
	}

	// Now test pop on empty stack (StackPointer=0)
	_, err := vm.StackPop()
	if err == nil {
		t.Error("Expected error for pop on empty stack (StackPointer=0)")
	}

	// Test peek on empty stack (StackPointer=0)
	_, err = vm.StackPeek(0)
	if err == nil {
		t.Error("Expected error for peek on empty stack")
	}
}

// TestRAMOperations tests RAM operations for 100% coverage
func TestRAMOperations(t *testing.T) {
	program := NewProgram()
	vm := NewVMState(program, []field.Element{}, []field.Element{})

	// Test write
	addr := field.New(100)
	val := field.New(42)
	vm.RAMWrite(addr, val)

	// Test read
	readVal := vm.RAMRead(addr)
	if !readVal.Equal(val) {
		t.Errorf("RAMRead = %v, want %v", readVal, val)
	}

	// Test read from uninitialized address
	uninitAddr := field.New(200)
	uninitVal := vm.RAMRead(uninitAddr)
	if !uninitVal.IsZero() {
		t.Errorf("Uninitialized RAM should be zero, got %v", uninitVal)
	}
}

// TestCurrentInstruction tests current instruction for 100% coverage
func TestCurrentInstruction(t *testing.T) {
	program := NewProgram()
	arg := field.New(42)
	program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &arg})

	vm := NewVMState(program, []field.Element{}, []field.Element{})

	inst, err := vm.CurrentInstruction()
	if err != nil {
		t.Fatalf("CurrentInstruction failed: %v", err)
	}

	if inst.Instruction != Push {
		t.Errorf("Current instruction = %v, want %v", inst.Instruction, Push)
	}
}

// TestCurrentInstructionError tests error cases for 100% coverage
func TestCurrentInstructionError(t *testing.T) {
	// Test with empty program
	program := NewProgram()
	vm := NewVMState(program, []field.Element{}, []field.Element{})

	_, err := vm.CurrentInstruction()
	if err == nil {
		t.Error("Expected error for empty program")
	}

	// Test with invalid instruction pointer
	program.AddInstruction(&EncodedInstruction{Instruction: Halt, Argument: nil})
	vm.InstructionPointer = 10

	_, err = vm.CurrentInstruction()
	if err == nil {
		t.Error("Expected error for invalid instruction pointer")
	}
}

// TestIncrementIP tests instruction pointer increment for 100% coverage
func TestIncrementIP(t *testing.T) {
	program := NewProgram()
	program.AddInstruction(&EncodedInstruction{Instruction: Halt, Argument: nil})

	vm := NewVMState(program, []field.Element{}, []field.Element{})

	initialIP := vm.InstructionPointer
	if err := vm.IncrementIP(); err != nil {
		t.Fatalf("IncrementIP failed: %v", err)
	}

	if vm.InstructionPointer != initialIP+1 {
		t.Errorf("InstructionPointer = %d, want %d", vm.InstructionPointer, initialIP+1)
	}
}

// TestSimpleProgramExecution tests simple program execution for 100% coverage
func TestSimpleProgramExecution(t *testing.T) {
	program := NewProgram()

	// Program: push 5, push 3, add, halt
	arg5 := field.New(5)
	arg3 := field.New(3)
	program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &arg5})
	program.AddInstruction(&EncodedInstruction{Instruction: Push, Argument: &arg3})
	program.AddInstruction(&EncodedInstruction{Instruction: Add, Argument: nil})
	program.AddInstruction(&EncodedInstruction{Instruction: Halt, Argument: nil})

	vm := NewVMState(program, []field.Element{}, []field.Element{})

	// Execute the program
	if err := vm.Run(); err != nil {
		t.Fatalf("Program execution failed: %v", err)
	}

	// Check that we have a result on the stack
	// StackPointer should be > 0 (we start with 5 from digest, push 2, pop 2 after add = 6 total)
	if vm.StackPointer == 0 {
		t.Error("StackPointer should be > 0 after execution")
	}

	// The result should be 8 (5 + 3) at the top of stack
	// Top of stack is at StackPointer-1
	result := vm.Stack[vm.StackPointer-1]
	expected := field.New(8)
	if !result.Equal(expected) {
		t.Errorf("Result = %v, want %v", result, expected)
	}
}
