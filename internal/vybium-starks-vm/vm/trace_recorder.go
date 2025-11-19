package vm

import (
	"fmt"

	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
)

// SimpleTraceRecorder is a production-ready trace recorder that focuses on
// processor state recording. Coprocessor table population is deferred to
// when we generate full proofs.
//
// This follows Triton VM's layered approach:
// - Phase 4a: Processor trace (THIS FILE - focus on main execution)
// - Phase 4b: Coprocessor traces (detailed hash, RAM, U32 tables)
type SimpleTraceRecorder struct {
	aet        *AET
	cycleCount uint64
}

// NewSimpleTraceRecorder creates a new simple trace recorder
func NewSimpleTraceRecorder(program *Program) (*SimpleTraceRecorder, error) {
	if program == nil {
		return nil, fmt.Errorf("program cannot be nil")
	}

	aet, err := NewAET(program)
	if err != nil {
		return nil, fmt.Errorf("failed to create AET: %w", err)
	}

	return &SimpleTraceRecorder{
		aet:        aet,
		cycleCount: 0,
	}, nil
}

// RecordState records the VM state before instruction execution
func (str *SimpleTraceRecorder) RecordState(vm *VMState) error {
	// Track instruction multiplicity
	if vm.InstructionPointer < len(str.aet.InstructionMultiplicities) {
		str.aet.InstructionMultiplicities[vm.InstructionPointer]++
	}

	// Record processor state
	if err := str.recordProcessorState(vm); err != nil {
		return err
	}

	str.cycleCount++
	return nil
}

// recordProcessorState records the processor state to the processor table
func (str *SimpleTraceRecorder) recordProcessorState(vm *VMState) error {
	// Get current instruction
	var currentInst Instruction = Nop
	if vm.InstructionPointer < len(vm.Program.Instructions) {
		currentInst = vm.Program.Instructions[vm.InstructionPointer].Instruction
	}

	// Next instruction address
	nia := vm.InstructionPointer + currentInst.Size()

	// Instruction bits (simplified to 3 bits for our processor table)
	opcode := uint32(currentInst)
	ib0 := field.New((uint64(opcode) >> 0) & 1)
	ib1 := field.New((uint64(opcode) >> 1) & 1)
	ib2 := field.New((uint64(opcode) >> 2) & 1)

	// Jump stack values
	jsp := field.New(uint64(len(vm.JumpStack)))
	jso := field.Zero
	jsd := field.Zero
	if len(vm.JumpStack) > 0 {
		top := vm.JumpStack[len(vm.JumpStack)-1]
		jso = field.New(uint64(top.Origin))
		jsd = field.New(uint64(top.Destination))
	}

	// Stack (top 16 elements)
	stack := make([]field.Element, 16)
	for i := 0; i < 16; i++ {
		if i < len(vm.Stack) {
			stack[i] = vm.Stack[len(vm.Stack)-1-i]
		} else {
			stack[i] = field.Zero
		}
	}

	// Create processor state
	state := &ProcessorState{
		Clock:                field.New(vm.CycleCount),
		InstructionPointer:   field.New(uint64(vm.InstructionPointer)),
		CurrentInstruction:   field.New(uint64(currentInst)),
		NextInstructionOrArg: field.New(uint64(nia)),
		InstructionBit0:      ib0,
		InstructionBit1:      ib1,
		InstructionBit2:      ib2,
		JumpStackPointer:     jsp,
		JumpStackOrigin:      jso,
		JumpStackDestination: jsd,
		Stack:                stack,
	}

	return str.aet.ProcessorTable.AddRow(state)
}

// GenerateAET finalizes and returns the AET
func (str *SimpleTraceRecorder) GenerateAET() (*AET, error) {
	// Pad all tables
	if err := str.aet.Pad(); err != nil {
		return nil, fmt.Errorf("failed to pad AET: %w", err)
	}

	return str.aet, nil
}
