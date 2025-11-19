package vybiumstarksvm

import (
	"math/big"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/vm"
	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
)

// VM is the public interface for the Vybium STARKs VM
type VM interface {
	// Execute runs a program on the VM and returns the execution trace
	Execute(program *Program, publicInput []*FieldElement, secretInput []*FieldElement) (*ExecutionTrace, error)

	// GetState returns the current VM state
	GetState() *VMState
}

// VMState represents the current state of the VM (read-only)
type VMState struct {
	// Instruction pointer
	InstructionPointer int

	// Stack pointer
	StackPointer int

	// Cycle count
	CycleCount int

	// Halted flag
	Halted bool

	// Public output
	PublicOutput []*FieldElement
}

// vmImpl is the internal implementation of VM
type vmImpl struct {
	field   *core.Field
	config  *VMConfig
	vmState *vm.VMState
	program *vm.Program
}

// NewVM creates a new Vybium STARKs VM with the given configuration
func NewVM(config *VMConfig) (VM, error) {
	// Parse field modulus
	modulus := new(big.Int)
	if _, ok := modulus.SetString(config.FieldModulus, 10); !ok {
		return nil, &VMError{
			Code:    ErrInvalidConfig,
			Message: "invalid field modulus",
		}
	}

	// Create field
	field, err := core.NewField(modulus)
	if err != nil {
		return nil, &VMError{
			Code:    ErrFieldCreation,
			Message: "failed to create field: " + err.Error(),
		}
	}

	return &vmImpl{
		field:  field,
		config: config,
	}, nil
}

// convertToInternal converts public field elements to internal format
func convertToInternal(elems []*FieldElement) []field.Element {
	result := make([]field.Element, len(elems))
	for i, e := range elems {
		if e != nil {
			// Use Big() to get the big.Int value, then convert to uint64
			result[i] = field.New(e.Big().Uint64())
		}
	}
	return result
}

// convertFromInternal converts internal field elements to public format
func (v *vmImpl) convertFromInternal(elems []field.Element) []*FieldElement {
	result := make([]*FieldElement, len(elems))
	for i, e := range elems {
		// Convert field.Element to core.FieldElement via big.Int
		bigVal := new(big.Int).SetUint64(e.Value())
		result[i] = v.field.NewElement(bigVal)
	}
	return result
}

// Execute runs a program on the VM and returns the execution trace
func (v *vmImpl) Execute(program *Program, publicInput []*FieldElement, secretInput []*FieldElement) (*ExecutionTrace, error) {
	// Convert public Program to internal vm.Program (no longer needs field)
	internalProgram := vm.NewProgram()

	for _, inst := range program.Instructions {
		// Convert instruction to internal format
		var arg *field.Element
		if inst.Argument != nil {
			elem := field.New(inst.Argument.Big().Uint64())
			arg = &elem
		}
		internalInst := &vm.EncodedInstruction{
			Instruction: vm.Instruction(inst.Opcode),
			Argument:    arg,
		}
		internalProgram.AddInstruction(internalInst)
	}

	// Convert inputs to internal format
	internalPublicInput := convertToInternal(publicInput)
	internalSecretInput := convertToInternal(secretInput)

	// Create VM state (signature: program, publicInput, secretInput)
	v.vmState = vm.NewVMState(internalProgram, internalPublicInput, internalSecretInput)
	v.program = internalProgram

	// Execute the program and generate trace
	aet, err := v.vmState.ExecuteAndTrace()
	if err != nil {
		return nil, &VMError{
			Code:    ErrVMExecution,
			Message: "VM execution failed: " + err.Error(),
		}
	}

	// Build execution trace with internal AET
	trace := &ExecutionTrace{
		PublicInput:  publicInput,
		PublicOutput: v.convertFromInternal(v.vmState.PublicOutput),
		CycleCount:   int(v.vmState.CycleCount),
		internalAET:  aet, // Store for proof generation
	}

	return trace, nil
}

// GetState returns the current VM state
func (v *vmImpl) GetState() *VMState {
	if v.vmState == nil {
		return &VMState{}
	}

	return &VMState{
		InstructionPointer: v.vmState.InstructionPointer,
		StackPointer:       v.vmState.StackPointer,
		CycleCount:         int(v.vmState.CycleCount),
		Halted:             v.vmState.Halting,
		PublicOutput:       v.convertFromInternal(v.vmState.PublicOutput),
	}
}

// DefaultVMConfig returns a default VM configuration
// Uses Goldilocks field for efficient arithmetic operations
func DefaultVMConfig() *VMConfig {
	return &VMConfig{
		FieldModulus:       "18446744069414584321", // Goldilocks: 2^64 - 2^32 + 1
		ProgramAttestation: true,                   // TIP-0006 enabled
		PermutationChecks:  true,                   // TIP-0007 enabled
		LookupTables:       true,                   // TIP-0005 enabled
	}
}
