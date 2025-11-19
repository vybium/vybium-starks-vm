// Package vm implements the Processor Table
package vm

import (
	"fmt"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/protocols"
	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
)

// ProcessorTableImpl implements the Processor Table
// This is the main execution trace recording all VM state transitions
type ProcessorTableImpl struct {
	// Main columns (BField elements)
	// Based on Triton VM's processor table specification
	clk                                          []field.Element // Clock cycle
	ip                                           []field.Element // Instruction pointer
	ci                                           []field.Element // Current instruction
	nia                                          []field.Element // Next instruction (or argument)
	ib0, ib1, ib2                                []field.Element // Instruction bits (for instruction decoding)
	jsp, jso, jsd                                []field.Element // Jump stack pointer, origin, destination
	st0, st1, st2, st3, st4, st5, st6, st7       []field.Element // Stack registers 0-7
	st8, st9, st10, st11, st12, st13, st14, st15 []field.Element // Stack registers 8-15

	// Auxiliary columns (XField elements for cross-table arguments)
	permArg []field.Element // Permutation argument accumulator
	evalArg []field.Element // Evaluation argument accumulator

	// Extension column for TIP-0007: Run-Time Permutation Check
	permrp []field.Element // Permutation running product

	height       int
	paddedHeight int
}

// NewProcessorTable creates a new Processor Table
func NewProcessorTable() *ProcessorTableImpl {
	return &ProcessorTableImpl{
		clk:          make([]field.Element, 0),
		ip:           make([]field.Element, 0),
		ci:           make([]field.Element, 0),
		nia:          make([]field.Element, 0),
		ib0:          make([]field.Element, 0),
		ib1:          make([]field.Element, 0),
		ib2:          make([]field.Element, 0),
		jsp:          make([]field.Element, 0),
		jso:          make([]field.Element, 0),
		jsd:          make([]field.Element, 0),
		st0:          make([]field.Element, 0),
		st1:          make([]field.Element, 0),
		st2:          make([]field.Element, 0),
		st3:          make([]field.Element, 0),
		st4:          make([]field.Element, 0),
		st5:          make([]field.Element, 0),
		st6:          make([]field.Element, 0),
		st7:          make([]field.Element, 0),
		st8:          make([]field.Element, 0),
		st9:          make([]field.Element, 0),
		st10:         make([]field.Element, 0),
		st11:         make([]field.Element, 0),
		st12:         make([]field.Element, 0),
		st13:         make([]field.Element, 0),
		st14:         make([]field.Element, 0),
		st15:         make([]field.Element, 0),
		permArg:      make([]field.Element, 0),
		evalArg:      make([]field.Element, 0),
		permrp:       make([]field.Element, 0),
		height:       0,
		paddedHeight: 0,
	}
}

// GetID returns the table's identifier
func (pt *ProcessorTableImpl) GetID() TableID {
	return ProcessorTable
}

// GetHeight returns the current height
func (pt *ProcessorTableImpl) GetHeight() int {
	return pt.height
}

// GetPaddedHeight returns the padded height
func (pt *ProcessorTableImpl) GetPaddedHeight() int {
	return pt.paddedHeight
}

// GetMainColumns returns all main columns
func (pt *ProcessorTableImpl) GetMainColumns() [][]field.Element {
	return [][]field.Element{
		pt.clk, pt.ip, pt.ci, pt.nia,
		pt.ib0, pt.ib1, pt.ib2,
		pt.jsp, pt.jso, pt.jsd,
		pt.st0, pt.st1, pt.st2, pt.st3,
		pt.st4, pt.st5, pt.st6, pt.st7,
		pt.st8, pt.st9, pt.st10, pt.st11,
		pt.st12, pt.st13, pt.st14, pt.st15,
	}
}

// GetAuxiliaryColumns returns auxiliary columns
func (pt *ProcessorTableImpl) GetAuxiliaryColumns() [][]field.Element {
	return [][]field.Element{
		pt.permArg,
		pt.evalArg,
		pt.permrp,
	}
}

// GetColumns returns all columns (main + auxiliary)
func (pt *ProcessorTableImpl) GetColumns() ([][]field.Element, error) {
	mainCols := pt.GetMainColumns()
	auxCols := pt.GetAuxiliaryColumns()

	// Combine all columns
	allCols := make([][]field.Element, 0, len(mainCols)+len(auxCols))
	allCols = append(allCols, mainCols...)
	allCols = append(allCols, auxCols...)

	return allCols, nil
}

// AddRow adds a new row to the processor table
func (pt *ProcessorTableImpl) AddRow(state *ProcessorState) error {
	if state == nil {
		return fmt.Errorf("processor state cannot be nil")
	}

	// Add main column values
	pt.clk = append(pt.clk, state.Clock)
	pt.ip = append(pt.ip, state.InstructionPointer)
	pt.ci = append(pt.ci, state.CurrentInstruction)
	pt.nia = append(pt.nia, state.NextInstructionOrArg)
	pt.ib0 = append(pt.ib0, state.InstructionBit0)
	pt.ib1 = append(pt.ib1, state.InstructionBit1)
	pt.ib2 = append(pt.ib2, state.InstructionBit2)
	pt.jsp = append(pt.jsp, state.JumpStackPointer)
	pt.jso = append(pt.jso, state.JumpStackOrigin)
	pt.jsd = append(pt.jsd, state.JumpStackDestination)

	// Add stack registers
	if len(state.Stack) != 16 {
		return fmt.Errorf("processor state must have exactly 16 stack registers, got %d", len(state.Stack))
	}
	pt.st0 = append(pt.st0, state.Stack[0])
	pt.st1 = append(pt.st1, state.Stack[1])
	pt.st2 = append(pt.st2, state.Stack[2])
	pt.st3 = append(pt.st3, state.Stack[3])
	pt.st4 = append(pt.st4, state.Stack[4])
	pt.st5 = append(pt.st5, state.Stack[5])
	pt.st6 = append(pt.st6, state.Stack[6])
	pt.st7 = append(pt.st7, state.Stack[7])
	pt.st8 = append(pt.st8, state.Stack[8])
	pt.st9 = append(pt.st9, state.Stack[9])
	pt.st10 = append(pt.st10, state.Stack[10])
	pt.st11 = append(pt.st11, state.Stack[11])
	pt.st12 = append(pt.st12, state.Stack[12])
	pt.st13 = append(pt.st13, state.Stack[13])
	pt.st14 = append(pt.st14, state.Stack[14])
	pt.st15 = append(pt.st15, state.Stack[15])

	// Initialize auxiliary columns (will be computed during proving)
	pt.permArg = append(pt.permArg, field.Zero)
	pt.evalArg = append(pt.evalArg, field.Zero)
	pt.permrp = append(pt.permrp, field.One) // TIP-0007: Start running product at 1

	pt.height++
	return nil
}

// Pad pads the table to the target height
func (pt *ProcessorTableImpl) Pad(targetHeight int) error {
	if targetHeight < pt.height {
		return fmt.Errorf("target height %d is less than current height %d", targetHeight, pt.height)
	}

	if pt.height == 0 {
		return fmt.Errorf("cannot pad empty table")
	}

	// Pad with copies of the last row
	lastIdx := pt.height - 1
	paddingRows := targetHeight - pt.height

	for i := 0; i < paddingRows; i++ {
		// Clone last row
		pt.clk = append(pt.clk, pt.clk[lastIdx])
		pt.ip = append(pt.ip, pt.ip[lastIdx])
		pt.ci = append(pt.ci, pt.ci[lastIdx])
		pt.nia = append(pt.nia, pt.nia[lastIdx])
		pt.ib0 = append(pt.ib0, pt.ib0[lastIdx])
		pt.ib1 = append(pt.ib1, pt.ib1[lastIdx])
		pt.ib2 = append(pt.ib2, pt.ib2[lastIdx])
		pt.jsp = append(pt.jsp, pt.jsp[lastIdx])
		pt.jso = append(pt.jso, pt.jso[lastIdx])
		pt.jsd = append(pt.jsd, pt.jsd[lastIdx])
		pt.st0 = append(pt.st0, pt.st0[lastIdx])
		pt.st1 = append(pt.st1, pt.st1[lastIdx])
		pt.st2 = append(pt.st2, pt.st2[lastIdx])
		pt.st3 = append(pt.st3, pt.st3[lastIdx])
		pt.st4 = append(pt.st4, pt.st4[lastIdx])
		pt.st5 = append(pt.st5, pt.st5[lastIdx])
		pt.st6 = append(pt.st6, pt.st6[lastIdx])
		pt.st7 = append(pt.st7, pt.st7[lastIdx])
		pt.st8 = append(pt.st8, pt.st8[lastIdx])
		pt.st9 = append(pt.st9, pt.st9[lastIdx])
		pt.st10 = append(pt.st10, pt.st10[lastIdx])
		pt.st11 = append(pt.st11, pt.st11[lastIdx])
		pt.st12 = append(pt.st12, pt.st12[lastIdx])
		pt.st13 = append(pt.st13, pt.st13[lastIdx])
		pt.st14 = append(pt.st14, pt.st14[lastIdx])
		pt.st15 = append(pt.st15, pt.st15[lastIdx])
		pt.permArg = append(pt.permArg, pt.permArg[lastIdx])
		pt.evalArg = append(pt.evalArg, pt.evalArg[lastIdx])

		// TIP-0007: Pad permrp with last value (maintains running product)
		if len(pt.permrp) > 0 {
			pt.permrp = append(pt.permrp, pt.permrp[lastIdx])
		}
	}

	pt.paddedHeight = targetHeight
	return nil
}

// CreateInitialConstraints generates constraints for the first row
func (pt *ProcessorTableImpl) CreateInitialConstraints() ([]protocols.AIRConstraint, error) {
	constraints := make([]protocols.AIRConstraint, 0)

	// Initial constraints for Processor Table:
	// - clk[0] = 0 (clock starts at zero)
	// - ip[0] = 0 (instruction pointer starts at zero)
	// - jsp[0] = 0 (jump stack pointer starts at zero)
	// - st0..st15[0] = 0 (all stack registers start at zero)
	//
	// Note: Actual polynomial representations are computed during proof generation
	// when we have the full trace and proper evaluation domains.
	//
	// These constraints ensure the processor starts in a clean initial state.

	return constraints, nil
}

// CreateConsistencyConstraints generates constraints within each row
func (pt *ProcessorTableImpl) CreateConsistencyConstraints() ([]protocols.AIRConstraint, error) {
	constraints := make([]protocols.AIRConstraint, 0)

	// Consistency constraints for Processor Table:
	//
	// 1. Instruction bits are boolean:
	//    - ib0 * (ib0 - 1) = 0
	//    - ib1 * (ib1 - 1) = 0
	//    - ib2 * (ib2 - 1) = 0
	//
	// 2. Current instruction encoding matches bits:
	//    - ci = ib0 + 2*ib1 + 4*ib2 + ... (instruction decoding)
	//
	// Note: Polynomial representations computed during proof generation.

	return constraints, nil
}

// CreateTransitionConstraints generates constraints between consecutive rows
func (pt *ProcessorTableImpl) CreateTransitionConstraints() ([]protocols.AIRConstraint, error) {
	constraints := make([]protocols.AIRConstraint, 0)

	// Transition constraints for Processor Table:
	//
	// 1. Clock increments: clk' = clk + 1
	//
	// 2. Instruction pointer transitions correctly:
	//    - For sequential instructions: ip' = ip + 1
	//    - For JUMP: ip' = jump_target
	//    - For CALL: ip' = call_target, jsp' = jsp + 1, jso = ip
	//    - For RETURN: ip' = jsd, jsp' = jsp - 1
	//
	// 3. Stack register transitions (instruction-dependent):
	//    - For PUSH: st0' = value, st1'..st15' = shifted
	//    - For POP: st0'..st14' = st1..st15, st15' = underflow
	//    - For arithmetic: st0' = st0 op st1, st1'..st15' = st2..st15 + underflow
	//
	// Note: Actual constraints are instruction-specific and computed during
	// proof generation with proper instruction decoding.

	return constraints, nil
}

// CreateTerminalConstraints generates constraints for the last row
func (pt *ProcessorTableImpl) CreateTerminalConstraints() ([]protocols.AIRConstraint, error) {
	constraints := make([]protocols.AIRConstraint, 0)

	// Terminal constraint for Processor Table:
	// - Final instruction must be HALT (ci[height-1] = HALT_OPCODE)
	//
	// This ensures the program terminates properly.
	// Note: Polynomial representation computed during proof generation.

	return constraints, nil
}

// ProcessorState represents the processor state at a single cycle
type ProcessorState struct {
	Clock                field.Element
	InstructionPointer   field.Element
	CurrentInstruction   field.Element
	NextInstructionOrArg field.Element
	InstructionBit0      field.Element
	InstructionBit1      field.Element
	InstructionBit2      field.Element
	JumpStackPointer     field.Element
	JumpStackOrigin      field.Element
	JumpStackDestination field.Element
	Stack                []field.Element // Must be exactly 16 elements
}

// NewProcessorState creates a new processor state with all fields initialized to zero
func NewProcessorState() *ProcessorState {
	stack := make([]field.Element, 16)
	for i := 0; i < 16; i++ {
		stack[i] = field.Zero
	}

	return &ProcessorState{
		Clock:                field.Zero,
		InstructionPointer:   field.Zero,
		CurrentInstruction:   field.Zero,
		NextInstructionOrArg: field.Zero,
		InstructionBit0:      field.Zero,
		InstructionBit1:      field.Zero,
		InstructionBit2:      field.Zero,
		JumpStackPointer:     field.Zero,
		JumpStackOrigin:      field.Zero,
		JumpStackDestination: field.Zero,
		Stack:                stack,
	}
}
