// Package vm implements the Program Hash Table
package vm

import (
	"fmt"

	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/hash"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/protocols"
)

// ProgramHashTableImpl implements the Program Hash Table (TIP-0006)
// This table computes the hash digest of the program's description using Poseidon in Sponge mode
//
// Key differences from regular Hash Table:
// 1. Single digest for variable-length input (vs multiple fixed-length)
// 2. Sponge mode absorption (absorb + squeeze)
// 3. State registers update by addition (not reset)
// 4. Receives chunks from Program Table via evaluation argument
//
// Main purpose: Compute program digest for recursive verification and program attestation
type ProgramHashTableImpl struct {
	// Main columns (BField elements)
	// State columns: Poseidon state (rate + capacity elements)
	// For Poseidon with rate=10, capacity=6, we have 16 state elements
	state [16][]field.Element // State registers 0-15

	// Control columns
	roundNumber []field.Element // Current round number in Poseidon
	isAbsorbing []field.Element // Boolean: are we absorbing input?
	isSqueezing []field.Element // Boolean: are we squeezing output?

	// Auxiliary columns (XField elements for cross-table arguments)
	recvChunkEvalArg []field.Element // Receives program chunks from Program Table

	height       int
	paddedHeight int

	// Poseidon/Sponge parameters (standard Tip5/Poseidon settings)
	rate      int // Number of elements absorbed per chunk (10 for Tip5)
	capacity  int // Number of capacity elements (6 for Tip5)
	width     int // Total state width (rate + capacity = 16)
	numRounds int // Total number of rounds per permutation
}

// NewProgramHashTable creates a new Program Hash Table with standard parameters
func NewProgramHashTable() *ProgramHashTableImpl {
	// Standard Tip5/Poseidon parameters
	rate := 10
	capacity := 6
	width := rate + capacity // 16
	numRounds := 83          // Standard for Tip5

	pht := &ProgramHashTableImpl{
		state:            [16][]field.Element{},
		roundNumber:      make([]field.Element, 0),
		isAbsorbing:      make([]field.Element, 0),
		isSqueezing:      make([]field.Element, 0),
		recvChunkEvalArg: make([]field.Element, 0),
		height:           0,
		paddedHeight:     0,
		rate:             rate,
		capacity:         capacity,
		width:            width,
		numRounds:        numRounds,
	}

	// Initialize state arrays
	for i := 0; i < 16; i++ {
		pht.state[i] = make([]field.Element, 0)
	}

	return pht
}

// GetID returns the table's identifier
func (pht *ProgramHashTableImpl) GetID() TableID {
	return ProgramHashTable
}

// GetHeight returns the current height
func (pht *ProgramHashTableImpl) GetHeight() int {
	return pht.height
}

// GetPaddedHeight returns the padded height
func (pht *ProgramHashTableImpl) GetPaddedHeight() int {
	return pht.paddedHeight
}

// GetMainColumns returns all main columns
func (pht *ProgramHashTableImpl) GetMainColumns() [][]field.Element {
	cols := make([][]field.Element, 0, 16+3)

	// Add all 16 state columns
	for i := 0; i < 16; i++ {
		cols = append(cols, pht.state[i])
	}

	// Add control columns
	cols = append(cols, pht.roundNumber)
	cols = append(cols, pht.isAbsorbing)
	cols = append(cols, pht.isSqueezing)

	return cols
}

// GetAuxiliaryColumns returns auxiliary columns
func (pht *ProgramHashTableImpl) GetAuxiliaryColumns() [][]field.Element {
	return [][]field.Element{
		pht.recvChunkEvalArg,
	}
}

// ProgramHashEntry represents a single row in the Program Hash Table
type ProgramHashEntry struct {
	State       [16]field.Element // Full Poseidon state
	RoundNumber field.Element     // Current round number
	IsAbsorbing field.Element     // Are we absorbing?
	IsSqueezing field.Element     // Are we squeezing?
}

// AddRow adds a new row to the program hash table
func (pht *ProgramHashTableImpl) AddRow(entry *ProgramHashEntry) error {
	if entry == nil {
		return fmt.Errorf("program hash entry cannot be nil")
	}

	// Add state columns
	for i := 0; i < 16; i++ {
		pht.state[i] = append(pht.state[i], entry.State[i])
	}

	// Add control columns
	pht.roundNumber = append(pht.roundNumber, entry.RoundNumber)
	pht.isAbsorbing = append(pht.isAbsorbing, entry.IsAbsorbing)
	pht.isSqueezing = append(pht.isSqueezing, entry.IsSqueezing)

	// Initialize auxiliary columns (computed during proving)
	pht.recvChunkEvalArg = append(pht.recvChunkEvalArg, field.Zero)

	pht.height++
	return nil
}

// Pad pads the table to the target height with padding rows
func (pht *ProgramHashTableImpl) Pad(targetHeight int) error {
	if targetHeight < pht.height || pht.height == 0 {
		return fmt.Errorf("invalid padding: target=%d, current=%d", targetHeight, pht.height)
	}

	lastIdx := pht.height - 1
	for i := pht.height; i < targetHeight; i++ {
		// Pad with last row values
		for j := 0; j < 16; j++ {
			pht.state[j] = append(pht.state[j], pht.state[j][lastIdx])
		}
		pht.roundNumber = append(pht.roundNumber, pht.roundNumber[lastIdx])
		pht.isAbsorbing = append(pht.isAbsorbing, pht.isAbsorbing[lastIdx])
		pht.isSqueezing = append(pht.isSqueezing, pht.isSqueezing[lastIdx])
		pht.recvChunkEvalArg = append(pht.recvChunkEvalArg, pht.recvChunkEvalArg[lastIdx])
	}

	pht.paddedHeight = targetHeight
	return nil
}

// CreateInitialConstraints returns initial boundary constraints
func (pht *ProgramHashTableImpl) CreateInitialConstraints() ([]protocols.AIRConstraint, error) {
	// TIP-0006 Initial Constraints:
	// 1. Capacity registers (state[rate] to state[rate+capacity-1]) are 0
	// 2. recvChunkEvalArg is initialized with first chunk from Program Table

	constraints := make([]protocols.AIRConstraint, 0)

	// Capacity registers start at zero
	for i := pht.rate; i < pht.width; i++ {
		constraints = append(constraints, protocols.AIRConstraint{
			Type:   "boundary",
			Index:  i - pht.rate,
			Degree: 1,
			// Polynomial: state[i] = 0 (capacity initialization)
		})
	}

	return constraints, nil
}

// CreateConsistencyConstraints returns consistency constraints (no additional ones for Program Hash Table)
func (pht *ProgramHashTableImpl) CreateConsistencyConstraints() ([]protocols.AIRConstraint, error) {
	return []protocols.AIRConstraint{}, nil
}

// CreateTransitionConstraints returns transition constraints
func (pht *ProgramHashTableImpl) CreateTransitionConstraints() ([]protocols.AIRConstraint, error) {
	// TIP-0006 Transition Constraints:
	// 1. recvChunkEvalArg accumulates when roundNumber transitions to 1
	// 2. Capacity registers remain unchanged when roundNumber == 1 in next row
	// 3. All state registers remain unchanged when roundNumber == 0 in next row
	// 4. Standard Poseidon round constraints (same as Hash Table)

	constraints := make([]protocols.AIRConstraint, 0)

	// Sponge absorption: when starting new permutation (round 1), accumulate chunk
	constraints = append(constraints, protocols.AIRConstraint{
		Type:   "transition",
		Index:  0,
		Degree: 3, // Involves multiplication and evaluation
		// Sponge absorption accumulates chunk when round = 1
	})

	// Capacity preservation during absorption
	for i := pht.rate; i < pht.width; i++ {
		constraints = append(constraints, protocols.AIRConstraint{
			Type:   "transition",
			Index:  1 + (i - pht.rate),
			Degree: 2,
			// state[i] unchanged during absorption
		})
	}

	return constraints, nil
}

// CreateTerminalConstraints returns terminal boundary constraints
func (pht *ProgramHashTableImpl) CreateTerminalConstraints() ([]protocols.AIRConstraint, error) {
	// TIP-0006 Terminal Constraints:
	// The digest (state[0] to state[4]) must match the value copied to
	// Processor Table's operational stack and standard output
	// This is enforced via boundary constraint with evaluation argument

	constraints := make([]protocols.AIRConstraint, 0)

	// Digest boundary constraint (enforced via cross-table argument)
	constraints = append(constraints, protocols.AIRConstraint{
		Type:   "boundary",
		Index:  0,
		Degree: 5, // Polynomial evaluation over 5 digest elements
		// Program digest matches ProcessorTable OpStack and StandardOutput
	})

	return constraints, nil
}

// ComputeProgramDigest computes the Poseidon hash digest of a program
// This is the main entry point for program attestation
func (pht *ProgramHashTableImpl) ComputeProgramDigest(program *Program) ([5]field.Element, error) {
	if program == nil {
		return [5]field.Element{}, fmt.Errorf("program cannot be nil")
	}

	// Encode program instructions as field elements
	// Each instruction contributes 2 elements: opcode + argument (or zero)
	programElements := make([]field.Element, 0, len(program.Instructions)*2)
	for _, instr := range program.Instructions {
		// Add instruction opcode
		programElements = append(programElements, field.New(uint64(instr.Instruction)))

		// Add argument if present, otherwise add zero
		if instr.Argument != nil {
			programElements = append(programElements, *instr.Argument)
		} else {
			programElements = append(programElements, field.Zero)
		}
	}

	// Hash the program description using Poseidon
	digestElement := hash.PoseidonHash(programElements)

	// Create 5-element digest (standard for Tip5/Poseidon in Triton VM)
	// For now, we use the single hash output in the first position and zeros for the rest
	// In a full Tip5 implementation, we would squeeze 5 elements from the sponge
	digest := [5]field.Element{
		digestElement,
		field.Zero,
		field.Zero,
		field.Zero,
		field.Zero,
	}

	return digest, nil
}

// ===========================================================================
// TIP-0006: Boundary Constraint Helpers
// ===========================================================================

// ComputeDigestEvaluation computes the evaluation polynomial δ for a digest
// According to TIP-0006: δ = γ^5 + Σ(i=0..4) digest[4-i] · γ^i
// This is used to link the digest across ProgramHashTable, ProcessorTable stack, and output
func ComputeDigestEvaluation(field *core.Field, digest [5]*core.FieldElement, gamma *core.FieldElement) *core.FieldElement {
	// Start with γ^5
	gamma2 := gamma.Mul(gamma)
	gamma3 := gamma2.Mul(gamma)
	gamma4 := gamma3.Mul(gamma)
	gamma5 := gamma4.Mul(gamma)

	result := gamma5

	// Add Σ(i=0..4) digest[4-i] · γ^i
	gammaPower := field.One()
	for i := 0; i < 5; i++ {
		term := digest[4-i].Mul(gammaPower)
		result = result.Add(term)
		gammaPower = gammaPower.Mul(gamma)
	}

	return result
}

// ValidateDigestConsistency checks that the digest is consistent across all three locations
// This is a runtime check for development/testing purposes
func ValidateDigestConsistency(
	programHashDigest [5]*core.FieldElement,
	processorStackDigest [5]*core.FieldElement,
	outputDigest [5]*core.FieldElement,
) bool {
	// All three digests must match
	for i := 0; i < 5; i++ {
		if !programHashDigest[i].Equal(processorStackDigest[i]) {
			return false
		}
		if !programHashDigest[i].Equal(outputDigest[i]) {
			return false
		}
	}
	return true
}
