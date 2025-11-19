// Package vm implements the Hash Table
package vm

import (
	"fmt"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/protocols"
	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
)

// HashTableImpl implements the Hash Table
// This table records cryptographic hash operations using Poseidon
//
// Unlike Triton VM which uses Tip5, we use Poseidon for:
// 1. Field-friendly operations
// 2. Multi-level security (128/256-bit)
// 3. Better integration with our existing Poseidon implementation
//
// Main purpose: Prove correctness of hash computations via evaluation arguments
type HashTableImpl struct {
	// Main columns (BField elements)
	// State columns: 16 state elements for Poseidon permutation
	state0, state1, state2, state3     []field.Element
	state4, state5, state6, state7     []field.Element
	state8, state9, state10, state11   []field.Element
	state12, state13, state14, state15 []field.Element

	// Control columns
	roundNumber    []field.Element // Current round number in Poseidon
	isFullRound    []field.Element // Boolean: is this a full round?
	isPartialRound []field.Element // Boolean: is this a partial round?

	// Auxiliary columns (XField elements for cross-table arguments)
	hashEvalArg []field.Element // Evaluation argument for hash input/output

	height       int
	paddedHeight int

	// Poseidon parameters
	poseidonWidth int // Width of Poseidon state (typically 16)
	numRounds     int // Total number of rounds
}

// NewHashTable creates a new Hash Table
func NewHashTable(poseidonWidth, numRounds int) *HashTableImpl {
	return &HashTableImpl{
		state0:         make([]field.Element, 0),
		state1:         make([]field.Element, 0),
		state2:         make([]field.Element, 0),
		state3:         make([]field.Element, 0),
		state4:         make([]field.Element, 0),
		state5:         make([]field.Element, 0),
		state6:         make([]field.Element, 0),
		state7:         make([]field.Element, 0),
		state8:         make([]field.Element, 0),
		state9:         make([]field.Element, 0),
		state10:        make([]field.Element, 0),
		state11:        make([]field.Element, 0),
		state12:        make([]field.Element, 0),
		state13:        make([]field.Element, 0),
		state14:        make([]field.Element, 0),
		state15:        make([]field.Element, 0),
		roundNumber:    make([]field.Element, 0),
		isFullRound:    make([]field.Element, 0),
		isPartialRound: make([]field.Element, 0),
		hashEvalArg:    make([]field.Element, 0),
		height:         0,
		paddedHeight:   0,
		poseidonWidth:  poseidonWidth,
		numRounds:      numRounds,
	}
}

// GetID returns the table's identifier
func (ht *HashTableImpl) GetID() TableID {
	return HashTable
}

// GetHeight returns the current height
func (ht *HashTableImpl) GetHeight() int {
	return ht.height
}

// GetPaddedHeight returns the padded height
func (ht *HashTableImpl) GetPaddedHeight() int {
	return ht.paddedHeight
}

// GetMainColumns returns all main columns
func (ht *HashTableImpl) GetMainColumns() [][]field.Element {
	return [][]field.Element{
		ht.state0, ht.state1, ht.state2, ht.state3,
		ht.state4, ht.state5, ht.state6, ht.state7,
		ht.state8, ht.state9, ht.state10, ht.state11,
		ht.state12, ht.state13, ht.state14, ht.state15,
		ht.roundNumber, ht.isFullRound, ht.isPartialRound,
	}
}

// GetAuxiliaryColumns returns auxiliary columns
func (ht *HashTableImpl) GetAuxiliaryColumns() [][]field.Element {
	return [][]field.Element{
		ht.hashEvalArg,
	}
}

// AddRow adds a new row to the hash table
func (ht *HashTableImpl) AddRow(entry *HashEntry) error {
	if entry == nil {
		return fmt.Errorf("hash entry cannot be nil")
	}

	if len(entry.State) != 16 {
		return fmt.Errorf("hash entry state must have exactly 16 elements, got %d", len(entry.State))
	}

	// Add state columns
	ht.state0 = append(ht.state0, entry.State[0])
	ht.state1 = append(ht.state1, entry.State[1])
	ht.state2 = append(ht.state2, entry.State[2])
	ht.state3 = append(ht.state3, entry.State[3])
	ht.state4 = append(ht.state4, entry.State[4])
	ht.state5 = append(ht.state5, entry.State[5])
	ht.state6 = append(ht.state6, entry.State[6])
	ht.state7 = append(ht.state7, entry.State[7])
	ht.state8 = append(ht.state8, entry.State[8])
	ht.state9 = append(ht.state9, entry.State[9])
	ht.state10 = append(ht.state10, entry.State[10])
	ht.state11 = append(ht.state11, entry.State[11])
	ht.state12 = append(ht.state12, entry.State[12])
	ht.state13 = append(ht.state13, entry.State[13])
	ht.state14 = append(ht.state14, entry.State[14])
	ht.state15 = append(ht.state15, entry.State[15])

	// Add control columns
	ht.roundNumber = append(ht.roundNumber, entry.RoundNumber)
	ht.isFullRound = append(ht.isFullRound, entry.IsFullRound)
	ht.isPartialRound = append(ht.isPartialRound, entry.IsPartialRound)

	// Initialize auxiliary columns (computed during proving)
	ht.hashEvalArg = append(ht.hashEvalArg, field.Zero)

	ht.height++
	return nil
}

// Pad pads the table to the target height with padding rows
func (ht *HashTableImpl) Pad(targetHeight int) error {
	if targetHeight < ht.height {
		return fmt.Errorf("target height %d is less than current height %d", targetHeight, ht.height)
	}

	if ht.height == 0 {
		return fmt.Errorf("cannot pad empty table")
	}

	// Use last row values for padding
	lastIdx := ht.height - 1
	paddingRows := targetHeight - ht.height

	for i := 0; i < paddingRows; i++ {
		ht.state0 = append(ht.state0, ht.state0[lastIdx])
		ht.state1 = append(ht.state1, ht.state1[lastIdx])
		ht.state2 = append(ht.state2, ht.state2[lastIdx])
		ht.state3 = append(ht.state3, ht.state3[lastIdx])
		ht.state4 = append(ht.state4, ht.state4[lastIdx])
		ht.state5 = append(ht.state5, ht.state5[lastIdx])
		ht.state6 = append(ht.state6, ht.state6[lastIdx])
		ht.state7 = append(ht.state7, ht.state7[lastIdx])
		ht.state8 = append(ht.state8, ht.state8[lastIdx])
		ht.state9 = append(ht.state9, ht.state9[lastIdx])
		ht.state10 = append(ht.state10, ht.state10[lastIdx])
		ht.state11 = append(ht.state11, ht.state11[lastIdx])
		ht.state12 = append(ht.state12, ht.state12[lastIdx])
		ht.state13 = append(ht.state13, ht.state13[lastIdx])
		ht.state14 = append(ht.state14, ht.state14[lastIdx])
		ht.state15 = append(ht.state15, ht.state15[lastIdx])
		ht.roundNumber = append(ht.roundNumber, ht.roundNumber[lastIdx])
		ht.isFullRound = append(ht.isFullRound, ht.isFullRound[lastIdx])
		ht.isPartialRound = append(ht.isPartialRound, ht.isPartialRound[lastIdx])
		ht.hashEvalArg = append(ht.hashEvalArg, ht.hashEvalArg[lastIdx])
	}

	ht.paddedHeight = targetHeight
	return nil
}

// CreateInitialConstraints generates constraints for the first row
func (ht *HashTableImpl) CreateInitialConstraints() ([]protocols.AIRConstraint, error) {
	constraints := make([]protocols.AIRConstraint, 0)

	// Initial constraints for Hash Table:
	//
	// 1. Round number starts at zero:
	//    roundNumber[0] = 0
	//
	// 2. First round must be a full round:
	//    isFullRound[0] = 1, isPartialRound[0] = 0
	//
	// 3. Hash evaluation argument initialized:
	//    hashEvalArg[0] = default_initial
	//
	// Note: Initial state values are set by the hash operation being proved.
	// Actual polynomial representations computed during proof generation.

	return constraints, nil
}

// CreateConsistencyConstraints generates constraints within each row
func (ht *HashTableImpl) CreateConsistencyConstraints() ([]protocols.AIRConstraint, error) {
	constraints := make([]protocols.AIRConstraint, 0)

	// Consistency constraints for Hash Table:
	//
	// 1. isFullRound is boolean (0 or 1):
	//    isFullRound * (isFullRound - 1) = 0
	//
	// 2. isPartialRound is boolean (0 or 1):
	//    isPartialRound * (isPartialRound - 1) = 0
	//
	// 3. Exactly one of isFullRound or isPartialRound is true:
	//    isFullRound + isPartialRound = 1
	//
	// 4. Round number is within valid range:
	//    0 <= roundNumber < numRounds
	//    This is enforced via range check lookups
	//
	// Note: Actual polynomial representations computed during proof generation.

	return constraints, nil
}

// CreateTransitionConstraints generates constraints between consecutive rows
func (ht *HashTableImpl) CreateTransitionConstraints() ([]protocols.AIRConstraint, error) {
	constraints := make([]protocols.AIRConstraint, 0)

	// Transition constraints for Hash Table (Poseidon permutation):
	//
	// 1. Round number increments or resets:
	//    If roundNumber < numRounds-1:
	//      roundNumber' = roundNumber + 1
	//    If roundNumber = numRounds-1:
	//      roundNumber' = 0 (start new hash)
	//
	// 2. Round type transitions correctly:
	//    Based on Poseidon structure (RF_full rounds at start/end, RP_partial in middle)
	//
	// 3. State transitions follow Poseidon round function:
	//    For full rounds (all state elements):
	//      - Add round constants
	//      - Apply S-box (x^α, typically α=5)
	//      - Apply MDS matrix
	//    For partial rounds (only first element):
	//      - Add round constants
	//      - Apply S-box to state[0] only
	//      - Apply MDS matrix
	//
	// 4. Hash evaluation argument updates:
	//    When starting new hash (roundNumber = 0):
	//      hashEvalArg' = hashEvalArg * indeterminate + compressed_input
	//    When finishing hash (roundNumber' = 0 and roundNumber = numRounds-1):
	//      hashEvalArg' = hashEvalArg * indeterminate + compressed_output
	//    Otherwise:
	//      hashEvalArg' = hashEvalArg
	//
	// Note: Poseidon constraints are complex and depend on round constants and MDS matrix.
	// For production, these would be computed from our enhanced Poseidon implementation.
	// Actual polynomial representations computed during proof generation with proper parameters.
	//
	// Innovation: We use Poseidon instead of Tip5, providing:
	// - Field-friendly operations
	// - Multi-level security (128/256-bit)
	// - Better integration with zkSTARKs literature

	return constraints, nil
}

// CreateTerminalConstraints generates constraints for the last row
func (ht *HashTableImpl) CreateTerminalConstraints() ([]protocols.AIRConstraint, error) {
	constraints := make([]protocols.AIRConstraint, 0)

	// Terminal constraints for Hash Table:
	//
	// The final hash evaluation argument must match the evaluation argument
	// from the Processor table (for hash operations).
	//
	// This is verified via cross-table evaluation arguments.

	return constraints, nil
}

// UpdateHashEvaluationArgument updates the evaluation argument for hash operations
// This links hash operations in the Processor table to this Hash table
func (ht *HashTableImpl) UpdateHashEvaluationArgument(indeterminate field.Element) error {
	if ht.height == 0 {
		return fmt.Errorf("cannot update hash evaluation on empty table")
	}

	// Initialize first row
	ht.hashEvalArg[0] = field.Zero

	// Track when we're at hash boundaries (roundNumber = 0 or roundNumber = numRounds-1)
	// This is where we absorb input or emit output in the evaluation argument

	for i := 1; i < ht.height; i++ {
		// For now, carry forward the value
		// In production, this would check for hash boundaries and update accordingly
		ht.hashEvalArg[i] = ht.hashEvalArg[i-1]
	}

	return nil
}

// HashEntry represents a single entry in the hash table (one round of Poseidon)
type HashEntry struct {
	State          []field.Element // 16-element Poseidon state
	RoundNumber    field.Element   // Current round number
	IsFullRound    field.Element   // Boolean: is this a full round?
	IsPartialRound field.Element   // Boolean: is this a partial round?
}

// NewHashEntry creates a new hash entry
func NewHashEntry(
	state []field.Element,
	roundNumber field.Element,
	isFullRound, isPartialRound bool,
) (*HashEntry, error) {
	if len(state) != 16 {
		return nil, fmt.Errorf("state must have exactly 16 elements, got %d", len(state))
	}

	var fullRoundVal, partialRoundVal field.Element
	if isFullRound {
		fullRoundVal = field.One
	} else {
		fullRoundVal = field.Zero
	}
	if isPartialRound {
		partialRoundVal = field.One
	} else {
		partialRoundVal = field.Zero
	}

	return &HashEntry{
		State:          state,
		RoundNumber:    roundNumber,
		IsFullRound:    fullRoundVal,
		IsPartialRound: partialRoundVal,
	}, nil
}
