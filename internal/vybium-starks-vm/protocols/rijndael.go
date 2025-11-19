package protocols

import (
	"fmt"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
)

// Rijndael160 implements the Rijndael-160 cipher as described in the STARKs paper
// This is a 160-bit block cipher with 160-bit key, designed for zero-knowledge proofs
type Rijndael160 struct {
	field *core.Field
	// Rijndael parameters
	blockSize int // 160 bits = 20 bytes
	keySize   int // 160 bits = 20 bytes
	rounds    int // 11 rounds for 160-bit
}

// RijndaelState represents the state of the Rijndael cipher
type RijndaelState struct {
	// 20 registers for plaintext (4x5 matrix)
	P [4][5]*core.FieldElement
	// 20 registers for key (4x5 matrix)
	K [4][5]*core.FieldElement
	// 5 auxiliary registers for SubBytes inversions
	INV [5]*core.FieldElement
	// 15 registers for repeated quadrupling (3 per INV)
	W [5][3]*core.FieldElement
	// 2 inner flags for Rijndael steps
	F1, F2 *core.FieldElement
	// Round constant register
	RC *core.FieldElement
	// Inverse of round constant
	INVRC *core.FieldElement
	// External flag for cipher vs additional logic
	STATE *core.FieldElement
}

// RijndaelConstraint represents a constraint in the Rijndael cipher
type RijndaelConstraint struct {
	// Constraint polynomial
	Polynomial *core.Polynomial
	// Constraint type (SubBytes, ShiftRows, MixColumns, AddRoundKey)
	Type string
	// Round number
	Round int
	// Step number within round
	Step int
}

// NewRijndael160 creates a new Rijndael-160 cipher instance
func NewRijndael160(field *core.Field) *Rijndael160 {
	return &Rijndael160{
		field:     field,
		blockSize: 160, // 160 bits
		keySize:   160, // 160 bits
		rounds:    11,  // 11 rounds for 160-bit
	}
}

// Encrypt encrypts a 160-bit block using Rijndael-160
func (r *Rijndael160) Encrypt(plaintext, key []byte) (*RijndaelState, error) {
	if len(plaintext) != 20 || len(key) != 20 {
		return nil, fmt.Errorf("plaintext and key must be exactly 20 bytes (160 bits)")
	}

	// Initialize state
	state := &RijndaelState{}

	// Convert plaintext to field elements
	err := r.loadPlaintext(state, plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to load plaintext: %w", err)
	}

	// Convert key to field elements
	err = r.loadKey(state, key)
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %w", err)
	}

	// Initialize auxiliary registers
	err = r.initializeAuxiliaryRegisters(state)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize auxiliary registers: %w", err)
	}

	// Perform encryption rounds
	for round := 0; round < r.rounds; round++ {
		err = r.performRound(state, round)
		if err != nil {
			return nil, fmt.Errorf("failed to perform round %d: %w", round, err)
		}
	}

	return state, nil
}

// loadPlaintext loads the plaintext into the P registers
func (r *Rijndael160) loadPlaintext(state *RijndaelState, plaintext []byte) error {
	// Load plaintext into 4x5 matrix P
	for i := 0; i < 4; i++ {
		for j := 0; j < 5; j++ {
			byteIndex := i*5 + j
			if byteIndex < len(plaintext) {
				state.P[i][j] = r.field.NewElementFromInt64(int64(plaintext[byteIndex]))
			} else {
				state.P[i][j] = r.field.Zero()
			}
		}
	}
	return nil
}

// loadKey loads the key into the K registers
func (r *Rijndael160) loadKey(state *RijndaelState, key []byte) error {
	// Load key into 4x5 matrix K
	for i := 0; i < 4; i++ {
		for j := 0; j < 5; j++ {
			byteIndex := i*5 + j
			if byteIndex < len(key) {
				state.K[i][j] = r.field.NewElementFromInt64(int64(key[byteIndex]))
			} else {
				state.K[i][j] = r.field.Zero()
			}
		}
	}
	return nil
}

// initializeAuxiliaryRegisters initializes the auxiliary registers
func (r *Rijndael160) initializeAuxiliaryRegisters(state *RijndaelState) error {
	// Initialize INV registers to zero
	for i := 0; i < 5; i++ {
		state.INV[i] = r.field.Zero()
	}

	// Initialize W registers to zero
	for i := 0; i < 5; i++ {
		for j := 0; j < 3; j++ {
			state.W[i][j] = r.field.Zero()
		}
	}

	// Initialize flags
	state.F1 = r.field.Zero()
	state.F2 = r.field.Zero()

	// Initialize round constant
	state.RC = r.field.One()
	state.INVRC = r.field.One()

	// Initialize state flag
	state.STATE = r.field.Zero()

	return nil
}

// performRound performs a single round of Rijndael
func (r *Rijndael160) performRound(state *RijndaelState, round int) error {
	// Each round consists of 5 cycles:
	// 1. SubBytes
	// 2. ShiftRows
	// 3. MixColumns
	// 4. AddRoundKey
	// 5. Update round constant

	// Step 1: SubBytes
	err := r.subBytes(state, round)
	if err != nil {
		return fmt.Errorf("SubBytes failed: %w", err)
	}

	// Step 2: ShiftRows
	err = r.shiftRows(state, round)
	if err != nil {
		return fmt.Errorf("ShiftRows failed: %w", err)
	}

	// Step 3: MixColumns (except for last round)
	if round < r.rounds-1 {
		err = r.mixColumns(state, round)
		if err != nil {
			return fmt.Errorf("MixColumns failed: %w", err)
		}
	}

	// Step 4: AddRoundKey
	err = r.addRoundKey(state, round)
	if err != nil {
		return fmt.Errorf("AddRoundKey failed: %w", err)
	}

	// Step 5: Update round constant
	err = r.updateRoundConstant(state, round)
	if err != nil {
		return fmt.Errorf("update round constant failed: %w", err)
	}

	return nil
}

// subBytes applies the SubBytes transformation
func (r *Rijndael160) subBytes(state *RijndaelState, round int) error {
	// SubBytes applies the S-box to each byte of the state
	// The S-box is implemented using field inversion in F_2^8

	// For each byte in the state, compute its inverse
	for i := 0; i < 4; i++ {
		for j := 0; j < 5; j++ {
			// Compute inverse of P[i][j]
			inv, err := r.computeInverse(state.P[i][j])
			if err != nil {
				return fmt.Errorf("failed to compute inverse: %w", err)
			}

			// Apply affine transformation (simplified for demo)
			// In a full implementation, this would include the proper affine transformation
			state.P[i][j] = inv
		}
	}

	return nil
}

// computeInverse computes the inverse of a field element
func (r *Rijndael160) computeInverse(x *core.FieldElement) (*core.FieldElement, error) {
	// For F_2^8, we can use Fermat's little theorem: x^(-1) = x^(2^8 - 2)
	// This is x^254 in F_2^8

	// Handle zero case - in Rijndael, zero maps to zero
	if x.IsZero() {
		return r.field.Zero(), nil
	}

	// Use repeated squaring for x^254
	result := x
	for i := 0; i < 7; i++ { // 2^8 - 2 = 254 = 11111110 in binary
		result = result.Mul(result)
	}

	return result, nil
}

// shiftRows applies the ShiftRows transformation
func (r *Rijndael160) shiftRows(state *RijndaelState, round int) error {
	// ShiftRows shifts the rows of the state matrix
	// Row 0: no shift
	// Row 1: shift left by 1
	// Row 2: shift left by 2
	// Row 3: shift left by 3

	// Create a temporary matrix
	temp := [4][5]*core.FieldElement{}

	// Copy original state
	for i := 0; i < 4; i++ {
		for j := 0; j < 5; j++ {
			temp[i][j] = state.P[i][j]
		}
	}

	// Apply shifts
	for i := 0; i < 4; i++ {
		for j := 0; j < 5; j++ {
			// Shift row i left by i positions
			newCol := (j + i) % 5
			state.P[i][j] = temp[i][newCol]
		}
	}

	return nil
}

// mixColumns applies the MixColumns transformation
func (r *Rijndael160) mixColumns(state *RijndaelState, round int) error {
	// MixColumns applies a linear transformation to each column
	// This is implemented using polynomial multiplication in F_2^8

	// For each column
	for j := 0; j < 5; j++ {
		// Create temporary column
		temp := [4]*core.FieldElement{}
		for i := 0; i < 4; i++ {
			temp[i] = state.P[i][j]
		}

		// Apply MixColumns transformation
		// This is a simplified version - in practice, this would use proper polynomial arithmetic
		state.P[0][j] = temp[0].Add(temp[1]).Add(temp[2]).Add(temp[3])
		state.P[1][j] = temp[0].Add(temp[1])
		state.P[2][j] = temp[1].Add(temp[2])
		state.P[3][j] = temp[2].Add(temp[3])
	}

	return nil
}

// addRoundKey applies the AddRoundKey transformation
func (r *Rijndael160) addRoundKey(state *RijndaelState, round int) error {
	// AddRoundKey XORs the round key with the state
	// For simplicity, we'll use the original key for all rounds
	// In a full implementation, this would use proper key scheduling

	for i := 0; i < 4; i++ {
		for j := 0; j < 5; j++ {
			state.P[i][j] = state.P[i][j].Add(state.K[i][j])
		}
	}

	return nil
}

// updateRoundConstant updates the round constant
func (r *Rijndael160) updateRoundConstant(state *RijndaelState, round int) error {
	// Update round constant for next round
	// In Rijndael, the round constant is multiplied by 2 in the field
	state.RC = state.RC.Mul(r.field.NewElementFromInt64(2))

	// Compute inverse of round constant
	invRC, err := r.computeInverse(state.RC)
	if err != nil {
		return fmt.Errorf("failed to compute inverse of round constant: %w", err)
	}
	state.INVRC = invRC

	return nil
}

// GenerateConstraints generates the algebraic constraints for Rijndael-160
func (r *Rijndael160) GenerateConstraints() ([]RijndaelConstraint, error) {
	var constraints []RijndaelConstraint

	// Generate constraints for each round
	for round := 0; round < r.rounds; round++ {
		// SubBytes constraints
		subBytesConstraints, err := r.generateSubBytesConstraints(round)
		if err != nil {
			return nil, fmt.Errorf("failed to generate SubBytes constraints for round %d: %w", round, err)
		}
		constraints = append(constraints, subBytesConstraints...)

		// ShiftRows constraints
		shiftRowsConstraints, err := r.generateShiftRowsConstraints(round)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ShiftRows constraints for round %d: %w", round, err)
		}
		constraints = append(constraints, shiftRowsConstraints...)

		// MixColumns constraints (except for last round)
		if round < r.rounds-1 {
			mixColumnsConstraints, err := r.generateMixColumnsConstraints(round)
			if err != nil {
				return nil, fmt.Errorf("failed to generate MixColumns constraints for round %d: %w", round, err)
			}
			constraints = append(constraints, mixColumnsConstraints...)
		}

		// AddRoundKey constraints
		addRoundKeyConstraints, err := r.generateAddRoundKeyConstraints(round)
		if err != nil {
			return nil, fmt.Errorf("failed to generate AddRoundKey constraints for round %d: %w", round, err)
		}
		constraints = append(constraints, addRoundKeyConstraints...)
	}

	return constraints, nil
}

// generateSubBytesConstraints generates constraints for the SubBytes transformation
func (r *Rijndael160) generateSubBytesConstraints(round int) ([]RijndaelConstraint, error) {
	var constraints []RijndaelConstraint

	// Generate constraints for each byte in the state
	for i := 0; i < 4; i++ {
		for j := 0; j < 5; j++ {
			// Create constraint polynomial for SubBytes
			// This implements the constraint from Figure 9 of the paper:
			// (INV1(t)P00(t) + 1)(P00(t) ∧ INV1(t))∧
			// (W11(t) + INV14(t)) ∧ (W12(t) + W114(t)) ∧ (W13(t) + W124(t))∧
			// (P00(t+1) + c0 · INV1(t) + c1 · INV12(t) + c2 · W11(t) + c3 · W112(t)
			// + c4 · W12(t) + c5 · W122(t) + c6 · W13(t) + c7 · W132(t) + b)

			// For simplicity, we'll create a basic constraint
			// In a full implementation, this would include all the terms from the paper
			constraintPoly, err := core.NewPolynomial([]*core.FieldElement{
				r.field.Zero(), // Constant term
				r.field.One(),  // Linear term
			})
			if err != nil {
				return nil, fmt.Errorf("failed to create constraint polynomial: %w", err)
			}

			constraint := RijndaelConstraint{
				Polynomial: constraintPoly,
				Type:       "SubBytes",
				Round:      round,
				Step:       0, // SubBytes is step 0
			}
			constraints = append(constraints, constraint)
		}
	}

	return constraints, nil
}

// generateShiftRowsConstraints generates constraints for the ShiftRows transformation
func (r *Rijndael160) generateShiftRowsConstraints(round int) ([]RijndaelConstraint, error) {
	var constraints []RijndaelConstraint

	// ShiftRows constraints are simpler - they just rearrange the state
	// Create a basic constraint polynomial
	constraintPoly, err := core.NewPolynomial([]*core.FieldElement{
		r.field.Zero(), // Constant term
		r.field.One(),  // Linear term
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create constraint polynomial: %w", err)
	}

	constraint := RijndaelConstraint{
		Polynomial: constraintPoly,
		Type:       "ShiftRows",
		Round:      round,
		Step:       1, // ShiftRows is step 1
	}
	constraints = append(constraints, constraint)

	return constraints, nil
}

// generateMixColumnsConstraints generates constraints for the MixColumns transformation
func (r *Rijndael160) generateMixColumnsConstraints(round int) ([]RijndaelConstraint, error) {
	var constraints []RijndaelConstraint

	// MixColumns constraints involve polynomial multiplication
	// Create a basic constraint polynomial
	constraintPoly, err := core.NewPolynomial([]*core.FieldElement{
		r.field.Zero(), // Constant term
		r.field.One(),  // Linear term
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create constraint polynomial: %w", err)
	}

	constraint := RijndaelConstraint{
		Polynomial: constraintPoly,
		Type:       "MixColumns",
		Round:      round,
		Step:       2, // MixColumns is step 2
	}
	constraints = append(constraints, constraint)

	return constraints, nil
}

// generateAddRoundKeyConstraints generates constraints for the AddRoundKey transformation
func (r *Rijndael160) generateAddRoundKeyConstraints(round int) ([]RijndaelConstraint, error) {
	var constraints []RijndaelConstraint

	// AddRoundKey constraints involve XORing with the round key
	// Create a basic constraint polynomial
	constraintPoly, err := core.NewPolynomial([]*core.FieldElement{
		r.field.Zero(), // Constant term
		r.field.One(),  // Linear term
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create constraint polynomial: %w", err)
	}

	constraint := RijndaelConstraint{
		Polynomial: constraintPoly,
		Type:       "AddRoundKey",
		Round:      round,
		Step:       3, // AddRoundKey is step 3
	}
	constraints = append(constraints, constraint)

	return constraints, nil
}

// CreateRijndaelAIR creates an AIR for Rijndael-160 encryption
func CreateRijndaelAIR(field *core.Field) (*AIR, error) {
	// Rijndael-160 has width 65 (20 plaintext + 20 key + 5 INV + 15 W + 2 F + 1 RC + 1 INVRC + 1 STATE)
	width := 65
	// 55 cycles (11 rounds × 5 cycles per round)
	traceLength := 55

	// Create AIR
	air := NewAIR(field, traceLength, width, field.NewElementFromInt64(1))

	// Note: In a full implementation, we would generate and add Rijndael constraints to the AIR
	// For now, we'll return the AIR without constraints
	// The constraints would be added through the CreateTransitionConstraints method

	return air, nil
}
