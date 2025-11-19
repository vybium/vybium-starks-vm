package protocols

import (
	"fmt"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
)

// SHA256 implements SHA-256 hash function constraints for zero-knowledge proofs
// Based on the techniques described in the STARKs paper
type SHA256 struct {
	field *core.Field
	// SHA-256 constants
	roundConstants [64]*core.FieldElement
	// Bit extraction instance
	bitExtraction *BitExtraction
}

// SHA256State represents the state of SHA-256 computation
type SHA256State struct {
	// 8 32-bit words for the hash state
	H [8]*core.FieldElement
	// 16 32-bit words for the message schedule
	W [64]*core.FieldElement
	// Working variables
	A, B, C, D, E, F, G, H_var *core.FieldElement
	// Temporary variables for bit operations
	T1, T2 *core.FieldElement
}

// SHA256Constraint represents a constraint in SHA-256 computation
type SHA256Constraint struct {
	// Constraint polynomial
	Polynomial *core.FieldElement
	// Constraint type (Ch, Maj, Σ0, Σ1, etc.)
	Type string
	// Round number
	Round int
	// Step number within round
	Step int
}

// NewSHA256 creates a new SHA-256 instance
func NewSHA256(field *core.Field) *SHA256 {
	// Initialize round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
	roundConstants := [64]*core.FieldElement{
		field.NewElementFromInt64(0x428a2f98), field.NewElementFromInt64(0x71374491),
		field.NewElementFromInt64(0xb5c0fbcf), field.NewElementFromInt64(0xe9b5dba5),
		field.NewElementFromInt64(0x3956c25b), field.NewElementFromInt64(0x59f111f1),
		field.NewElementFromInt64(0x923f82a4), field.NewElementFromInt64(0xab1c5ed5),
		field.NewElementFromInt64(0xd807aa98), field.NewElementFromInt64(0x12835b01),
		field.NewElementFromInt64(0x243185be), field.NewElementFromInt64(0x550c7dc3),
		field.NewElementFromInt64(0x72be5d74), field.NewElementFromInt64(0x80deb1fe),
		field.NewElementFromInt64(0x9bdc06a7), field.NewElementFromInt64(0xc19bf174),
		field.NewElementFromInt64(0xe49b69c1), field.NewElementFromInt64(0xefbe4786),
		field.NewElementFromInt64(0x0fc19dc6), field.NewElementFromInt64(0x240ca1cc),
		field.NewElementFromInt64(0x2de92c6f), field.NewElementFromInt64(0x4a7484aa),
		field.NewElementFromInt64(0x5cb0a9dc), field.NewElementFromInt64(0x76f988da),
		field.NewElementFromInt64(0x983e5152), field.NewElementFromInt64(0xa831c66d),
		field.NewElementFromInt64(0xb00327c8), field.NewElementFromInt64(0xbf597fc7),
		field.NewElementFromInt64(0xc6e00bf3), field.NewElementFromInt64(0xd5a79147),
		field.NewElementFromInt64(0x06ca6351), field.NewElementFromInt64(0x14292967),
		field.NewElementFromInt64(0x27b70a85), field.NewElementFromInt64(0x2e1b2138),
		field.NewElementFromInt64(0x4d2c6dfc), field.NewElementFromInt64(0x53380d13),
		field.NewElementFromInt64(0x650a7354), field.NewElementFromInt64(0x766a0abb),
		field.NewElementFromInt64(0x81c2c92e), field.NewElementFromInt64(0x92722c85),
		field.NewElementFromInt64(0xa2bfe8a1), field.NewElementFromInt64(0xa81a664b),
		field.NewElementFromInt64(0xc24b8b70), field.NewElementFromInt64(0xc76c51a3),
		field.NewElementFromInt64(0xd192e819), field.NewElementFromInt64(0xd6990624),
		field.NewElementFromInt64(0xf40e3585), field.NewElementFromInt64(0x106aa070),
		field.NewElementFromInt64(0x19a4c116), field.NewElementFromInt64(0x1e376c08),
		field.NewElementFromInt64(0x2748774c), field.NewElementFromInt64(0x34b0bcb5),
		field.NewElementFromInt64(0x391c0cb3), field.NewElementFromInt64(0x4ed8aa4a),
		field.NewElementFromInt64(0x5b9cca4f), field.NewElementFromInt64(0x682e6ff3),
		field.NewElementFromInt64(0x748f82ee), field.NewElementFromInt64(0x78a5636f),
		field.NewElementFromInt64(0x84c87814), field.NewElementFromInt64(0x8cc70208),
		field.NewElementFromInt64(0x90befffa), field.NewElementFromInt64(0xa4506ceb),
		field.NewElementFromInt64(0xbef9a3f7), field.NewElementFromInt64(0xc67178f2),
	}

	return &SHA256{
		field:          field,
		roundConstants: roundConstants,
		bitExtraction:  NewBitExtraction(field),
	}
}

// Hash computes the SHA-256 hash of the input
func (sha *SHA256) Hash(message []byte) (*SHA256State, error) {
	// Initialize state
	state := &SHA256State{}
	err := sha.initializeState(state)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize state: %w", err)
	}

	// Process message in 512-bit blocks
	blockSize := 64 // 512 bits = 64 bytes
	for i := 0; i < len(message); i += blockSize {
		block := message[i:]
		if len(block) > blockSize {
			block = block[:blockSize]
		}

		err = sha.processBlock(state, block)
		if err != nil {
			return nil, fmt.Errorf("failed to process block: %w", err)
		}
	}

	return state, nil
}

// initializeState initializes the SHA-256 state
func (sha *SHA256) initializeState(state *SHA256State) error {
	// Initialize hash values (first 32 bits of fractional parts of square roots of first 8 primes)
	state.H[0] = sha.field.NewElementFromInt64(0x6a09e667)
	state.H[1] = sha.field.NewElementFromInt64(0xbb67ae85)
	state.H[2] = sha.field.NewElementFromInt64(0x3c6ef372)
	state.H[3] = sha.field.NewElementFromInt64(0xa54ff53a)
	state.H[4] = sha.field.NewElementFromInt64(0x510e527f)
	state.H[5] = sha.field.NewElementFromInt64(0x9b05688c)
	state.H[6] = sha.field.NewElementFromInt64(0x1f83d9ab)
	state.H[7] = sha.field.NewElementFromInt64(0x5be0cd19)

	// Initialize working variables
	state.A = state.H[0]
	state.B = state.H[1]
	state.C = state.H[2]
	state.D = state.H[3]
	state.E = state.H[4]
	state.F = state.H[5]
	state.G = state.H[6]
	state.H_var = state.H[7]

	// Initialize temporary variables
	state.T1 = sha.field.Zero()
	state.T2 = sha.field.Zero()

	return nil
}

// processBlock processes a 512-bit block
func (sha *SHA256) processBlock(state *SHA256State, block []byte) error {
	// Prepare message schedule
	err := sha.prepareMessageSchedule(state, block)
	if err != nil {
		return fmt.Errorf("failed to prepare message schedule: %w", err)
	}

	// Main loop (64 rounds)
	for round := 0; round < 64; round++ {
		err = sha.processRound(state, round)
		if err != nil {
			return fmt.Errorf("failed to process round %d: %w", round, err)
		}
	}

	// Add the chunk's hash to result so far
	for i := 0; i < 8; i++ {
		state.H[i] = state.H[i].Add(state.H[i])
	}

	return nil
}

// prepareMessageSchedule prepares the message schedule W
func (sha *SHA256) prepareMessageSchedule(state *SHA256State, block []byte) error {
	// Copy chunk into first 16 words of W
	for i := 0; i < 16; i++ {
		// Convert 4 bytes to 32-bit word
		word := uint32(0)
		for j := 0; j < 4 && i*4+j < len(block); j++ {
			word |= uint32(block[i*4+j]) << (8 * (3 - j))
		}
		state.W[i] = sha.field.NewElementFromInt64(int64(word))
	}

	// Extend the first 16 words into the remaining 48 words
	for i := 16; i < 64; i++ {
		// W[i] = σ1(W[i-2]) + W[i-7] + σ0(W[i-15]) + W[i-16]
		sigma1, err := sha.sigma1(state.W[i-2])
		if err != nil {
			return fmt.Errorf("failed to compute σ1: %w", err)
		}

		sigma0, err := sha.sigma0(state.W[i-15])
		if err != nil {
			return fmt.Errorf("failed to compute σ0: %w", err)
		}

		state.W[i] = sigma1.Add(state.W[i-7]).Add(sigma0).Add(state.W[i-16])
	}

	return nil
}

// processRound processes a single round of SHA-256
func (sha *SHA256) processRound(state *SHA256State, round int) error {
	// T1 = H + Σ1(E) + Ch(E,F,G) + K[i] + W[i]
	sigma1E, err := sha.sigma1(state.E)
	if err != nil {
		return fmt.Errorf("failed to compute Σ1(E): %w", err)
	}

	chEFG, err := sha.ch(state.E, state.F, state.G)
	if err != nil {
		return fmt.Errorf("failed to compute Ch(E,F,G): %w", err)
	}

	state.T1 = state.H_var.Add(sigma1E).Add(chEFG).Add(sha.roundConstants[round]).Add(state.W[round])

	// T2 = Σ0(A) + Maj(A,B,C)
	sigma0A, err := sha.sigma0(state.A)
	if err != nil {
		return fmt.Errorf("failed to compute Σ0(A): %w", err)
	}

	majABC, err := sha.maj(state.A, state.B, state.C)
	if err != nil {
		return fmt.Errorf("failed to compute Maj(A,B,C): %w", err)
	}

	state.T2 = sigma0A.Add(majABC)

	// Update working variables
	state.H_var = state.G
	state.G = state.F
	state.F = state.E
	state.E = state.D.Add(state.T1)
	state.D = state.C
	state.C = state.B
	state.B = state.A
	state.A = state.T1.Add(state.T2)

	return nil
}

// ch implements the Ch function: Ch(x,y,z) = (x ∧ y) ⊕ (¬x ∧ z)
func (sha *SHA256) ch(x, y, z *core.FieldElement) (*core.FieldElement, error) {
	// Ch(x,y,z) = (x ∧ y) ⊕ (¬x ∧ z)
	// This is equivalent to: Ch(x,y,z) = (x ∧ y) ⊕ (¬x ∧ z)
	// In field arithmetic: Ch(x,y,z) = x·y + (1-x)·z

	// Compute x·y
	xy := x.Mul(y)

	// Compute (1-x)·z
	oneMinusX := sha.field.One().Sub(x)
	notXZ := oneMinusX.Mul(z)

	// Compute Ch(x,y,z) = x·y + (1-x)·z
	return xy.Add(notXZ), nil
}

// maj implements the Maj function: Maj(x,y,z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)
func (sha *SHA256) maj(x, y, z *core.FieldElement) (*core.FieldElement, error) {
	// Maj(x,y,z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)
	// In field arithmetic: Maj(x,y,z) = x·y + x·z + y·z - 2·x·y·z

	// Compute x·y, x·z, y·z
	xy := x.Mul(y)
	xz := x.Mul(z)
	yz := y.Mul(z)

	// Compute x·y·z
	xyz := xy.Mul(z)

	// Compute Maj(x,y,z) = x·y + x·z + y·z - 2·x·y·z
	two := sha.field.NewElementFromInt64(2)
	twoXyz := two.Mul(xyz)

	return xy.Add(xz).Add(yz).Sub(twoXyz), nil
}

// sigma0 implements the Σ0 function: Σ0(x) = ROTR^2(x) ⊕ ROTR^13(x) ⊕ ROTR^22(x)
func (sha *SHA256) sigma0(x *core.FieldElement) (*core.FieldElement, error) {
	// Σ0(x) = ROTR^2(x) ⊕ ROTR^13(x) ⊕ ROTR^22(x)
	// This involves cyclic right rotations and XOR operations

	// For field arithmetic, we need to implement bit-level operations
	// This is where the bit extraction constraints become crucial

	// Extract bits from x
	bits, err := sha.bitExtraction.FieldElementToBits(x, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to extract bits: %w", err)
	}

	// Perform cyclic right rotations
	rotr2 := sha.rotateRight(bits, 2)
	rotr13 := sha.rotateRight(bits, 13)
	rotr22 := sha.rotateRight(bits, 22)

	// XOR the rotated values
	rotr2Element, err := sha.bitExtraction.BitsToFieldElement(rotr2)
	if err != nil {
		return nil, fmt.Errorf("failed to convert rotr2 to field element: %w", err)
	}

	rotr13Element, err := sha.bitExtraction.BitsToFieldElement(rotr13)
	if err != nil {
		return nil, fmt.Errorf("failed to convert rotr13 to field element: %w", err)
	}

	rotr22Element, err := sha.bitExtraction.BitsToFieldElement(rotr22)
	if err != nil {
		return nil, fmt.Errorf("failed to convert rotr22 to field element: %w", err)
	}

	// XOR operations in field arithmetic
	result := rotr2Element.Add(rotr13Element).Add(rotr22Element)

	return result, nil
}

// sigma1 implements the Σ1 function: Σ1(x) = ROTR^6(x) ⊕ ROTR^11(x) ⊕ ROTR^25(x)
func (sha *SHA256) sigma1(x *core.FieldElement) (*core.FieldElement, error) {
	// Σ1(x) = ROTR^6(x) ⊕ ROTR^11(x) ⊕ ROTR^25(x)

	// Extract bits from x
	bits, err := sha.bitExtraction.FieldElementToBits(x, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to extract bits: %w", err)
	}

	// Perform cyclic right rotations
	rotr6 := sha.rotateRight(bits, 6)
	rotr11 := sha.rotateRight(bits, 11)
	rotr25 := sha.rotateRight(bits, 25)

	// XOR the rotated values
	rotr6Element, err := sha.bitExtraction.BitsToFieldElement(rotr6)
	if err != nil {
		return nil, fmt.Errorf("failed to convert rotr6 to field element: %w", err)
	}

	rotr11Element, err := sha.bitExtraction.BitsToFieldElement(rotr11)
	if err != nil {
		return nil, fmt.Errorf("failed to convert rotr11 to field element: %w", err)
	}

	rotr25Element, err := sha.bitExtraction.BitsToFieldElement(rotr25)
	if err != nil {
		return nil, fmt.Errorf("failed to convert rotr25 to field element: %w", err)
	}

	// XOR operations in field arithmetic
	result := rotr6Element.Add(rotr11Element).Add(rotr25Element)

	return result, nil
}

// rotateRight performs cyclic right rotation on a bit array
func (sha *SHA256) rotateRight(bits []*core.FieldElement, amount int) []*core.FieldElement {
	if len(bits) == 0 {
		return bits
	}

	amount = amount % len(bits)
	if amount == 0 {
		return bits
	}

	result := make([]*core.FieldElement, len(bits))
	for i := 0; i < len(bits); i++ {
		newIndex := (i + amount) % len(bits)
		result[newIndex] = bits[i]
	}

	return result
}

// GenerateConstraints generates the algebraic constraints for SHA-256
func (sha *SHA256) GenerateConstraints() ([]SHA256Constraint, error) {
	var constraints []SHA256Constraint

	// Generate constraints for each round
	for round := 0; round < 64; round++ {
		// Ch function constraints
		chConstraints, err := sha.generateChConstraints(round)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Ch constraints for round %d: %w", round, err)
		}
		constraints = append(constraints, chConstraints...)

		// Maj function constraints
		majConstraints, err := sha.generateMajConstraints(round)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Maj constraints for round %d: %w", round, err)
		}
		constraints = append(constraints, majConstraints...)

		// Σ0 function constraints
		sigma0Constraints, err := sha.generateSigma0Constraints(round)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Σ0 constraints for round %d: %w", round, err)
		}
		constraints = append(constraints, sigma0Constraints...)

		// Σ1 function constraints
		sigma1Constraints, err := sha.generateSigma1Constraints(round)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Σ1 constraints for round %d: %w", round, err)
		}
		constraints = append(constraints, sigma1Constraints...)
	}

	return constraints, nil
}

// generateChConstraints generates constraints for the Ch function
func (sha *SHA256) generateChConstraints(round int) ([]SHA256Constraint, error) {
	var constraints []SHA256Constraint

	// Ch(x,y,z) = x·y + (1-x)·z
	// This creates a constraint: Ch(x,y,z) - x·y - (1-x)·z = 0

	constraintPoly := sha.field.Zero() // Simplified for demo
	constraint := SHA256Constraint{
		Polynomial: constraintPoly,
		Type:       "Ch",
		Round:      round,
		Step:       0,
	}
	constraints = append(constraints, constraint)

	return constraints, nil
}

// generateMajConstraints generates constraints for the Maj function
func (sha *SHA256) generateMajConstraints(round int) ([]SHA256Constraint, error) {
	var constraints []SHA256Constraint

	// Maj(x,y,z) = x·y + x·z + y·z - 2·x·y·z
	// This creates a constraint: Maj(x,y,z) - x·y - x·z - y·z + 2·x·y·z = 0

	constraintPoly := sha.field.Zero() // Simplified for demo
	constraint := SHA256Constraint{
		Polynomial: constraintPoly,
		Type:       "Maj",
		Round:      round,
		Step:       1,
	}
	constraints = append(constraints, constraint)

	return constraints, nil
}

// generateSigma0Constraints generates constraints for the Σ0 function
func (sha *SHA256) generateSigma0Constraints(round int) ([]SHA256Constraint, error) {
	var constraints []SHA256Constraint

	// Σ0(x) = ROTR^2(x) ⊕ ROTR^13(x) ⊕ ROTR^22(x)
	// This involves bit extraction and rotation constraints

	constraintPoly := sha.field.Zero() // Simplified for demo
	constraint := SHA256Constraint{
		Polynomial: constraintPoly,
		Type:       "Sigma0",
		Round:      round,
		Step:       2,
	}
	constraints = append(constraints, constraint)

	return constraints, nil
}

// generateSigma1Constraints generates constraints for the Σ1 function
func (sha *SHA256) generateSigma1Constraints(round int) ([]SHA256Constraint, error) {
	var constraints []SHA256Constraint

	// Σ1(x) = ROTR^6(x) ⊕ ROTR^11(x) ⊕ ROTR^25(x)
	// This involves bit extraction and rotation constraints

	constraintPoly := sha.field.Zero() // Simplified for demo
	constraint := SHA256Constraint{
		Polynomial: constraintPoly,
		Type:       "Sigma1",
		Round:      round,
		Step:       3,
	}
	constraints = append(constraints, constraint)

	return constraints, nil
}

// CreateSHA256AIR creates an AIR for SHA-256 computation
func CreateSHA256AIR(field *core.Field) (*AIR, error) {
	// SHA-256 has width 8 (hash state) + 64 (message schedule) + 8 (working variables) + 2 (temporary)
	width := 8 + 64 + 8 + 2
	// 64 rounds
	traceLength := 64

	// Create AIR
	air := NewAIR(field, traceLength, width, field.NewElementFromInt64(1))

	// Note: In a full implementation, we would generate and add SHA-256 constraints to the AIR
	// For now, we'll return the AIR without constraints
	// The constraints would be added through the CreateTransitionConstraints method

	return air, nil
}
