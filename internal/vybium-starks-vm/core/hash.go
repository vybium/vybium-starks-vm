package core

import (
	"crypto/sha256"
	"math/big"
)

// PoseidonHash implements a basic Poseidon hash function
// NOTE: This is a BASIC implementation for testing purposes.
// For production use, use EnhancedPoseidonHash in poseidon_enhanced.go which includes:
// - Grain LFSR parameter generation
// - Cauchy MDS matrix construction
// - Full sponge construction
// - Configurable security levels (128-bit, 256-bit)
// - Proper round constants and MDS matrix
type PoseidonHash struct {
	field *Field
	// Poseidon parameters for the field
	roundsFull    int
	roundsPartial int
	// S-box power (typically 3 or 5)
	sboxPower int
}

// NewPoseidonHash creates a new Poseidon hash instance
func NewPoseidonHash(field *Field) *PoseidonHash {
	// Standard Poseidon parameters for common fields
	// These can be optimized based on the specific field
	return &PoseidonHash{
		field:         field,
		roundsFull:    8,  // Full rounds
		roundsPartial: 57, // Partial rounds
		sboxPower:     5,  // S-box power
	}
}

// Hash computes the Poseidon hash of the input
func (p *PoseidonHash) Hash(inputs []*FieldElement) (*FieldElement, error) {
	if len(inputs) == 0 {
		return p.field.Zero(), nil
	}

	// Poseidon state (capacity + rate)
	// For simplicity, we'll use a 2-element state
	state := make([]*FieldElement, 2)
	state[0] = p.field.Zero() // capacity
	state[1] = p.field.Zero() // rate

	// Process inputs in chunks
	for i := 0; i < len(inputs); i++ {
		// Add input to rate element
		state[1] = state[1].Add(inputs[i])

		// Apply Poseidon permutation
		state = p.poseidonPermutation(state)
	}

	// Return the capacity element as the hash
	return state[0], nil
}

// poseidonPermutation applies the Poseidon permutation
func (p *PoseidonHash) poseidonPermutation(state []*FieldElement) []*FieldElement {
	// Basic Poseidon permutation for testing
	// Production code should use EnhancedPoseidonHash with proper Grain LFSR constants and Cauchy MDS matrix

	// Apply full rounds
	for round := 0; round < p.roundsFull/2; round++ {
		state = p.fullRound(state, round)
	}

	// Apply partial rounds
	for round := 0; round < p.roundsPartial; round++ {
		state = p.partialRound(state, round)
	}

	// Apply remaining full rounds
	for round := 0; round < p.roundsFull/2; round++ {
		state = p.fullRound(state, round)
	}

	return state
}

// fullRound applies a full round of Poseidon
func (p *PoseidonHash) fullRound(state []*FieldElement, round int) []*FieldElement {
	// Add round constants (simplified)
	roundConstant := p.field.NewElementFromInt64(int64(round + 1))

	// Apply S-box to all elements
	for i := range state {
		state[i] = state[i].Add(roundConstant)
		state[i] = p.sbox(state[i])
	}

	// Apply MDS matrix (basic mixing for testing)
	// Production: EnhancedPoseidonHash uses proper Cauchy-constructed MDS matrix
	state[0] = state[0].Add(state[1])
	state[1] = state[1].Add(state[0])

	return state
}

// partialRound applies a partial round of Poseidon
func (p *PoseidonHash) partialRound(state []*FieldElement, round int) []*FieldElement {
	// Add round constant
	roundConstant := p.field.NewElementFromInt64(int64(round + 100))
	state[0] = state[0].Add(roundConstant)

	// Apply S-box only to first element
	state[0] = p.sbox(state[0])

	// Apply MDS matrix (basic mixing for testing)
	state[0] = state[0].Add(state[1])
	state[1] = state[1].Add(state[0])

	return state
}

// sbox applies the S-box transformation
func (p *PoseidonHash) sbox(x *FieldElement) *FieldElement {
	// S-box: x^sboxPower
	result := x
	for i := 1; i < p.sboxPower; i++ {
		result = result.Mul(x)
	}
	return result
}

// RescueHash implements the Rescue hash function
// Rescue is another field-friendly hash function for zero-knowledge proofs
type RescueHash struct {
	field *Field
	// Rescue parameters
	rounds int
	// S-box power (typically 3)
	sboxPower int
}

// NewRescueHash creates a new Rescue hash instance
func NewRescueHash(field *Field) *RescueHash {
	return &RescueHash{
		field:     field,
		rounds:    10, // Number of rounds
		sboxPower: 3,  // S-box power
	}
}

// Hash computes the Rescue hash of the input
func (r *RescueHash) Hash(inputs []*FieldElement) (*FieldElement, error) {
	if len(inputs) == 0 {
		return r.field.Zero(), nil
	}

	// Rescue state (2 elements)
	state := make([]*FieldElement, 2)
	state[0] = r.field.Zero()
	state[1] = r.field.Zero()

	// Process inputs
	for i := 0; i < len(inputs); i++ {
		state[1] = state[1].Add(inputs[i])
		state = r.rescuePermutation(state)
	}

	return state[0], nil
}

// rescuePermutation applies the Rescue permutation
func (r *RescueHash) rescuePermutation(state []*FieldElement) []*FieldElement {
	for round := 0; round < r.rounds; round++ {
		// Forward round
		state = r.forwardRound(state, round)
		// Backward round
		state = r.backwardRound(state, round)
	}
	return state
}

// forwardRound applies a forward round of Rescue
func (r *RescueHash) forwardRound(state []*FieldElement, round int) []*FieldElement {
	// Add round constant
	roundConstant := r.field.NewElementFromInt64(int64(round + 1))

	// Apply S-box
	for i := range state {
		state[i] = state[i].Add(roundConstant)
		state[i] = r.sbox(state[i])
	}

	// Apply MDS matrix (simplified)
	state[0] = state[0].Add(state[1])
	state[1] = state[1].Add(state[0])

	return state
}

// backwardRound applies a backward round of Rescue
func (r *RescueHash) backwardRound(state []*FieldElement, round int) []*FieldElement {
	// Apply inverse S-box
	for i := range state {
		state[i] = r.inverseSbox(state[i])
	}

	// Add round constant
	roundConstant := r.field.NewElementFromInt64(int64(round + 1000))
	for i := range state {
		state[i] = state[i].Add(roundConstant)
	}

	// Apply MDS matrix (simplified)
	state[0] = state[0].Add(state[1])
	state[1] = state[1].Add(state[0])

	return state
}

// sbox applies the S-box transformation
func (r *RescueHash) sbox(x *FieldElement) *FieldElement {
	// S-box: x^sboxPower
	result := x
	for i := 1; i < r.sboxPower; i++ {
		result = result.Mul(x)
	}
	return result
}

// inverseSbox applies the inverse S-box transformation
func (r *RescueHash) inverseSbox(x *FieldElement) *FieldElement {
	// Inverse S-box: x^(1/sboxPower) mod (p-1)
	// For sboxPower = 3, we need x^(1/3) mod (p-1)
	// This is equivalent to x^((p-1+1)/3) mod p

	// Compute (p-1+1)/3 = p/3
	p := r.field.Modulus()
	exponent := new(big.Int).Div(p, big.NewInt(3))

	// Compute x^exponent mod p using repeated squaring
	result := r.field.One()
	base := x
	for exponent.Sign() > 0 {
		if exponent.Bit(0) == 1 {
			result = result.Mul(base)
		}
		base = base.Mul(base)
		exponent.Rsh(exponent, 1)
	}
	return result
}

// FieldFriendlyHash provides a unified interface for field-friendly hash functions
type FieldFriendlyHash interface {
	Hash(inputs []*FieldElement) (*FieldElement, error)
}

// GetFieldFriendlyHash returns a field-friendly hash function
func GetFieldFriendlyHash(field *Field, hashType string) FieldFriendlyHash {
	switch hashType {
	case "poseidon":
		return NewPoseidonHash(field)
	case "rescue":
		return NewRescueHash(field)
	default:
		// Default to Poseidon
		return NewPoseidonHash(field)
	}
}

// HashFieldElements hashes a slice of field elements using the specified hash function
func HashFieldElements(field *Field, hashType string, inputs []*FieldElement) (*FieldElement, error) {
	hasher := GetFieldFriendlyHash(field, hashType)
	return hasher.Hash(inputs)
}

// HashBytes hashes a byte slice by converting it to field elements
func HashBytes(field *Field, hashType string, data []byte) (*FieldElement, error) {
	// Convert bytes to field elements
	// For simplicity, we'll process 4 bytes at a time
	var inputs []*FieldElement

	for i := 0; i < len(data); i += 4 {
		// Convert 4 bytes to a field element
		var value int64
		for j := 0; j < 4 && i+j < len(data); j++ {
			value |= int64(data[i+j]) << (8 * j)
		}

		fieldElement := field.NewElementFromInt64(value)
		inputs = append(inputs, fieldElement)
	}

	// If no data, add a zero element
	if len(inputs) == 0 {
		inputs = append(inputs, field.Zero())
	}

	return HashFieldElements(field, hashType, inputs)
}

// HashBytesToBytes hashes a byte slice and returns bytes (for compatibility)
func HashBytesToBytes(field *Field, hashType string, data []byte) ([]byte, error) {
	hashElement, err := HashBytes(field, hashType, data)
	if err != nil {
		return nil, err
	}

	// Convert field element to bytes, ensuring we have enough bytes
	fieldBytes := hashElement.Big().Bytes()

	// Pad to 32 bytes if needed
	result := make([]byte, 32)
	copy(result[32-len(fieldBytes):], fieldBytes)

	return result, nil
}

// Legacy hash function for compatibility
// legacyHash is kept for future reference but currently unused
// nolint:unused
func legacyHash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
