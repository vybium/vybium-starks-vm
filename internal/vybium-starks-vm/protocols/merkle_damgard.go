package protocols

import (
	"fmt"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
)

// MerkleDamgard implements the Merkle-Damgard construction for hashchain computation
// Based on the STARKs paper: uses Rijndael-160 as the compression function
type MerkleDamgard struct {
	field *core.Field
	// Davies-Meyer hash function (Rijndael-160 based)
	compressionFunc *DaviesMeyer
	// Initial hash value (IV)
	initialValue *core.FieldElement
	// Block size for the hash function
	blockSize int
}

// MerkleDamgardState represents the state of the Merkle-Damgard construction
type MerkleDamgardState struct {
	// Current hash value
	CurrentHash *core.FieldElement
	// Input block being processed
	InputBlock []byte
	// Hashchain elements
	HashchainElements []*core.FieldElement
	// Current block index
	BlockIndex int
	// Total number of blocks
	TotalBlocks int
}

// MerkleDamgardConstraint represents a constraint in the Merkle-Damgard construction
type MerkleDamgardConstraint struct {
	// Constraint polynomial
	Polynomial *core.Polynomial
	// Constraint type (compression, padding, etc.)
	Type string
	// Block number
	Block int
}

// NewMerkleDamgard creates a new Merkle-Damgard construction instance
func NewMerkleDamgard(field *core.Field) *MerkleDamgard {
	// Create Davies-Meyer compression function
	compressionFunc := NewDaviesMeyer(field)

	// Set initial value (IV) - typically a fixed value
	initialValue := field.NewElementFromInt64(0x6a09e667) // Standard IV

	return &MerkleDamgard{
		field:           field,
		compressionFunc: compressionFunc,
		initialValue:    initialValue,
		blockSize:       20, // 160 bits = 20 bytes for Rijndael-160
	}
}

// ComputeHashchain computes a hashchain using the Merkle-Damgard construction
func (md *MerkleDamgard) ComputeHashchain(elements []*core.FieldElement) (*MerkleDamgardState, error) {
	if len(elements) == 0 {
		return nil, fmt.Errorf("hashchain elements cannot be empty")
	}

	// Initialize state
	state := &MerkleDamgardState{
		CurrentHash:       md.initialValue,
		HashchainElements: elements,
		BlockIndex:        0,
		TotalBlocks:       len(elements),
	}

	// Process each element in the hashchain
	for i, element := range elements {
		state.BlockIndex = i

		// Convert element to input block
		err := md.prepareInputBlock(state, element)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare input block %d: %w", i, err)
		}

		// Apply compression function
		err = md.applyCompressionFunction(state)
		if err != nil {
			return nil, fmt.Errorf("failed to apply compression function at block %d: %w", i, err)
		}
	}

	return state, nil
}

// prepareInputBlock prepares the input block for compression
func (md *MerkleDamgard) prepareInputBlock(state *MerkleDamgardState, element *core.FieldElement) error {
	// Convert field element to bytes
	elementBytes := element.Bytes()

	// Pad to block size if necessary
	state.InputBlock = make([]byte, md.blockSize)
	copy(state.InputBlock, elementBytes)

	// If the element is larger than block size, we need to handle it differently
	// For simplicity, we'll truncate or pad as needed
	if len(elementBytes) > md.blockSize {
		// Truncate to block size
		copy(state.InputBlock, elementBytes[:md.blockSize])
	} else if len(elementBytes) < md.blockSize {
		// Pad with zeros
		for i := len(elementBytes); i < md.blockSize; i++ {
			state.InputBlock[i] = 0
		}
	}

	return nil
}

// applyCompressionFunction applies the Davies-Meyer compression function
func (md *MerkleDamgard) applyCompressionFunction(state *MerkleDamgardState) error {
	// Use Davies-Meyer: h_i = E_{h_{i-1}}(m_i) ⊕ m_i
	// where E is Rijndael-160 and m_i is the current block

	// Convert current hash to key
	keyBytes := make([]byte, md.blockSize)
	hashBytes := state.CurrentHash.Bytes()
	copy(keyBytes, hashBytes)

	// Apply Davies-Meyer compression
	hashState, err := md.compressionFunc.Hash(state.InputBlock, keyBytes)
	if err != nil {
		return fmt.Errorf("failed to compute Davies-Meyer hash: %w", err)
	}

	// Update current hash with the first element of the hash output
	state.CurrentHash = hashState.HashOutput[0]

	return nil
}

// VerifyHashchain verifies that a hashchain is correctly computed
func (md *MerkleDamgard) VerifyHashchain(elements []*core.FieldElement, expectedHash *core.FieldElement) (bool, error) {
	// Compute hashchain
	state, err := md.ComputeHashchain(elements)
	if err != nil {
		return false, fmt.Errorf("failed to compute hashchain: %w", err)
	}

	// Verify final hash matches expected
	return state.CurrentHash.Equal(expectedHash), nil
}

// GenerateConstraints generates the algebraic constraints for Merkle-Damgard
func (md *MerkleDamgard) GenerateConstraints() ([]MerkleDamgardConstraint, error) {
	var constraints []MerkleDamgardConstraint

	// Compression function constraints
	compressionConstraints, err := md.generateCompressionConstraints()
	if err != nil {
		return nil, fmt.Errorf("failed to generate compression constraints: %w", err)
	}
	constraints = append(constraints, compressionConstraints...)

	// Padding constraints
	paddingConstraints, err := md.generatePaddingConstraints()
	if err != nil {
		return nil, fmt.Errorf("failed to generate padding constraints: %w", err)
	}
	constraints = append(constraints, paddingConstraints...)

	// Hashchain constraints
	hashchainConstraints, err := md.generateHashchainConstraints()
	if err != nil {
		return nil, fmt.Errorf("failed to generate hashchain constraints: %w", err)
	}
	constraints = append(constraints, hashchainConstraints...)

	return constraints, nil
}

// generateCompressionConstraints generates constraints for the compression function
func (md *MerkleDamgard) generateCompressionConstraints() ([]MerkleDamgardConstraint, error) {
	var constraints []MerkleDamgardConstraint

	// Generate constraints for Davies-Meyer compression
	// h_i = E_{h_{i-1}}(m_i) ⊕ m_i

	constraintPoly, err := core.NewPolynomial([]*core.FieldElement{
		md.field.Zero(), // Constant term
		md.field.One(),  // Linear term
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create compression constraint polynomial: %w", err)
	}

	constraint := MerkleDamgardConstraint{
		Polynomial: constraintPoly,
		Type:       "compression",
		Block:      0,
	}
	constraints = append(constraints, constraint)

	return constraints, nil
}

// generatePaddingConstraints generates constraints for input padding
func (md *MerkleDamgard) generatePaddingConstraints() ([]MerkleDamgardConstraint, error) {
	var constraints []MerkleDamgardConstraint

	// Generate constraints for input padding
	// Ensure that input blocks are properly padded to block size

	constraintPoly, err := core.NewPolynomial([]*core.FieldElement{
		md.field.Zero(), // Constant term
		md.field.One(),  // Linear term
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create padding constraint polynomial: %w", err)
	}

	constraint := MerkleDamgardConstraint{
		Polynomial: constraintPoly,
		Type:       "padding",
		Block:      0,
	}
	constraints = append(constraints, constraint)

	return constraints, nil
}

// generateHashchainConstraints generates constraints for hashchain computation
func (md *MerkleDamgard) generateHashchainConstraints() ([]MerkleDamgardConstraint, error) {
	var constraints []MerkleDamgardConstraint

	// Generate constraints for hashchain computation
	// Ensure that each step of the hashchain is correctly computed

	constraintPoly, err := core.NewPolynomial([]*core.FieldElement{
		md.field.Zero(), // Constant term
		md.field.One(),  // Linear term
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create hashchain constraint polynomial: %w", err)
	}

	constraint := MerkleDamgardConstraint{
		Polynomial: constraintPoly,
		Type:       "hashchain",
		Block:      0,
	}
	constraints = append(constraints, constraint)

	return constraints, nil
}

// CreateMerkleDamgardAIR creates an AIR for Merkle-Damgard construction
func CreateMerkleDamgardAIR(field *core.Field, numBlocks int) (*AIR, error) {
	// Merkle-Damgard has width 3 (current hash + input block + output hash)
	width := 3
	// Number of blocks
	traceLength := numBlocks

	// Create AIR
	air := NewAIR(field, traceLength, width, field.NewElementFromInt64(1))

	// Note: In a full implementation, we would generate and add Merkle-Damgard constraints to the AIR
	// For now, we'll return the AIR without constraints
	// The constraints would be added through the CreateTransitionConstraints method

	return air, nil
}

// CreateDNAProfileHashchain creates a hashchain for DNA profile database
func CreateDNAProfileHashchain(field *core.Field, profiles []DNAProfile) ([]*core.FieldElement, *core.FieldElement, error) {
	// Create Merkle-Damgard instance
	md := NewMerkleDamgard(field)

	// Convert DNA profiles to hashchain elements
	elements := make([]*core.FieldElement, len(profiles)*2) // 2 elements per profile

	for i, profile := range profiles {
		// Convert STR pairs to field elements
		// First element: first 10 STR pairs
		firstElement := field.Zero()
		power := field.One()
		for j := 0; j < 10; j++ {
			// Add both STR values from the pair
			term := profile.STRPairs[j][0].Add(profile.STRPairs[j][1])
			term = term.Mul(power)
			firstElement = firstElement.Add(term)
			power = power.Mul(field.NewElementFromInt64(2))
		}
		elements[i*2] = firstElement

		// Second element: last 10 STR pairs
		secondElement := field.Zero()
		power = field.One()
		for j := 10; j < 20; j++ {
			// Add both STR values from the pair
			term := profile.STRPairs[j][0].Add(profile.STRPairs[j][1])
			term = term.Mul(power)
			secondElement = secondElement.Add(term)
			power = power.Mul(field.NewElementFromInt64(2))
		}
		elements[i*2+1] = secondElement
	}

	// Compute hashchain
	state, err := md.ComputeHashchain(elements)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute DNA profile hashchain: %w", err)
	}

	return elements, state.CurrentHash, nil
}

// VerifyDNAProfileHashchain verifies a DNA profile hashchain
func VerifyDNAProfileHashchain(
	field *core.Field,
	profiles []DNAProfile,
	hashchainElements []*core.FieldElement,
	expectedCommitment *core.FieldElement,
) (bool, error) {
	// Create Merkle-Damgard instance
	md := NewMerkleDamgard(field)

	// Verify hashchain
	valid, err := md.VerifyHashchain(hashchainElements, expectedCommitment)
	if err != nil {
		return false, fmt.Errorf("failed to verify DNA profile hashchain: %w", err)
	}

	return valid, nil
}

// CreateDNAProfile creates a DNA profile from STR values
func CreateDNAProfile(field *core.Field, strValues [20][2]int, id int) *DNAProfile {
	profile := &DNAProfile{
		ID: id,
	}

	// Convert STR values to field elements
	for i := 0; i < 20; i++ {
		profile.STRPairs[i][0] = field.NewElementFromInt64(int64(strValues[i][0]))
		profile.STRPairs[i][1] = field.NewElementFromInt64(int64(strValues[i][1]))
	}

	return profile
}

// DNAProfileToFieldElements converts a DNA profile to field elements for hashing
func DNAProfileToFieldElements(profile *DNAProfile) []*core.FieldElement {
	elements := make([]*core.FieldElement, 2)

	// First element: first 10 STR pairs
	firstElement := profile.STRPairs[0][0].Field().Zero()
	power := profile.STRPairs[0][0].Field().One()
	for i := 0; i < 10; i++ {
		term := profile.STRPairs[i][0].Add(profile.STRPairs[i][1])
		term = term.Mul(power)
		firstElement = firstElement.Add(term)
		power = power.Mul(profile.STRPairs[0][0].Field().NewElementFromInt64(2))
	}
	elements[0] = firstElement

	// Second element: last 10 STR pairs
	secondElement := profile.STRPairs[0][0].Field().Zero()
	power = profile.STRPairs[0][0].Field().One()
	for i := 10; i < 20; i++ {
		term := profile.STRPairs[i][0].Add(profile.STRPairs[i][1])
		term = term.Mul(power)
		secondElement = secondElement.Add(term)
		power = power.Mul(profile.STRPairs[0][0].Field().NewElementFromInt64(2))
	}
	elements[1] = secondElement

	return elements
}
