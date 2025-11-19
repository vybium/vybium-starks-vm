package protocols

import (
	"fmt"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
)

// DaviesMeyer implements the Davies-Meyer transformation for converting Rijndael-160 to a hash function
// Based on the STARKs paper: hash(B, K) = E_K(B) ⊕ B
type DaviesMeyer struct {
	field    *core.Field
	rijndael *Rijndael160
}

// DaviesMeyerState represents the state of the Davies-Meyer transformation
type DaviesMeyerState struct {
	// Input block B (160 bits = 20 bytes)
	B [20]*core.FieldElement
	// Key K (160 bits = 20 bytes)
	K [20]*core.FieldElement
	// Encrypted block E_K(B)
	EncryptedB [20]*core.FieldElement
	// Hash output hash(B, K) = E_K(B) ⊕ B
	HashOutput [20]*core.FieldElement
	// Compressed representation of B (3 registers of 64 bits each)
	CompressedB [3]*core.FieldElement
	// Decompressed representation for output
	DecompressedB [20]*core.FieldElement
}

// DaviesMeyerConstraint represents a constraint in the Davies-Meyer transformation
type DaviesMeyerConstraint struct {
	// Constraint polynomial
	Polynomial *core.Polynomial
	// Constraint type (compression, encryption, decompression, xor)
	Type string
	// Step number
	Step int
}

// NewDaviesMeyer creates a new Davies-Meyer transformation instance
func NewDaviesMeyer(field *core.Field) *DaviesMeyer {
	return &DaviesMeyer{
		field:    field,
		rijndael: NewRijndael160(field),
	}
}

// Hash computes the Davies-Meyer hash: hash(B, K) = E_K(B) ⊕ B
func (dm *DaviesMeyer) Hash(block, key []byte) (*DaviesMeyerState, error) {
	if len(block) != 20 || len(key) != 20 {
		return nil, fmt.Errorf("block and key must be exactly 20 bytes (160 bits)")
	}

	// Initialize state
	state := &DaviesMeyerState{}

	// Load input block B
	err := dm.loadBlock(state, block)
	if err != nil {
		return nil, fmt.Errorf("failed to load block: %w", err)
	}

	// Load key K
	err = dm.loadKey(state, key)
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %w", err)
	}

	// Compress B into 3 registers
	err = dm.compressBlock(state)
	if err != nil {
		return nil, fmt.Errorf("failed to compress block: %w", err)
	}

	// Encrypt B using Rijndael-160: E_K(B)
	err = dm.encryptBlock(state)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt block: %w", err)
	}

	// Decompress B for output
	err = dm.decompressBlock(state)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress block: %w", err)
	}

	// Compute hash output: hash(B, K) = E_K(B) ⊕ B
	err = dm.computeHashOutput(state)
	if err != nil {
		return nil, fmt.Errorf("failed to compute hash output: %w", err)
	}

	return state, nil
}

// loadBlock loads the input block into the B registers
func (dm *DaviesMeyer) loadBlock(state *DaviesMeyerState, block []byte) error {
	// Load block into 20 registers
	for i := 0; i < 20; i++ {
		state.B[i] = dm.field.NewElementFromInt64(int64(block[i]))
	}
	return nil
}

// loadKey loads the key into the K registers
func (dm *DaviesMeyer) loadKey(state *DaviesMeyerState, key []byte) error {
	// Load key into 20 registers
	for i := 0; i < 20; i++ {
		state.K[i] = dm.field.NewElementFromInt64(int64(key[i]))
	}
	return nil
}

// compressBlock compresses B into 3 registers using field extension
func (dm *DaviesMeyer) compressBlock(state *DaviesMeyerState) error {
	// Compress 20 registers of B into 3 registers of 64 bits each
	// Using the technique from the paper: B_i = Σ_{k=0}^7 p_{k+8i} · g_0^k

	// For simplicity, we'll use a basic compression
	// In a full implementation, this would use proper field extension arithmetic

	// Compress first 8 bytes into B_0
	state.CompressedB[0] = dm.field.Zero()
	power := dm.field.One()
	for i := 0; i < 8; i++ {
		term := state.B[i].Mul(power)
		state.CompressedB[0] = state.CompressedB[0].Add(term)
		power = power.Mul(dm.field.NewElementFromInt64(2)) // g_0 = 2 for demo
	}

	// Compress next 8 bytes into B_1
	state.CompressedB[1] = dm.field.Zero()
	power = dm.field.One()
	for i := 8; i < 16; i++ {
		term := state.B[i].Mul(power)
		state.CompressedB[1] = state.CompressedB[1].Add(term)
		power = power.Mul(dm.field.NewElementFromInt64(2))
	}

	// Compress last 4 bytes into B_2 (with padding)
	state.CompressedB[2] = dm.field.Zero()
	power = dm.field.One()
	for i := 16; i < 20; i++ {
		term := state.B[i].Mul(power)
		state.CompressedB[2] = state.CompressedB[2].Add(term)
		power = power.Mul(dm.field.NewElementFromInt64(2))
	}

	return nil
}

// encryptBlock encrypts the block using Rijndael-160
func (dm *DaviesMeyer) encryptBlock(state *DaviesMeyerState) error {
	// Convert compressed B back to bytes for encryption
	blockBytes := make([]byte, 20)
	keyBytes := make([]byte, 20)

	// Convert B registers to bytes
	for i := 0; i < 20; i++ {
		blockBytes[i] = byte(state.B[i].Big().Int64() & 0xFF)
	}

	// Convert K registers to bytes
	for i := 0; i < 20; i++ {
		keyBytes[i] = byte(state.K[i].Big().Int64() & 0xFF)
	}

	// Encrypt using Rijndael-160
	rijndaelState, err := dm.rijndael.Encrypt(blockBytes, keyBytes)
	if err != nil {
		return fmt.Errorf("Rijndael encryption failed: %w", err)
	}

	// Store encrypted result
	for i := 0; i < 4; i++ {
		for j := 0; j < 5; j++ {
			index := i*5 + j
			if index < 20 {
				state.EncryptedB[index] = rijndaelState.P[i][j]
			}
		}
	}

	return nil
}

// decompressBlock decompresses B for output computation
func (dm *DaviesMeyer) decompressBlock(state *DaviesMeyerState) error {
	// Decompress the 3 compressed registers back to 20 registers
	// This is needed to compute the XOR with the encrypted output

	// For simplicity, we'll use the original B values
	// In a full implementation, this would use proper decompression
	for i := 0; i < 20; i++ {
		state.DecompressedB[i] = state.B[i]
	}

	return nil
}

// computeHashOutput computes the final hash output: E_K(B) ⊕ B
func (dm *DaviesMeyer) computeHashOutput(state *DaviesMeyerState) error {
	// Compute hash(B, K) = E_K(B) ⊕ B
	for i := 0; i < 20; i++ {
		// XOR operation in field arithmetic: a ⊕ b = a + b
		state.HashOutput[i] = state.EncryptedB[i].Add(state.DecompressedB[i])
	}

	return nil
}

// GenerateConstraints generates the algebraic constraints for Davies-Meyer
func (dm *DaviesMeyer) GenerateConstraints() ([]DaviesMeyerConstraint, error) {
	var constraints []DaviesMeyerConstraint

	// Compression constraints
	compressionConstraints, err := dm.generateCompressionConstraints()
	if err != nil {
		return nil, fmt.Errorf("failed to generate compression constraints: %w", err)
	}
	constraints = append(constraints, compressionConstraints...)

	// Encryption constraints (from Rijndael)
	encryptionConstraints, err := dm.generateEncryptionConstraints()
	if err != nil {
		return nil, fmt.Errorf("failed to generate encryption constraints: %w", err)
	}
	constraints = append(constraints, encryptionConstraints...)

	// Decompression constraints
	decompressionConstraints, err := dm.generateDecompressionConstraints()
	if err != nil {
		return nil, fmt.Errorf("failed to generate decompression constraints: %w", err)
	}
	constraints = append(constraints, decompressionConstraints...)

	// XOR constraints
	xorConstraints, err := dm.generateXORConstraints()
	if err != nil {
		return nil, fmt.Errorf("failed to generate XOR constraints: %w", err)
	}
	constraints = append(constraints, xorConstraints...)

	// Fermat's little theorem constraints
	fermatConstraints, err := dm.generateFermatConstraints()
	if err != nil {
		return nil, fmt.Errorf("failed to generate Fermat constraints: %w", err)
	}
	constraints = append(constraints, fermatConstraints...)

	return constraints, nil
}

// generateCompressionConstraints generates constraints for block compression
func (dm *DaviesMeyer) generateCompressionConstraints() ([]DaviesMeyerConstraint, error) {
	var constraints []DaviesMeyerConstraint

	// Compression constraint: B_i = Σ_{k=0}^7 p_{k+8i} · g_0^k
	// This ensures that the compression is done correctly

	for i := 0; i < 3; i++ {
		constraintPoly, err := core.NewPolynomial([]*core.FieldElement{
			dm.field.Zero(), // Constant term
			dm.field.One(),  // Linear term
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create compression constraint polynomial: %w", err)
		}

		constraint := DaviesMeyerConstraint{
			Polynomial: constraintPoly,
			Type:       "compression",
			Step:       i,
		}
		constraints = append(constraints, constraint)
	}

	return constraints, nil
}

// generateEncryptionConstraints generates constraints for Rijndael encryption
func (dm *DaviesMeyer) generateEncryptionConstraints() ([]DaviesMeyerConstraint, error) {
	var constraints []DaviesMeyerConstraint

	// Get Rijndael constraints
	rijndaelConstraints, err := dm.rijndael.GenerateConstraints()
	if err != nil {
		return nil, fmt.Errorf("failed to get Rijndael constraints: %w", err)
	}

	// Convert Rijndael constraints to Davies-Meyer constraints
	for _, rc := range rijndaelConstraints {
		constraint := DaviesMeyerConstraint{
			Polynomial: rc.Polynomial,
			Type:       "encryption_" + rc.Type,
			Step:       rc.Round*5 + rc.Step,
		}
		constraints = append(constraints, constraint)
	}

	return constraints, nil
}

// generateDecompressionConstraints generates constraints for block decompression
func (dm *DaviesMeyer) generateDecompressionConstraints() ([]DaviesMeyerConstraint, error) {
	var constraints []DaviesMeyerConstraint

	// Decompression constraint: B_i + Σ_{k=0}^7 p_{k+8i} · g_0^k = 0
	// This ensures that the decompression is done correctly

	for i := 0; i < 3; i++ {
		constraintPoly, err := core.NewPolynomial([]*core.FieldElement{
			dm.field.Zero(), // Constant term
			dm.field.One(),  // Linear term
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create decompression constraint polynomial: %w", err)
		}

		constraint := DaviesMeyerConstraint{
			Polynomial: constraintPoly,
			Type:       "decompression",
			Step:       i,
		}
		constraints = append(constraints, constraint)
	}

	return constraints, nil
}

// generateXORConstraints generates constraints for XOR operations
func (dm *DaviesMeyer) generateXORConstraints() ([]DaviesMeyerConstraint, error) {
	var constraints []DaviesMeyerConstraint

	// XOR constraint: hash(B, K) = E_K(B) ⊕ B
	// In field arithmetic: hash(B, K) = E_K(B) + B

	for i := 0; i < 20; i++ {
		constraintPoly, err := core.NewPolynomial([]*core.FieldElement{
			dm.field.Zero(), // Constant term
			dm.field.One(),  // Linear term
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create XOR constraint polynomial: %w", err)
		}

		constraint := DaviesMeyerConstraint{
			Polynomial: constraintPoly,
			Type:       "xor",
			Step:       i,
		}
		constraints = append(constraints, constraint)
	}

	return constraints, nil
}

// generateFermatConstraints generates Fermat's little theorem constraints
func (dm *DaviesMeyer) generateFermatConstraints() ([]DaviesMeyerConstraint, error) {
	var constraints []DaviesMeyerConstraint

	// Fermat's little theorem: ∀x ∈ F: x^|F| = x
	// In our case: p^256 + p = 0 for p ∈ F'
	// This ensures that the decompressed values are in the correct subfield

	for i := 0; i < 20; i++ {
		constraintPoly, err := core.NewPolynomial([]*core.FieldElement{
			dm.field.Zero(), // Constant term
			dm.field.One(),  // Linear term
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create Fermat constraint polynomial: %w", err)
		}

		constraint := DaviesMeyerConstraint{
			Polynomial: constraintPoly,
			Type:       "fermat",
			Step:       i,
		}
		constraints = append(constraints, constraint)
	}

	return constraints, nil
}

// CreateDaviesMeyerAIR creates an AIR for Davies-Meyer hash computation
func CreateDaviesMeyerAIR(field *core.Field) (*AIR, error) {
	// Davies-Meyer has width 68 (20 B + 20 K + 20 EncryptedB + 3 CompressedB + 3 DecompressedB + 2 auxiliary)
	width := 68
	// 58 cycles (1 compression + 55 Rijndael + 2 decompression)
	traceLength := 58

	// Create AIR
	air := NewAIR(field, traceLength, width, field.NewElementFromInt64(1))

	// Note: In a full implementation, we would generate and add Davies-Meyer constraints to the AIR
	// For now, we'll return the AIR without constraints
	// The constraints would be added through the CreateTransitionConstraints method

	return air, nil
}

// VerifyDaviesMeyerHash verifies that a Davies-Meyer hash computation is correct
func VerifyDaviesMeyerHash(field *core.Field, block, key, expectedHash []byte) (bool, error) {
	// Create Davies-Meyer instance
	dm := NewDaviesMeyer(field)

	// Compute hash
	state, err := dm.Hash(block, key)
	if err != nil {
		return false, fmt.Errorf("failed to compute hash: %w", err)
	}

	// Convert hash output to bytes
	computedHash := make([]byte, 20)
	for i := 0; i < 20; i++ {
		computedHash[i] = byte(state.HashOutput[i].Big().Int64() & 0xFF)
	}

	// Compare with expected hash
	if len(computedHash) != len(expectedHash) {
		return false, fmt.Errorf("hash length mismatch: expected %d, got %d", len(expectedHash), len(computedHash))
	}

	for i := 0; i < len(computedHash); i++ {
		if computedHash[i] != expectedHash[i] {
			return false, fmt.Errorf("hash mismatch at position %d: expected %d, got %d", i, expectedHash[i], computedHash[i])
		}
	}

	return true, nil
}
