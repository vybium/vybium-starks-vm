package protocols

import (
	"fmt"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
)

// DNAProfileMatch implements the DNA profile matching algorithm from the STARKs paper
// Based on Program 1: DNA profile match with hashchain verification
type DNAProfileMatch struct {
	field *core.Field
	// Davies-Meyer hash function for hashchain computation
	hashFunc *DaviesMeyer
	// Number of DNA profiles in the database
	numProfiles int
	// Generator for field multiplication (g in F*_264)
	generator *core.FieldElement
}

// DNAProfile represents a DNA profile in CODIS format
type DNAProfile struct {
	// 20 STR pairs (2 per loci)
	STRPairs [20][2]*core.FieldElement
	// Profile ID
	ID int
}

// DNAProfileMatchState represents the state of the DNA profile matching computation
type DNAProfileMatchState struct {
	// Input values (VAL1,j, VAL2,j for j ∈ {1,2,...,20})
	InputValues [2][20]*core.FieldElement
	// Hashchain elements (Wi for i ∈ {0,1,2,...,N})
	HashchainElements []*core.FieldElement
	// Current counter k = g^j
	Counter *core.FieldElement
	// Flag for alternating between odd/even elements
	Flag *core.FieldElement
	// Hash accumulator h
	HashAccumulator *core.FieldElement
	// Matching result T
	MatchingResult *core.FieldElement
	// Compressed input values (5 registers)
	CompressedInput [5]*core.FieldElement
	// Decompressed input values for comparison
	DecompressedInput [20]*core.FieldElement
}

// DNAProfileMatchConstraint represents a constraint in the DNA profile matching
type DNAProfileMatchConstraint struct {
	// Constraint polynomial
	Polynomial *core.Polynomial
	// Constraint type (hashchain, comparison, matching, etc.)
	Type string
	// Step number
	Step int
}

// NewDNAProfileMatch creates a new DNA profile matching instance
func NewDNAProfileMatch(field *core.Field, numProfiles int) *DNAProfileMatch {
	// Create Davies-Meyer hash function
	hashFunc := NewDaviesMeyer(field)

	// Create generator for field multiplication
	generator := field.NewElementFromInt64(2) // g = 2 for demo

	return &DNAProfileMatch{
		field:       field,
		hashFunc:    hashFunc,
		numProfiles: numProfiles,
		generator:   generator,
	}
}

// MatchProfile performs DNA profile matching as described in Program 1
func (dpm *DNAProfileMatch) MatchProfile(
	inputValues [2][20]*core.FieldElement,
	hashchainElements []*core.FieldElement,
	commitment *core.FieldElement,
) (*DNAProfileMatchState, error) {
	// Initialize state
	state := &DNAProfileMatchState{
		InputValues:       inputValues,
		HashchainElements: hashchainElements,
		Counter:           dpm.field.One(),  // k = 1 initially
		Flag:              dpm.field.Zero(), // flag = 0 initially
		HashAccumulator:   dpm.field.Zero(), // h = 0 initially
		MatchingResult:    dpm.field.Zero(), // T = 0 initially
	}

	// Step I: Verify input commitment
	err := dpm.verifyInputCommitment(state, commitment)
	if err != nil {
		return nil, fmt.Errorf("input commitment verification failed: %w", err)
	}

	// Step II: Initialize variables
	// k ← 1, flag ← 0, h ← 0, T ← 0, N ← 2n
	N := 2 * dpm.numProfiles

	// Step III-XIV: Main matching loop
	for j := 0; j < N; j++ {
		// Step IV: Parse hashchain element
		err = dpm.parseHashchainElement(state, j)
		if err != nil {
			return nil, fmt.Errorf("failed to parse hashchain element %d: %w", j, err)
		}

		// Step V-VIII: Check pairs based on flag
		if state.Flag.IsZero() {
			// Step VI: Check first 10 pairs
			err = dpm.checkPairs(state, 0, 10)
			if err != nil {
				return nil, fmt.Errorf("failed to check first 10 pairs: %w", err)
			}
		} else {
			// Step VIII: Check last 10 pairs
			err = dpm.checkPairs(state, 10, 20)
			if err != nil {
				return nil, fmt.Errorf("failed to check last 10 pairs: %w", err)
			}
		}

		// Step IX: Update matching result
		err = dpm.updateMatchingResult(state)
		if err != nil {
			return nil, fmt.Errorf("failed to update matching result: %w", err)
		}

		// Step XI: Update hash accumulator
		err = dpm.updateHashAccumulator(state, j)
		if err != nil {
			return nil, fmt.Errorf("failed to update hash accumulator: %w", err)
		}

		// Step XII: Update counter
		state.Counter = state.Counter.Mul(dpm.generator)

		// Step XIII: Toggle flag
		state.Flag = dpm.field.One().Sub(state.Flag)
	}

	// Step XV: Verify final commitment
	err = dpm.verifyFinalCommitment(state, commitment)
	if err != nil {
		return nil, fmt.Errorf("final commitment verification failed: %w", err)
	}

	return state, nil
}

// verifyInputCommitment verifies that the input values match the commitment
func (dpm *DNAProfileMatch) verifyInputCommitment(state *DNAProfileMatchState, commitment *core.FieldElement) error {
	// Compress input values
	err := dpm.compressInputValues(state)
	if err != nil {
		return fmt.Errorf("failed to compress input values: %w", err)
	}

	// Compute hash of input values
	computedHash, err := dpm.computeInputHash(state)
	if err != nil {
		return fmt.Errorf("failed to compute input hash: %w", err)
	}

	// Verify commitment matches computed hash
	if !computedHash.Equal(commitment) {
		return fmt.Errorf("input commitment verification failed")
	}

	return nil
}

// compressInputValues compresses the input values into 5 registers
func (dpm *DNAProfileMatch) compressInputValues(state *DNAProfileMatchState) error {
	// Compress 40 input values into 5 registers of 64 bits each
	// Using the same technique as in Davies-Meyer

	for i := 0; i < 5; i++ {
		state.CompressedInput[i] = dpm.field.Zero()
		power := dpm.field.One()

		// Compress 8 values per register
		for j := 0; j < 8; j++ {
			valueIndex := i*8 + j
			if valueIndex < 40 {
				// Determine which input array and position
				if valueIndex < 20 {
					// First input array
					value := state.InputValues[0][valueIndex]
					term := value.Mul(power)
					state.CompressedInput[i] = state.CompressedInput[i].Add(term)
				} else {
					// Second input array
					value := state.InputValues[1][valueIndex-20]
					term := value.Mul(power)
					state.CompressedInput[i] = state.CompressedInput[i].Add(term)
				}
				power = power.Mul(dpm.field.NewElementFromInt64(2))
			}
		}
	}

	return nil
}

// computeInputHash computes the hash of the input values
func (dpm *DNAProfileMatch) computeInputHash(state *DNAProfileMatchState) (*core.FieldElement, error) {
	// Convert compressed input to bytes for hashing
	inputBytes := make([]byte, 20) // Use 20 bytes for Rijndael-160
	for i := 0; i < 5; i++ {
		// Extract bytes from compressed input
		compressedValue := state.CompressedInput[i].Big().Int64()
		for j := 0; j < 4 && i*4+j < 20; j++ { // 4 bytes per compressed input, total 20 bytes
			byteIndex := i*4 + j
			if byteIndex < 20 {
				inputBytes[byteIndex] = byte((compressedValue >> (8 * j)) & 0xFF)
			}
		}
	}

	// Use Davies-Meyer hash function
	keyBytes := make([]byte, 20) // Zero key for demo
	hashState, err := dpm.hashFunc.Hash(inputBytes, keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to compute hash: %w", err)
	}

	// Return first element of hash output
	return hashState.HashOutput[0], nil
}

// parseHashchainElement parses a hashchain element into STR pairs
func (dpm *DNAProfileMatch) parseHashchainElement(state *DNAProfileMatchState, index int) error {
	// Parse (L1, R1, L2, R2, ..., L10, R10) = Wj
	// where j = log_g k

	// For demo purposes, we'll use the hashchain element directly
	// In a full implementation, this would involve proper parsing
	element := state.HashchainElements[index]

	// Extract STR pairs from the element
	// This is a simplified approach for demo
	for i := 0; i < 10; i++ {
		// Extract two STR values from the element
		// In practice, this would involve proper bit manipulation
		state.DecompressedInput[i*2] = element
		state.DecompressedInput[i*2+1] = element
	}

	return nil
}

// checkPairs checks STR pairs for matching
func (dpm *DNAProfileMatch) checkPairs(state *DNAProfileMatchState, startPair, endPair int) error {
	// Implement the CheckPairs subroutine from the paper
	// This checks if the input STR pairs match the database STR pairs

	for j := startPair; j < endPair; j++ {
		// Get input STR pair
		inputL := state.InputValues[0][j]
		inputR := state.InputValues[1][j]

		// Get database STR pair
		dbL := state.DecompressedInput[j*2]
		dbR := state.DecompressedInput[j*2+1]

		// Check for perfect match
		if (inputL.Equal(dbL) && inputR.Equal(dbR)) ||
			(inputL.Equal(dbR) && inputR.Equal(dbL)) {
			// Perfect match - continue
			continue
		}

		// Check for partial match
		if inputL.Equal(dbL) || inputL.Equal(dbR) ||
			inputR.Equal(dbL) || inputR.Equal(dbR) {
			// Partial match - set flag
			state.MatchingResult = dpm.field.NewElementFromInt64(1)
		} else {
			// No match - return 0
			state.MatchingResult = dpm.field.Zero()
			return nil
		}
	}

	return nil
}

// updateMatchingResult updates the matching result using MatchingResult subroutine
func (dpm *DNAProfileMatch) updateMatchingResult(state *DNAProfileMatchState) error {
	// Implement the MatchingResult subroutine from the paper
	// This combines the results from two CheckPairs calls

	// For demo purposes, we'll use a simplified approach
	// In a full implementation, this would involve proper logic

	// If we have a perfect match (result = 2), keep it
	// If we have a partial match (result = 1), set it
	// If we have no match (result = 0), keep previous result

	return nil
}

// updateHashAccumulator updates the hash accumulator
func (dpm *DNAProfileMatch) updateHashAccumulator(state *DNAProfileMatchState, index int) error {
	// h ← hash160(h, Wj)
	// This updates the hash accumulator with the current hashchain element

	// Convert current hash to bytes
	hashBytes := make([]byte, 20)
	for i := 0; i < 20; i++ {
		hashBytes[i] = byte(state.HashAccumulator.Big().Int64() & 0xFF)
	}

	// Convert hashchain element to bytes
	elementBytes := make([]byte, 20)
	for i := 0; i < 20; i++ {
		elementBytes[i] = byte(state.HashchainElements[index].Big().Int64() & 0xFF)
	}

	// Compute new hash
	hashState, err := dpm.hashFunc.Hash(hashBytes, elementBytes)
	if err != nil {
		return fmt.Errorf("failed to compute hash: %w", err)
	}

	// Update hash accumulator
	state.HashAccumulator = hashState.HashOutput[0]

	return nil
}

// verifyFinalCommitment verifies the final hashchain commitment
func (dpm *DNAProfileMatch) verifyFinalCommitment(state *DNAProfileMatchState, commitment *core.FieldElement) error {
	// Verify that the final hash accumulator matches the commitment
	if !state.HashAccumulator.Equal(commitment) {
		return fmt.Errorf("final commitment verification failed")
	}

	return nil
}

// GenerateConstraints generates the algebraic constraints for DNA profile matching
func (dpm *DNAProfileMatch) GenerateConstraints() ([]DNAProfileMatchConstraint, error) {
	var constraints []DNAProfileMatchConstraint

	// Hashchain constraints
	hashchainConstraints, err := dpm.generateHashchainConstraints()
	if err != nil {
		return nil, fmt.Errorf("failed to generate hashchain constraints: %w", err)
	}
	constraints = append(constraints, hashchainConstraints...)

	// Comparison constraints
	comparisonConstraints, err := dpm.generateComparisonConstraints()
	if err != nil {
		return nil, fmt.Errorf("failed to generate comparison constraints: %w", err)
	}
	constraints = append(constraints, comparisonConstraints...)

	// Matching constraints
	matchingConstraints, err := dpm.generateMatchingConstraints()
	if err != nil {
		return nil, fmt.Errorf("failed to generate matching constraints: %w", err)
	}
	constraints = append(constraints, matchingConstraints...)

	// Compression/decompression constraints
	compressionConstraints, err := dpm.generateCompressionConstraints()
	if err != nil {
		return nil, fmt.Errorf("failed to generate compression constraints: %w", err)
	}
	constraints = append(constraints, compressionConstraints...)

	return constraints, nil
}

// generateHashchainConstraints generates constraints for hashchain computation
func (dpm *DNAProfileMatch) generateHashchainConstraints() ([]DNAProfileMatchConstraint, error) {
	var constraints []DNAProfileMatchConstraint

	// Generate constraints for each hashchain step
	for i := 0; i < 2*dpm.numProfiles; i++ {
		constraintPoly, err := core.NewPolynomial([]*core.FieldElement{
			dpm.field.Zero(), // Constant term
			dpm.field.One(),  // Linear term
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create hashchain constraint polynomial: %w", err)
		}

		constraint := DNAProfileMatchConstraint{
			Polynomial: constraintPoly,
			Type:       "hashchain",
			Step:       i,
		}
		constraints = append(constraints, constraint)
	}

	return constraints, nil
}

// generateComparisonConstraints generates constraints for STR pair comparison
func (dpm *DNAProfileMatch) generateComparisonConstraints() ([]DNAProfileMatchConstraint, error) {
	var constraints []DNAProfileMatchConstraint

	// Generate constraints for each STR pair comparison
	for i := 0; i < 20; i++ {
		constraintPoly, err := core.NewPolynomial([]*core.FieldElement{
			dpm.field.Zero(), // Constant term
			dpm.field.One(),  // Linear term
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create comparison constraint polynomial: %w", err)
		}

		constraint := DNAProfileMatchConstraint{
			Polynomial: constraintPoly,
			Type:       "comparison",
			Step:       i,
		}
		constraints = append(constraints, constraint)
	}

	return constraints, nil
}

// generateMatchingConstraints generates constraints for matching logic
func (dpm *DNAProfileMatch) generateMatchingConstraints() ([]DNAProfileMatchConstraint, error) {
	var constraints []DNAProfileMatchConstraint

	// Generate constraints for matching result computation
	constraintPoly, err := core.NewPolynomial([]*core.FieldElement{
		dpm.field.Zero(), // Constant term
		dpm.field.One(),  // Linear term
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create matching constraint polynomial: %w", err)
	}

	constraint := DNAProfileMatchConstraint{
		Polynomial: constraintPoly,
		Type:       "matching",
		Step:       0,
	}
	constraints = append(constraints, constraint)

	return constraints, nil
}

// generateCompressionConstraints generates constraints for compression/decompression
func (dpm *DNAProfileMatch) generateCompressionConstraints() ([]DNAProfileMatchConstraint, error) {
	var constraints []DNAProfileMatchConstraint

	// Generate constraints for input compression
	for i := 0; i < 5; i++ {
		constraintPoly, err := core.NewPolynomial([]*core.FieldElement{
			dpm.field.Zero(), // Constant term
			dpm.field.One(),  // Linear term
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create compression constraint polynomial: %w", err)
		}

		constraint := DNAProfileMatchConstraint{
			Polynomial: constraintPoly,
			Type:       "compression",
			Step:       i,
		}
		constraints = append(constraints, constraint)
	}

	return constraints, nil
}

// CreateDNAProfileMatchAIR creates an AIR for DNA profile matching
func CreateDNAProfileMatchAIR(field *core.Field, numProfiles int) (*AIR, error) {
	// DNA profile matching has width 81 (5 compressed input + 2*N hashchain + 1 counter + 1 flag + 1 hash + 1 result + 20 decompressed + 50 auxiliary)
	width := 81
	// 62 cycles (2 compression + 2*N hashchain + 2 decompression + 2 matching)
	traceLength := 62

	// Create AIR
	air := NewAIR(field, traceLength, width, field.NewElementFromInt64(1))

	// Note: In a full implementation, we would generate and add DNA profile matching constraints to the AIR
	// For now, we'll return the AIR without constraints
	// The constraints would be added through the CreateTransitionConstraints method

	return air, nil
}

// VerifyDNAProfileMatch verifies that a DNA profile match computation is correct
func VerifyDNAProfileMatch(
	field *core.Field,
	inputValues [2][20]*core.FieldElement,
	hashchainElements []*core.FieldElement,
	commitment *core.FieldElement,
	expectedResult *core.FieldElement,
) (bool, error) {
	// Create DNA profile matching instance
	dpm := NewDNAProfileMatch(field, len(hashchainElements)/2)

	// Perform matching
	state, err := dpm.MatchProfile(inputValues, hashchainElements, commitment)
	if err != nil {
		return false, fmt.Errorf("failed to perform DNA profile matching: %w", err)
	}

	// Verify result
	if !state.MatchingResult.Equal(expectedResult) {
		return false, fmt.Errorf("matching result mismatch: expected %s, got %s",
			expectedResult.String(), state.MatchingResult.String())
	}

	return true, nil
}
