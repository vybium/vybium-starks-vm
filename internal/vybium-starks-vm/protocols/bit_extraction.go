package protocols

import (
	"fmt"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
)

// BitExtraction implements efficient bit extraction constraints for field elements
// Based on the techniques described in the STARKs paper for SHA2 implementation
type BitExtraction struct {
	field *core.Field
	// Precomputed constants for bit extraction
	alphaConstants []*core.FieldElement
}

// BitExtractionConstraint represents a constraint for bit extraction
type BitExtractionConstraint struct {
	// The field element to extract bits from
	Input *core.FieldElement
	// The extracted bit value
	Output *core.FieldElement
	// The bit position to extract
	BitPosition int
	// The constraint polynomial
	Polynomial *core.Polynomial
}

// NewBitExtraction creates a new bit extraction instance
func NewBitExtraction(field *core.Field) *BitExtraction {
	// Precompute alpha constants for bit extraction
	// These are field elements that depend only on the bit position
	alphaConstants := make([]*core.FieldElement, 256) // Support up to 256-bit fields

	// For each bit position, compute the corresponding alpha constant
	// This uses the technique from the paper: isZero(α, w, v) = w² + w + α·v
	for i := 0; i < 256; i++ {
		// In a full implementation, these would be computed using the trace function
		// For now, we'll use a simplified approach
		alphaConstants[i] = field.NewElementFromInt64(int64(i + 1))
	}

	return &BitExtraction{
		field:          field,
		alphaConstants: alphaConstants,
	}
}

// ExtractBit extracts the i-th bit from a field element
func (be *BitExtraction) ExtractBit(element *core.FieldElement, bitPosition int) (*core.FieldElement, error) {
	if bitPosition < 0 || bitPosition >= len(be.alphaConstants) {
		return nil, fmt.Errorf("bit position %d out of range [0, %d)", bitPosition, len(be.alphaConstants))
	}

	// Use the isZero constraint to extract the bit
	// The i-th bit of y is 0 if and only if there exists w such that w² + w + αᵢ·y = 0
	// where αᵢ is the precomputed constant for bit position i

	alpha := be.alphaConstants[bitPosition]

	// For simplicity, we'll use a basic bit extraction
	// In a full implementation, this would use proper field arithmetic
	// to determine if the bit is 0 or 1

	// Compute αᵢ·y
	alphaY := alpha.Mul(element)

	// For demo purposes, we'll use a simplified bit extraction
	// In practice, this would involve solving the quadratic equation w² + w + αᵢ·y = 0
	// and checking if it has solutions in the field

	// If αᵢ·y is zero, then the bit is 0
	if alphaY.IsZero() {
		return be.field.Zero(), nil
	}

	// Otherwise, we need to check if the quadratic equation has solutions
	// This is done using the trace function: Tr(αᵢ·y) = 0 if and only if solutions exist
	trace := be.computeTrace(alphaY)

	if trace.IsZero() {
		// The equation has solutions, so the bit is 0
		return be.field.Zero(), nil
	} else {
		// The equation has no solutions, so the bit is 1
		return be.field.One(), nil
	}
}

// computeTrace computes the trace of a field element
func (be *BitExtraction) computeTrace(element *core.FieldElement) *core.FieldElement {
	// Trace function: Tr(y) = Σᵢ₌₀ᵐ⁻¹ y^(2^i)
	// where m is the degree of the field extension

	// For F_2^m, the trace is computed as the sum of all conjugates
	trace := element
	current := element

	// Compute y^(2^i) for i = 1, 2, ..., m-1
	// For simplicity, we'll use a basic approach
	// In a full implementation, this would use proper field arithmetic
	for i := 1; i < 8; i++ { // Assuming F_2^8 for demo
		current = current.Mul(current) // Square the element
		trace = trace.Add(current)
	}

	return trace
}

// GenerateBitExtractionConstraints generates constraints for bit extraction
func (be *BitExtraction) GenerateBitExtractionConstraints(element *core.FieldElement, bitPosition int) (*BitExtractionConstraint, error) {
	// Extract the bit
	bitValue, err := be.ExtractBit(element, bitPosition)
	if err != nil {
		return nil, fmt.Errorf("failed to extract bit: %w", err)
	}

	// Create constraint polynomial
	// The constraint is: isZero(αᵢ, w, y) = w² + w + αᵢ·y = 0
	// where w is a witness variable and αᵢ is the constant for bit position i

	alpha := be.alphaConstants[bitPosition]

	// Create polynomial: w² + w + αᵢ·y
	// This represents the constraint that must be satisfied
	constraintPoly, err := core.NewPolynomial([]*core.FieldElement{
		alpha.Mul(element), // Constant term: αᵢ·y
		be.field.One(),     // Linear term: w
		be.field.One(),     // Quadratic term: w²
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create constraint polynomial: %w", err)
	}

	return &BitExtractionConstraint{
		Input:       element,
		Output:      bitValue,
		BitPosition: bitPosition,
		Polynomial:  constraintPoly,
	}, nil
}

// ExtractMultipleBits extracts multiple bits from a field element
func (be *BitExtraction) ExtractMultipleBits(element *core.FieldElement, bitPositions []int) ([]*core.FieldElement, error) {
	bits := make([]*core.FieldElement, len(bitPositions))

	for i, pos := range bitPositions {
		bit, err := be.ExtractBit(element, pos)
		if err != nil {
			return nil, fmt.Errorf("failed to extract bit %d: %w", pos, err)
		}
		bits[i] = bit
	}

	return bits, nil
}

// GenerateMultipleBitConstraints generates constraints for multiple bit extractions
func (be *BitExtraction) GenerateMultipleBitConstraints(element *core.FieldElement, bitPositions []int) ([]*BitExtractionConstraint, error) {
	var constraints []*BitExtractionConstraint

	for _, pos := range bitPositions {
		constraint, err := be.GenerateBitExtractionConstraints(element, pos)
		if err != nil {
			return nil, fmt.Errorf("failed to generate constraint for bit %d: %w", pos, err)
		}
		constraints = append(constraints, constraint)
	}

	return constraints, nil
}

// IsZeroConstraint represents the isZero constraint from the paper
type IsZeroConstraint struct {
	// The field element to check
	Element *core.FieldElement
	// The witness variable
	Witness *core.FieldElement
	// The alpha constant
	Alpha *core.FieldElement
	// The constraint polynomial: w² + w + α·v
	Polynomial *core.Polynomial
}

// CreateIsZeroConstraint creates an isZero constraint
func (be *BitExtraction) CreateIsZeroConstraint(element *core.FieldElement, alpha *core.FieldElement) (*IsZeroConstraint, error) {
	// Create polynomial: w² + w + α·v
	// where w is the witness variable and v is the element
	alphaV := alpha.Mul(element)

	constraintPoly, err := core.NewPolynomial([]*core.FieldElement{
		alphaV,         // Constant term: α·v
		be.field.One(), // Linear term: w
		be.field.One(), // Quadratic term: w²
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create isZero constraint polynomial: %w", err)
	}

	return &IsZeroConstraint{
		Element:    element,
		Witness:    be.field.Zero(), // Will be set by the prover
		Alpha:      alpha,
		Polynomial: constraintPoly,
	}, nil
}

// VerifyBitExtraction verifies that a bit extraction constraint is satisfied
func (be *BitExtraction) VerifyBitExtraction(constraint *BitExtractionConstraint, witness *core.FieldElement) (bool, error) {
	// Verify that the constraint polynomial evaluates to zero
	// when the witness variable is set to the correct value

	// Evaluate the constraint polynomial at the witness
	evaluation := constraint.Polynomial.Eval(witness)

	// The constraint is satisfied if the evaluation is zero
	return evaluation.IsZero(), nil
}

// CreateBitExtractionAIR creates an AIR for bit extraction operations
func CreateBitExtractionAIR(field *core.Field, numBits int) (*AIR, error) {
	// Create AIR for bit extraction
	// Width: 1 input element + numBits output bits + numBits witness variables
	width := 1 + numBits + numBits
	traceLength := 1 // Single step operation

	// Create AIR
	air := NewAIR(field, traceLength, width, field.NewElementFromInt64(1))

	// Note: In a full implementation, we would generate and add bit extraction constraints to the AIR
	// For now, we'll return the AIR without constraints
	// The constraints would be added through the CreateTransitionConstraints method

	return air, nil
}

// FieldElementToBits converts a field element to its bit representation
func (be *BitExtraction) FieldElementToBits(element *core.FieldElement, numBits int) ([]*core.FieldElement, error) {
	bits := make([]*core.FieldElement, numBits)

	for i := 0; i < numBits; i++ {
		bit, err := be.ExtractBit(element, i)
		if err != nil {
			return nil, fmt.Errorf("failed to extract bit %d: %w", i, err)
		}
		bits[i] = bit
	}

	return bits, nil
}

// BitsToFieldElement converts a bit array to a field element
func (be *BitExtraction) BitsToFieldElement(bits []*core.FieldElement) (*core.FieldElement, error) {
	if len(bits) == 0 {
		return be.field.Zero(), nil
	}

	result := be.field.Zero()
	power := be.field.One()

	for _, bit := range bits {
		// Add bit * 2^i to result
		term := bit.Mul(power)
		result = result.Add(term)

		// Update power for next iteration
		power = power.Mul(be.field.NewElementFromInt64(2))
	}

	return result, nil
}
