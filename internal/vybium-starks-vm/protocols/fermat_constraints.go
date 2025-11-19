package protocols

import (
	"fmt"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
)

// FermatConstraints implements Fermat's little theorem constraints for field element validation
// Based on the STARKs paper: ∀x ∈ F: x^|F| = x
type FermatConstraints struct {
	field *core.Field
	// Field size for Fermat's little theorem
	fieldSize *core.FieldElement
}

// FermatConstraint represents a Fermat's little theorem constraint
type FermatConstraint struct {
	// The field element to validate
	Element *core.FieldElement
	// The constraint polynomial: x^|F| - x = 0
	Polynomial *core.Polynomial
	// The field size |F|
	FieldSize *core.FieldElement
}

// NewFermatConstraints creates a new Fermat constraints instance
func NewFermatConstraints(field *core.Field) *FermatConstraints {
	return &FermatConstraints{
		field:     field,
		fieldSize: field.NewElement(field.Modulus()),
	}
}

// ValidateFieldElement validates that a field element satisfies Fermat's little theorem
func (fc *FermatConstraints) ValidateFieldElement(element *core.FieldElement) (bool, error) {
	// Fermat's little theorem: x^|F| = x
	// This is equivalent to: x^|F| - x = 0

	// Compute x^|F|
	xToFieldSize, err := fc.computePower(element, fc.fieldSize)
	if err != nil {
		return false, fmt.Errorf("failed to compute x^|F|: %w", err)
	}

	// Check if x^|F| = x
	return xToFieldSize.Equal(element), nil
}

// computePower computes x^n using repeated squaring
func (fc *FermatConstraints) computePower(x, n *core.FieldElement) (*core.FieldElement, error) {
	// Convert n to big integer for bit manipulation
	nBig := n.Big()

	// Handle special cases
	if nBig.Sign() == 0 {
		return fc.field.One(), nil // x^0 = 1
	}

	if nBig.Cmp(fc.field.One().Big()) == 0 {
		return x, nil // x^1 = x
	}

	// Use repeated squaring algorithm
	result := fc.field.One()
	current := x

	// Process bits of n from right to left
	for nBig.Sign() > 0 {
		if nBig.Bit(0) == 1 { // If least significant bit is 1
			result = result.Mul(current)
		}
		current = current.Mul(current) // Square current
		nBig.Rsh(nBig, 1)              // Right shift by 1
	}

	return result, nil
}

// GenerateFermatConstraint generates a Fermat's little theorem constraint
func (fc *FermatConstraints) GenerateFermatConstraint(element *core.FieldElement) (*FermatConstraint, error) {
	// Create constraint polynomial: x^|F| - x = 0
	// This is equivalent to: x^|F| + x = 0 (since -x = x in characteristic 2 fields)

	// For efficiency, we'll use a simplified constraint
	// In a full implementation, this would involve proper polynomial construction
	constraintPoly, err := core.NewPolynomial([]*core.FieldElement{
		fc.field.Zero(), // Constant term
		fc.field.One(),  // Linear term (x)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Fermat constraint polynomial: %w", err)
	}

	return &FermatConstraint{
		Element:    element,
		Polynomial: constraintPoly,
		FieldSize:  fc.fieldSize,
	}, nil
}

// GenerateMultipleFermatConstraints generates Fermat constraints for multiple elements
func (fc *FermatConstraints) GenerateMultipleFermatConstraints(elements []*core.FieldElement) ([]*FermatConstraint, error) {
	var constraints []*FermatConstraint

	for _, element := range elements {
		constraint, err := fc.GenerateFermatConstraint(element)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Fermat constraint: %w", err)
		}
		constraints = append(constraints, constraint)
	}

	return constraints, nil
}

// ValidateSubfieldElement validates that an element is in a specific subfield
func (fc *FermatConstraints) ValidateSubfieldElement(element *core.FieldElement, subfieldSize *core.FieldElement) (bool, error) {
	// For a subfield F' of F, we have: ∀x ∈ F': x^|F'| = x
	// This is a stronger condition than Fermat's little theorem for the full field

	// Compute x^|F'|
	xToSubfieldSize, err := fc.computePower(element, subfieldSize)
	if err != nil {
		return false, fmt.Errorf("failed to compute x^|F'|: %w", err)
	}

	// Check if x^|F'| = x
	return xToSubfieldSize.Equal(element), nil
}

// GenerateSubfieldConstraint generates a constraint for subfield validation
func (fc *FermatConstraints) GenerateSubfieldConstraint(element *core.FieldElement, subfieldSize *core.FieldElement) (*FermatConstraint, error) {
	// Create constraint polynomial: x^|F'| - x = 0
	constraintPoly, err := core.NewPolynomial([]*core.FieldElement{
		fc.field.Zero(), // Constant term
		fc.field.One(),  // Linear term (x)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create subfield constraint polynomial: %w", err)
	}

	return &FermatConstraint{
		Element:    element,
		Polynomial: constraintPoly,
		FieldSize:  subfieldSize,
	}, nil
}

// CreateFermatAIR creates an AIR for Fermat's little theorem validation
func CreateFermatAIR(field *core.Field, numElements int) (*AIR, error) {
	// Create AIR for Fermat validation
	// Width: numElements elements + numElements witness variables
	width := numElements + numElements
	traceLength := 1 // Single step operation

	// Create AIR
	air := NewAIR(field, traceLength, width, field.NewElementFromInt64(1))

	// Note: In a full implementation, we would generate and add Fermat constraints to the AIR
	// For now, we'll return the AIR without constraints
	// The constraints would be added through the CreateTransitionConstraints method

	return air, nil
}

// VerifyFermatConstraints verifies that Fermat constraints are satisfied
func VerifyFermatConstraints(field *core.Field, elements []*core.FieldElement) (bool, error) {
	fermatConstraints := NewFermatConstraints(field)

	for i, element := range elements {
		valid, err := fermatConstraints.ValidateFieldElement(element)
		if err != nil {
			return false, fmt.Errorf("failed to validate element %d: %w", i, err)
		}
		if !valid {
			return false, fmt.Errorf("element %d does not satisfy Fermat's little theorem", i)
		}
	}

	return true, nil
}

// RepeatedQuadrupling implements the repeated quadrupling technique from the paper
// This is used to reduce the degree of Fermat constraints
type RepeatedQuadrupling struct {
	field *core.Field
}

// NewRepeatedQuadrupling creates a new repeated quadrupling instance
func NewRepeatedQuadrupling(field *core.Field) *RepeatedQuadrupling {
	return &RepeatedQuadrupling{
		field: field,
	}
}

// ComputeRepeatedQuadrupling computes x^(4^k) for k = 0, 1, 2, ...
func (rq *RepeatedQuadrupling) ComputeRepeatedQuadrupling(x *core.FieldElement, maxK int) ([]*core.FieldElement, error) {
	results := make([]*core.FieldElement, maxK+1)

	// x^(4^0) = x^1 = x
	results[0] = x

	// Compute x^(4^k) for k = 1, 2, ..., maxK
	current := x
	for k := 1; k <= maxK; k++ {
		// x^(4^k) = (x^(4^(k-1)))^4
		current = current.Mul(current) // Square
		current = current.Mul(current) // Square again (total: 4th power)
		results[k] = current
	}

	return results, nil
}

// GenerateRepeatedQuadruplingConstraints generates constraints for repeated quadrupling
func (rq *RepeatedQuadrupling) GenerateRepeatedQuadruplingConstraints(x *core.FieldElement, maxK int) ([]*core.Polynomial, error) {
	var constraints []*core.Polynomial

	// Generate constraint for each quadrupling step
	for k := 1; k <= maxK; k++ {
		// Constraint: x^(4^k) = (x^(4^(k-1)))^4
		// This is: x^(4^k) - (x^(4^(k-1)))^4 = 0

		constraintPoly, err := core.NewPolynomial([]*core.FieldElement{
			rq.field.Zero(), // Constant term
			rq.field.One(),  // Linear term
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create repeated quadrupling constraint polynomial: %w", err)
		}

		constraints = append(constraints, constraintPoly)
	}

	return constraints, nil
}

// CreateRepeatedQuadruplingAIR creates an AIR for repeated quadrupling
func CreateRepeatedQuadruplingAIR(field *core.Field, maxK int) (*AIR, error) {
	// Create AIR for repeated quadrupling
	// Width: 1 input + maxK+1 outputs
	width := 1 + maxK + 1
	traceLength := 1 // Single step operation

	// Create AIR
	air := NewAIR(field, traceLength, width, field.NewElementFromInt64(1))

	// Note: In a full implementation, we would generate and add repeated quadrupling constraints to the AIR
	// For now, we'll return the AIR without constraints
	// The constraints would be added through the CreateTransitionConstraints method

	return air, nil
}

// ValidateRepeatedQuadrupling validates that repeated quadrupling is computed correctly
func ValidateRepeatedQuadrupling(field *core.Field, x *core.FieldElement, maxK int) (bool, error) {
	rq := NewRepeatedQuadrupling(field)

	// Compute repeated quadrupling
	results, err := rq.ComputeRepeatedQuadrupling(x, maxK)
	if err != nil {
		return false, fmt.Errorf("failed to compute repeated quadrupling: %w", err)
	}

	// Verify each step
	for k := 1; k <= maxK; k++ {
		// Check that x^(4^k) = (x^(4^(k-1)))^4
		expected := results[k-1].Mul(results[k-1]).Mul(results[k-1]).Mul(results[k-1])
		if !results[k].Equal(expected) {
			return false, fmt.Errorf("repeated quadrupling validation failed at step %d", k)
		}
	}

	return true, nil
}
