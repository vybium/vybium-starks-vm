package protocols

import (
	"fmt"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/utils"
)

// AIR represents an Algebraic Intermediate Representation
// This arithmetizes a computation into polynomial constraints over a trace table
type AIR struct {
	field       *core.Field
	traceLength int                    // T - number of computation steps
	stateWidth  int                    // w - width of state
	trace       [][]*core.FieldElement // f ∈ F^(T×w) - execution trace
	domain      []*core.FieldElement   // S - evaluation domain
	ldeDomain   []*core.FieldElement   // L - low-degree extension domain
	rate        *core.FieldElement     // ρ - rate parameter
}

// AIRConstraint represents a constraint in the AIR
type AIRConstraint struct {
	Type       string           // "transition" or "boundary"
	Polynomial *core.Polynomial // P_j for transition constraints
	Index      int              // constraint index
	Degree     int              // degree bound d_P
}

// AIRTrace represents the execution trace as polynomials
type AIRTrace struct {
	Polynomials []*core.Polynomial   // f_j: L → F for each state column
	Domain      []*core.FieldElement // L - low-degree extension domain
	MerkleRoot  []byte               // Merkle root of polynomial evaluations
}

// NewAIR creates a new AIR instance
func NewAIR(field *core.Field, traceLength, stateWidth int, rate *core.FieldElement) *AIR {
	return &AIR{
		field:       field,
		traceLength: traceLength,
		stateWidth:  stateWidth,
		rate:        rate,
	}
}

// SetTrace sets the execution trace
func (air *AIR) SetTrace(trace [][]*core.FieldElement) error {
	if len(trace) != air.traceLength {
		return fmt.Errorf("trace length mismatch: expected %d, got %d", air.traceLength, len(trace))
	}

	for i, row := range trace {
		if len(row) != air.stateWidth {
			return fmt.Errorf("state width mismatch at row %d: expected %d, got %d", i, air.stateWidth, len(row))
		}
	}

	air.trace = trace
	return nil
}

// SetDomain sets the evaluation domain S
func (air *AIR) SetDomain(domain []*core.FieldElement) error {
	if len(domain) != air.traceLength {
		return fmt.Errorf("domain size mismatch: expected %d, got %d", air.traceLength, len(domain))
	}

	air.domain = domain
	return nil
}

// CreateLDEDomain creates the low-degree extension domain L ⊃ S
// L has size mN where m = 4 or 8 for zero-knowledge
func (air *AIR) CreateLDEDomain(extensionFactor int) error {
	if extensionFactor != 4 && extensionFactor != 8 {
		return fmt.Errorf("extension factor must be 4 or 8, got %d", extensionFactor)
	}

	// Create LDE domain L = ⟨ω⟩ with size mN
	ldeSize := extensionFactor * air.traceLength

	// Ensure LDE domain size is a power of 2
	if !utils.IsPowerOfTwo(ldeSize) {
		return fmt.Errorf("LDE domain size %d must be a power of 2", ldeSize)
	}

	// Create cyclic group L = ⟨ω⟩
	// For simplicity, we'll use a generator ω = 2
	omega := air.field.NewElementFromInt64(2)

	ldeDomain := make([]*core.FieldElement, ldeSize)
	ldeDomain[0] = air.field.One() // ω^0 = 1

	power := air.field.One()
	for i := 1; i < ldeSize; i++ {
		power = power.Mul(omega)
		ldeDomain[i] = power
	}

	air.ldeDomain = ldeDomain
	return nil
}

// ArithmetizeTrace converts the trace into polynomials
// Each column of the trace becomes a polynomial f_j: L → F
func (air *AIR) ArithmetizeTrace() (*AIRTrace, error) {
	if len(air.trace) == 0 {
		return nil, fmt.Errorf("trace not set")
	}

	if len(air.ldeDomain) == 0 {
		return nil, fmt.Errorf("LDE domain not created")
	}

	// Convert each column of the trace to a polynomial
	polynomials := make([]*core.Polynomial, air.stateWidth)

	for j := 0; j < air.stateWidth; j++ {
		// Extract column j from the trace
		column := make([]*core.FieldElement, air.traceLength)
		for i := 0; i < air.traceLength; i++ {
			column[i] = air.trace[i][j]
		}

		// Interpolate polynomial f_j over the domain S
		poly, err := air.interpolatePolynomial(column, air.domain)
		if err != nil {
			return nil, fmt.Errorf("failed to interpolate polynomial for column %d: %w", j, err)
		}

		// Extend to LDE domain L
		extendedPoly, err := air.extendPolynomialToLDE(poly)
		if err != nil {
			return nil, fmt.Errorf("failed to extend polynomial for column %d: %w", j, err)
		}

		polynomials[j] = extendedPoly
	}

	// Create Merkle tree for polynomial evaluations over LDE domain
	evaluations := make([][]*core.FieldElement, air.stateWidth)
	for j := 0; j < air.stateWidth; j++ {
		evaluations[j] = make([]*core.FieldElement, len(air.ldeDomain))
		for i, point := range air.ldeDomain {
			evaluations[j][i] = polynomials[j].Eval(point)
		}
	}

	// Flatten evaluations for Merkle tree
	flatEvaluations := make([]*core.FieldElement, 0, air.stateWidth*len(air.ldeDomain))
	for j := 0; j < air.stateWidth; j++ {
		flatEvaluations = append(flatEvaluations, evaluations[j]...)
	}

	tree, err := core.NewMerkleTree(air.evaluationsToBytes(flatEvaluations))
	if err != nil {
		return nil, fmt.Errorf("failed to create Merkle tree: %w", err)
	}

	return &AIRTrace{
		Polynomials: polynomials,
		Domain:      air.ldeDomain,
		MerkleRoot:  tree.Root(),
	}, nil
}

// interpolatePolynomial interpolates a polynomial from values over a domain
func (air *AIR) interpolatePolynomial(values []*core.FieldElement, domain []*core.FieldElement) (*core.Polynomial, error) {
	if len(values) != len(domain) {
		return nil, fmt.Errorf("values and domain length mismatch")
	}

	n := len(domain)
	if n == 0 {
		return nil, fmt.Errorf("cannot interpolate from empty domain")
	}

	// Initialize result polynomial as zero
	result, err := core.NewPolynomial([]*core.FieldElement{air.field.Zero()})
	if err != nil {
		return nil, err
	}

	// Lagrange interpolation: f(x) = Σ(y_i * L_i(x))
	for i := 0; i < n; i++ {
		// Compute Lagrange basis polynomial L_i(x)
		lagrangeBasis, err := air.computeLagrangeBasis(i, domain)
		if err != nil {
			return nil, fmt.Errorf("failed to compute Lagrange basis %d: %w", i, err)
		}

		// Scale by value
		scaledBasis, err := lagrangeBasis.MulScalar(values[i])
		if err != nil {
			return nil, fmt.Errorf("failed to scale Lagrange basis %d: %w", i, err)
		}

		// Add to result
		result, err = result.Add(scaledBasis)
		if err != nil {
			return nil, fmt.Errorf("failed to add Lagrange basis %d: %w", i, err)
		}
	}

	return result, nil
}

// computeLagrangeBasis computes the i-th Lagrange basis polynomial L_i(x)
func (air *AIR) computeLagrangeBasis(i int, domain []*core.FieldElement) (*core.Polynomial, error) {
	if i < 0 || i >= len(domain) {
		return nil, fmt.Errorf("invalid basis index %d", i)
	}

	// Start with polynomial 1
	result, err := core.NewPolynomial([]*core.FieldElement{air.field.One()})
	if err != nil {
		return nil, err
	}

	xi := domain[i]

	// Compute Π((x - x_j) / (x_i - x_j)) for j ≠ i
	for j := 0; j < len(domain); j++ {
		if j == i {
			continue
		}

		xj := domain[j]

		// Compute (x - x_j)
		negXj := xj.Neg()
		linearPoly, err := core.NewPolynomial([]*core.FieldElement{negXj, air.field.One()})
		if err != nil {
			return nil, err
		}

		// Compute (x_i - x_j)
		denominator := xi.Sub(xj)
		if denominator.IsZero() {
			return nil, fmt.Errorf("duplicate domain points: x_%d = x_%d", i, j)
		}

		// Scale by 1/(x_i - x_j)
		invDenominator, err := denominator.Inv()
		if err != nil {
			return nil, err
		}
		scaledPoly, err := linearPoly.MulScalar(invDenominator)
		if err != nil {
			return nil, err
		}

		// Multiply with result
		result, err = result.Mul(scaledPoly)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// extendPolynomialToLDE extends a polynomial from domain S to LDE domain L
func (air *AIR) extendPolynomialToLDE(poly *core.Polynomial) (*core.Polynomial, error) {
	// For zero-knowledge, we add a random blinding polynomial
	// r(X) ∈ F[X] with deg(r) < ρN

	// Generate random blinding polynomial
	blindingPoly, err := air.generateBlindingPolynomial()
	if err != nil {
		return nil, fmt.Errorf("failed to generate blinding polynomial: %w", err)
	}

	// Add blinding polynomial to original polynomial
	extendedPoly, err := poly.Add(blindingPoly)
	if err != nil {
		return nil, fmt.Errorf("failed to add blinding polynomial: %w", err)
	}

	return extendedPoly, nil
}

// generateBlindingPolynomial generates a random blinding polynomial for zero-knowledge
func (air *AIR) generateBlindingPolynomial() (*core.Polynomial, error) {
	// Generate random polynomial r(X) with deg(r) < ρN
	maxDegree := int(air.rate.Mul(air.field.NewElementFromInt64(int64(air.traceLength))).Big().Int64()) - 1

	if maxDegree < 0 {
		// If max degree is negative, return zero polynomial
		return core.NewPolynomial([]*core.FieldElement{air.field.Zero()})
	}

	// Generate random coefficients using cryptographically secure randomness
	coefficients := make([]*core.FieldElement, maxDegree+1)
	for i := 0; i <= maxDegree; i++ {
		// Generate cryptographically secure random field element
		randomValue, err := air.field.RandomElement()
		if err != nil {
			return nil, fmt.Errorf("failed to generate random field element: %w", err)
		}
		coefficients[i] = randomValue
	}

	return core.NewPolynomial(coefficients)
}

// CreateTransitionConstraints creates transition constraints for the AIR
// P_j(f_i, f_{i+1}) = 0 for each step i
func (air *AIR) CreateTransitionConstraints() ([]AIRConstraint, error) {
	var constraints []AIRConstraint

	// For each state column, create transition constraints
	for j := 0; j < air.stateWidth; j++ {
		// Create proper transition constraint based on the computation
		// For Fibonacci example: f_{i+1} = f_i + f_{i-1}
		// This becomes: f_{i+1} - f_i - f_{i-1} = 0

		// Create constraint polynomial P_j(X, Y, Z) = Y - X - Z
		// where X = f_i, Y = f_{i+1}, Z = f_{i-1}
		// For simplicity, we'll create a linear constraint: Y - X - Z = 0

		// Create coefficients for the constraint polynomial
		// P(X, Y, Z) = -X + Y - Z = 0
		// This represents: Y = X + Z (Fibonacci relation)
		constraintCoeffs := []*core.FieldElement{
			air.field.Zero(),                  // constant term
			air.field.NewElementFromInt64(-1), // coefficient for X (current state)
			air.field.One(),                   // coefficient for Y (next state)
			air.field.NewElementFromInt64(-1), // coefficient for Z (previous state)
		}

		constraintPoly, err := core.NewPolynomial(constraintCoeffs)
		if err != nil {
			return nil, fmt.Errorf("failed to create constraint polynomial for column %d: %w", j, err)
		}

		constraint := AIRConstraint{
			Type:       "transition",
			Polynomial: constraintPoly,
			Index:      j,
			Degree:     1, // Simple linear constraint
		}

		constraints = append(constraints, constraint)
	}

	return constraints, nil
}

// CreateBoundaryConstraints creates boundary constraints for the AIR
// Ensures input/output correctness
func (air *AIR) CreateBoundaryConstraints(inputs, outputs []*core.FieldElement) ([]AIRConstraint, error) {
	var constraints []AIRConstraint

	// Input constraints: f_1,j = x_j
	if len(inputs) > 0 {
		for j := 0; j < air.stateWidth && j < len(inputs); j++ {
			// Create constraint: f_1,j - x_j = 0
			negInput := inputs[j].Neg()
			constraintPoly, err := core.NewPolynomial([]*core.FieldElement{negInput, air.field.One()})
			if err != nil {
				return nil, fmt.Errorf("failed to create input constraint for column %d: %w", j, err)
			}

			constraint := AIRConstraint{
				Type:       "boundary",
				Polynomial: constraintPoly,
				Index:      j,
				Degree:     1,
			}

			constraints = append(constraints, constraint)
		}
	}

	// Output constraints: f_T,j = y_j
	if len(outputs) > 0 {
		for j := 0; j < air.stateWidth && j < len(outputs); j++ {
			// Create constraint: f_T,j - y_j = 0
			negOutput := outputs[j].Neg()
			constraintPoly, err := core.NewPolynomial([]*core.FieldElement{negOutput, air.field.One()})
			if err != nil {
				return nil, fmt.Errorf("failed to create output constraint for column %d: %w", j, err)
			}

			constraint := AIRConstraint{
				Type:       "boundary",
				Polynomial: constraintPoly,
				Index:      j,
				Degree:     1,
			}

			constraints = append(constraints, constraint)
		}
	}

	return constraints, nil
}

// evaluationsToBytes converts field element evaluations to byte slices for Merkle tree
func (air *AIR) evaluationsToBytes(evaluations []*core.FieldElement) [][]byte {
	bytes := make([][]byte, len(evaluations))
	for i, eval := range evaluations {
		bytes[i] = eval.Bytes()
	}
	return bytes
}

// GetTraceLength returns the trace length
func (air *AIR) GetTraceLength() int {
	return air.traceLength
}

// GetStateWidth returns the state width
func (air *AIR) GetStateWidth() int {
	return air.stateWidth
}

// GetLDEDomain returns the LDE domain
func (air *AIR) GetLDEDomain() []*core.FieldElement {
	return air.ldeDomain
}

// GetRate returns the rate parameter
func (air *AIR) GetRate() *core.FieldElement {
	return air.rate
}
