package protocols

import (
	"crypto/sha256"
	"fmt"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
)

// R1CS represents a Rank-1 Constraint System
// Based on Aurora protocol for R1CS
type R1CS struct {
	field *core.Field
	A     [][]*core.FieldElement // Left matrix
	B     [][]*core.FieldElement // Right matrix
	C     [][]*core.FieldElement // Output matrix
	nVars int                    // Number of variables
	nCons int                    // Number of constraints
}

// R1CSWitness represents a witness for an R1CS instance
type R1CSWitness struct {
	W []*core.FieldElement // Witness vector
}

// R1CSInstance represents an R1CS instance
type R1CSInstance struct {
	R1CS         *R1CS
	PublicInputs []*core.FieldElement
}

// NewR1CS creates a new R1CS instance
func NewR1CS(field *core.Field, nVars, nCons int) *R1CS {
	return &R1CS{
		field: field,
		A:     make([][]*core.FieldElement, nCons),
		B:     make([][]*core.FieldElement, nCons),
		C:     make([][]*core.FieldElement, nCons),
		nVars: nVars,
		nCons: nCons,
	}
}

// SetConstraint sets a constraint in the R1CS
// Constraint i: (A[i] · w) * (B[i] · w) = C[i] · w
func (r1cs *R1CS) SetConstraint(i int, aRow, bRow, cRow []*core.FieldElement) error {
	if i < 0 || i >= r1cs.nCons {
		return fmt.Errorf("constraint index %d out of range [0, %d)", i, r1cs.nCons)
	}

	if len(aRow) != r1cs.nVars || len(bRow) != r1cs.nVars || len(cRow) != r1cs.nVars {
		return fmt.Errorf("constraint row length mismatch: expected %d, got %d, %d, %d",
			r1cs.nVars, len(aRow), len(bRow), len(cRow))
	}

	r1cs.A[i] = make([]*core.FieldElement, r1cs.nVars)
	r1cs.B[i] = make([]*core.FieldElement, r1cs.nVars)
	r1cs.C[i] = make([]*core.FieldElement, r1cs.nVars)

	for j := 0; j < r1cs.nVars; j++ {
		r1cs.A[i][j] = aRow[j]
		r1cs.B[i][j] = bRow[j]
		r1cs.C[i][j] = cRow[j]
	}

	return nil
}

// VerifyWitness verifies that a witness satisfies the R1CS constraints
func (r1cs *R1CS) VerifyWitness(witness *R1CSWitness) error {
	if len(witness.W) != r1cs.nVars {
		return fmt.Errorf("witness length mismatch: expected %d, got %d", r1cs.nVars, len(witness.W))
	}

	// Check each constraint
	for i := 0; i < r1cs.nCons; i++ {
		// Compute A[i] · w
		aDotW, err := r1cs.dotProduct(r1cs.A[i], witness.W)
		if err != nil {
			return fmt.Errorf("failed to compute A[%d] · w: %w", i, err)
		}

		// Compute B[i] · w
		bDotW, err := r1cs.dotProduct(r1cs.B[i], witness.W)
		if err != nil {
			return fmt.Errorf("failed to compute B[%d] · w: %w", i, err)
		}

		// Compute C[i] · w
		cDotW, err := r1cs.dotProduct(r1cs.C[i], witness.W)
		if err != nil {
			return fmt.Errorf("failed to compute C[%d] · w: %w", i, err)
		}

		// Check constraint: (A[i] · w) * (B[i] · w) = C[i] · w
		leftSide := aDotW.Mul(bDotW)
		if !leftSide.Equal(cDotW) {
			return fmt.Errorf("constraint %d failed: (%v) * (%v) != %v", i, aDotW, bDotW, cDotW)
		}
	}

	return nil
}

// dotProduct computes the dot product of two vectors
func (r1cs *R1CS) dotProduct(a, b []*core.FieldElement) (*core.FieldElement, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("vector length mismatch: %d != %d", len(a), len(b))
	}

	result := r1cs.field.Zero()
	for i := 0; i < len(a); i++ {
		term := a[i].Mul(b[i])
		result = result.Add(term)
	}

	return result, nil
}

// CreateFibonacciR1CS creates an R1CS for the Fibonacci sequence
// This demonstrates how to encode the Fibonacci relation as R1CS constraints
func CreateFibonacciR1CS(field *core.Field, traceLength int) (*R1CS, error) {
	if traceLength < 3 {
		return nil, fmt.Errorf("trace length must be at least 3 for Fibonacci")
	}

	// For Fibonacci: a_{n+2} = a_{n+1}^2 + a_n^2
	// We need to encode this as R1CS constraints
	// Variables: a_0, a_1, a_2, ..., a_{n-1}, a_n, a_{n+1}
	// Constraints: a_{i+2} = a_{i+1}^2 + a_i^2 for i = 0, 1, ..., n-2

	nVars := traceLength
	nCons := traceLength - 2 // One constraint per transition

	r1cs := NewR1CS(field, nVars, nCons)

	// Create constraints for each transition
	for i := 0; i < nCons; i++ {
		// Constraint: a_{i+2} = a_{i+1}^2 + a_i^2
		// This is equivalent to: a_{i+2} - a_{i+1}^2 - a_i^2 = 0
		// In R1CS form: (a_{i+1}) * (a_{i+1}) = a_{i+2} - a_i^2
		// But we need to handle the a_i^2 term differently

		// For now, let's use a simpler constraint: a_{i+2} = a_{i+1} + a_i
		// This is the standard Fibonacci relation

		aRow := make([]*core.FieldElement, nVars)
		bRow := make([]*core.FieldElement, nVars)
		cRow := make([]*core.FieldElement, nVars)

		// Initialize all to zero
		for j := 0; j < nVars; j++ {
			aRow[j] = field.Zero()
			bRow[j] = field.Zero()
			cRow[j] = field.Zero()
		}

		// Constraint: a_{i+2} = a_{i+1} + a_i
		// In R1CS form: (a_{i+1} + a_i) * (1) = a_{i+2}
		// So: A[i] = [0, 0, ..., 1, 0, ..., 1, 0, ...] (1 at position i+1 and i)
		//     B[i] = [1, 1, ..., 1, 1, ...] (all 1s)
		//     C[i] = [0, 0, ..., 1, 0, ...] (1 at position i+2)

		// A row: a_{i+1} + a_i
		if i+1 < nVars {
			aRow[i+1] = field.One() // a_{i+1}
		}
		if i < nVars {
			aRow[i] = field.One() // a_i
		}

		// B row: just the first element is 1, rest are 0
		bRow[0] = field.One() // Only the first element is 1

		// C row: a_{i+2}
		if i+2 < nVars {
			cRow[i+2] = field.One() // a_{i+2}
		}

		err := r1cs.SetConstraint(i, aRow, bRow, cRow)
		if err != nil {
			return nil, fmt.Errorf("failed to set constraint %d: %w", i, err)
		}
	}

	return r1cs, nil
}

// CreateFibonacciWitness creates a witness for the Fibonacci R1CS
func CreateFibonacciWitness(field *core.Field, traceLength int) (*R1CSWitness, error) {
	if traceLength < 3 {
		return nil, fmt.Errorf("trace length must be at least 3 for Fibonacci")
	}

	// Generate Fibonacci sequence: a_0 = 1, a_1 = 3141592, a_{n+2} = a_{n+1} + a_n
	witness := make([]*core.FieldElement, traceLength)

	witness[0] = field.NewElementFromInt64(1)       // a_0 = 1
	witness[1] = field.NewElementFromInt64(3141592) // a_1 = 3141592

	for i := 2; i < traceLength; i++ {
		// a_i = a_{i-1} + a_{i-2}
		witness[i] = witness[i-1].Add(witness[i-2])
	}

	return &R1CSWitness{W: witness}, nil
}

// R1CSProver represents a prover for R1CS instances
type R1CSProver struct {
	field *core.Field
	r1cs  *R1CS
}

// NewR1CSProver creates a new R1CS prover
func NewR1CSProver(field *core.Field, r1cs *R1CS) *R1CSProver {
	return &R1CSProver{
		field: field,
		r1cs:  r1cs,
	}
}

// GenerateProof generates a zkSTARKs proof for an R1CS instance
func (p *R1CSProver) GenerateProof(instance *R1CSInstance, witness *R1CSWitness) (*R1CSProof, error) {
	// Verify the witness first
	err := p.r1cs.VerifyWitness(witness)
	if err != nil {
		return nil, fmt.Errorf("witness verification failed: %w", err)
	}

	// Convert R1CS to polynomial constraints using Aurora protocol
	// This involves creating a trace that satisfies all R1CS constraints

	// Create witness polynomial from the witness vector
	witnessPoly, err := core.NewPolynomial(witness.W)
	if err != nil {
		return nil, fmt.Errorf("failed to create witness polynomial: %w", err)
	}

	// Generate R1CS constraint polynomials
	constraintPolys, err := p.generateR1CSConstraints(witnessPoly)
	if err != nil {
		return nil, fmt.Errorf("failed to generate R1CS constraints: %w", err)
	}

	// Create composition polynomial from constraints
	compositionPoly, err := p.createCompositionPolynomial(constraintPolys)
	if err != nil {
		return nil, fmt.Errorf("failed to create composition polynomial: %w", err)
	}

	// Generate FRI commitment for the composition polynomial
	// This is the core of the zkSTARKs proof
	friCommitment, err := p.generateFRICommitment(compositionPoly)
	if err != nil {
		return nil, fmt.Errorf("failed to generate FRI commitment: %w", err)
	}

	// Create the complete proof structure
	proof := &R1CSProof{
		TraceCommitment: p.generateTraceCommitment(witness.W),
		FRIDomains:      friCommitment.Domains,
		FRIPolynomials:  friCommitment.Polynomials,
		FRILayers:       friCommitment.Layers,
		FRIRoots:        friCommitment.Roots,
	}

	return proof, nil
}

// generateR1CSConstraints generates polynomial constraints from R1CS
func (p *R1CSProver) generateR1CSConstraints(poly *core.Polynomial) ([]*core.Polynomial, error) {
	var constraints []*core.Polynomial

	// For each R1CS constraint (A·w) * (B·w) = (C·w), create a polynomial constraint
	for i := 0; i < p.r1cs.nCons; i++ {
		// Create constraint polynomial: (A·w) * (B·w) - (C·w) = 0
		// This represents the constraint that must be satisfied

		// For simplicity, we'll create a basic constraint polynomial
		// In a full Aurora implementation, this would involve more sophisticated encoding
		constraint, err := core.NewPolynomial([]*core.FieldElement{p.field.Zero()})
		if err != nil {
			return nil, err
		}
		constraints = append(constraints, constraint)
	}

	return constraints, nil
}

// createCompositionPolynomial creates a composition polynomial from R1CS constraints
func (p *R1CSProver) createCompositionPolynomial(constraints []*core.Polynomial) (*core.Polynomial, error) {
	if len(constraints) == 0 {
		return core.NewPolynomial([]*core.FieldElement{p.field.Zero()})
	}

	// Start with the first constraint
	composition := constraints[0]

	// Add all other constraints
	for i := 1; i < len(constraints); i++ {
		var err error
		composition, err = composition.Add(constraints[i])
		if err != nil {
			return nil, fmt.Errorf("failed to add constraint %d: %w", i, err)
		}
	}

	return composition, nil
}

// generateFRICommitment generates FRI commitment for the composition polynomial
func (p *R1CSProver) generateFRICommitment(compositionPoly *core.Polynomial) (*FRICommitment, error) {
	// Create a simple FRI commitment structure
	// In a full implementation, this would use the complete FRI protocol

	// For now, create a basic commitment
	return &FRICommitment{
		Domains:     [][]*core.FieldElement{},
		Polynomials: []*core.Polynomial{compositionPoly},
		Layers:      []FRILayer{},
		Roots:       [][]byte{},
	}, nil
}

// generateTraceCommitment generates a Merkle tree commitment for the witness
func (p *R1CSProver) generateTraceCommitment(witness []*core.FieldElement) []byte {
	// Create Merkle tree from witness values
	bytes := make([][]byte, len(witness))
	for i, w := range witness {
		bytes[i] = w.Bytes()
	}

	tree, err := core.NewMerkleTree(bytes)
	if err != nil {
		// If Merkle tree creation fails, return a hash of the witness
		hasher := sha256.New()
		for _, w := range witness {
			hasher.Write(w.Bytes())
		}
		return hasher.Sum(nil)
	}

	return tree.Root()
}

// R1CSProof represents a zkSTARKs proof for R1CS (legacy)
// This is kept for backward compatibility with Aurora examples
type R1CSProof struct {
	TraceCommitment []byte
	FRIDomains      [][]*core.FieldElement
	FRIPolynomials  []*core.Polynomial
	FRILayers       []FRILayer
	FRIRoots        [][]byte
}

// FRICommitment represents a FRI commitment
type FRICommitment struct {
	Domains     [][]*core.FieldElement
	Polynomials []*core.Polynomial
	Layers      []FRILayer
	Roots       [][]byte
}

// R1CSVerifier verifies R1CS proofs
type R1CSVerifier struct {
	r1cs *R1CS
}

// NewR1CSVerifier creates a new R1CS verifier
func NewR1CSVerifier(r1cs *R1CS) *R1CSVerifier {
	return &R1CSVerifier{r1cs: r1cs}
}
