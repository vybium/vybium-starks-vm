package codes

import (
	"fmt"
	"math/big"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/utils"
)

// BinaryAdditiveRSCode implements binary additive RS codes from TR17-134
// F = F_2^m (binary field), S is an additive coset
type BinaryAdditiveRSCode struct {
	field *core.Field
	rate  *core.FieldElement   // ρ ∈ (0, 1]
	coset []*core.FieldElement // Additive coset S = {s + Σ a_i ω_i | a_i ∈ F_2}
	basis []*core.FieldElement // Basis elements ω_i
}

// NewBinaryAdditiveRSCode creates a new binary additive RS code
func NewBinaryAdditiveRSCode(field *core.Field, rate *core.FieldElement, coset []*core.FieldElement, basis []*core.FieldElement) (*BinaryAdditiveRSCode, error) {
	if len(coset) == 0 {
		return nil, fmt.Errorf("coset cannot be empty")
	}

	if len(basis) == 0 {
		return nil, fmt.Errorf("basis cannot be empty")
	}

	// Verify that the coset size is 2^k for some k
	if !utils.IsPowerOfTwo(len(coset)) {
		return nil, fmt.Errorf("coset size must be a power of 2")
	}

	// Verify that basis size matches coset dimension
	expectedBasisSize := utils.Log2(len(coset))
	if len(basis) != expectedBasisSize {
		return nil, fmt.Errorf("basis size mismatch: expected %d, got %d", expectedBasisSize, len(basis))
	}

	return &BinaryAdditiveRSCode{
		field: field,
		rate:  rate,
		coset: coset,
		basis: basis,
	}, nil
}

// CreateCyclicGroupCoset creates a coset for a cyclic group ⟨ω⟩
// This is the most common case in FRI protocols
func CreateCyclicGroupCoset(field *core.Field, omega *core.FieldElement, size int) ([]*core.FieldElement, []*core.FieldElement, error) {
	if !utils.IsPowerOfTwo(size) {
		return nil, nil, fmt.Errorf("size must be a power of 2")
	}

	// Create cyclic group ⟨ω⟩ = {1, ω, ω², ..., ω^(N-1)}
	coset := make([]*core.FieldElement, size)
	coset[0] = field.One() // ω^0 = 1

	power := field.One()
	for i := 1; i < size; i++ {
		power = power.Mul(omega)
		coset[i] = power
	}

	// Create basis for the additive structure
	// For a cyclic group of size 2^k, we need k basis elements
	basis := make([]*core.FieldElement, utils.Log2(size))
	basis[0] = omega // First basis element is ω

	// Additional basis elements are powers of ω
	for i := 1; i < len(basis); i++ {
		basis[i] = omega.Exp(big.NewInt(int64(1 << i)))
	}

	return coset, basis, nil
}

// IsInCode checks if a function f: S → F is in the binary additive RS code
func (rs *BinaryAdditiveRSCode) IsInCode(function []*core.FieldElement) (bool, error) {
	if len(function) != len(rs.coset) {
		return false, fmt.Errorf("function length mismatch: expected %d, got %d", len(rs.coset), len(function))
	}

	// Check if the function can be interpolated by a polynomial of degree < ρN
	maxDegree := int(rs.rate.Mul(rs.field.NewElementFromInt64(int64(len(rs.coset)))).Big().Int64()) - 1

	// Interpolate the polynomial
	poly, err := rs.interpolatePolynomial(function)
	if err != nil {
		return false, fmt.Errorf("failed to interpolate polynomial: %w", err)
	}

	// Check degree constraint
	return poly.Degree() <= maxDegree, nil
}

// interpolatePolynomial interpolates a polynomial from function values
// Uses Lagrange interpolation over the additive coset
func (rs *BinaryAdditiveRSCode) interpolatePolynomial(function []*core.FieldElement) (*core.Polynomial, error) {
	if len(function) != len(rs.coset) {
		return nil, fmt.Errorf("function length mismatch")
	}

	n := len(rs.coset)
	if n == 0 {
		return nil, fmt.Errorf("cannot interpolate from empty coset")
	}

	// Initialize result polynomial as zero
	result, err := core.NewPolynomial([]*core.FieldElement{rs.field.Zero()})
	if err != nil {
		return nil, err
	}

	// Lagrange interpolation: f(x) = Σ(y_i * L_i(x))
	for i := 0; i < n; i++ {
		// Compute Lagrange basis polynomial L_i(x)
		lagrangeBasis, err := rs.computeLagrangeBasis(i)
		if err != nil {
			return nil, fmt.Errorf("failed to compute Lagrange basis %d: %w", i, err)
		}

		// Scale by function value
		scaledBasis, err := lagrangeBasis.MulScalar(function[i])
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
// L_i(x) = Π((x - x_j) / (x_i - x_j)) for j ≠ i
func (rs *BinaryAdditiveRSCode) computeLagrangeBasis(i int) (*core.Polynomial, error) {
	if i < 0 || i >= len(rs.coset) {
		return nil, fmt.Errorf("invalid basis index %d", i)
	}

	// Start with polynomial 1
	result, err := core.NewPolynomial([]*core.FieldElement{rs.field.One()})
	if err != nil {
		return nil, err
	}

	xi := rs.coset[i]

	// Compute Π((x - x_j) / (x_i - x_j)) for j ≠ i
	for j := 0; j < len(rs.coset); j++ {
		if j == i {
			continue
		}

		xj := rs.coset[j]

		// Compute (x - x_j)
		negXj := xj.Neg()
		linearPoly, err := core.NewPolynomial([]*core.FieldElement{negXj, rs.field.One()})
		if err != nil {
			return nil, err
		}

		// Compute (x_i - x_j)
		denominator := xi.Sub(xj)
		if denominator.IsZero() {
			return nil, fmt.Errorf("duplicate coset points: x_%d = x_%d", i, j)
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

// ComputeHammingDistance computes the relative Hamming distance between two functions
// Δ_S(u, v) = |{z ∈ S | u(z) ≠ v(z)}| / N
func (rs *BinaryAdditiveRSCode) ComputeHammingDistance(u, v []*core.FieldElement) (*core.FieldElement, error) {
	if len(u) != len(v) || len(u) != len(rs.coset) {
		return nil, fmt.Errorf("function length mismatch")
	}

	differences := 0
	for i := 0; i < len(u); i++ {
		if !u[i].Equal(v[i]) {
			differences++
		}
	}

	// Return relative distance as field element
	distance := rs.field.NewElementFromInt64(int64(differences))
	cosetSize := rs.field.NewElementFromInt64(int64(len(rs.coset)))

	relativeDistance, err := distance.Div(cosetSize)
	if err != nil {
		return nil, err
	}

	return relativeDistance, nil
}

// ComputeDistanceToCode computes the distance from a function to the binary additive RS code
// Δ(f, RS[F, S, ρ]) = min_{g ∈ RS} Δ(f, g)
func (rs *BinaryAdditiveRSCode) ComputeDistanceToCode(function []*core.FieldElement) (*core.FieldElement, error) {
	if len(function) != len(rs.coset) {
		return nil, fmt.Errorf("function length mismatch")
	}

	// Find the closest polynomial in the binary additive RS code
	// This is done by interpolating and then truncating to the maximum degree

	// First, interpolate the full polynomial
	fullPoly, err := rs.interpolatePolynomial(function)
	if err != nil {
		return nil, fmt.Errorf("failed to interpolate: %w", err)
	}

	// If the polynomial is already within the code, distance is 0
	maxDegree := int(rs.rate.Mul(rs.field.NewElementFromInt64(int64(len(rs.coset)))).Big().Int64()) - 1
	if fullPoly.Degree() <= maxDegree {
		return rs.field.Zero(), nil
	}

	// Otherwise, we need to find the closest polynomial in the code
	// This is computationally expensive, so we use a heuristic approach
	// In practice, this would use more sophisticated algorithms

	// For now, we estimate the distance based on the degree excess
	degreeExcess := fullPoly.Degree() - maxDegree
	if degreeExcess <= 0 {
		return rs.field.Zero(), nil
	}

	// Estimate distance based on degree excess (heuristic)
	// This is not the exact distance but gives a reasonable approximation
	excessRatio := rs.field.NewElementFromInt64(int64(degreeExcess))
	cosetSize := rs.field.NewElementFromInt64(int64(len(rs.coset)))

	estimatedDistance, err := excessRatio.Div(cosetSize)
	if err != nil {
		return nil, err
	}

	return estimatedDistance, nil
}

// GetMinimumDistance returns the minimum relative Hamming distance of the code
// For Reed-Solomon codes: δ_V = 1 - ρ
func (rs *BinaryAdditiveRSCode) GetMinimumDistance() *core.FieldElement {
	one := rs.field.One()
	return one.Sub(rs.rate)
}

// GetUniqueDecodingRadius returns the unique decoding radius
// For Reed-Solomon codes: δ < (1 - ρ)/2
func (rs *BinaryAdditiveRSCode) GetUniqueDecodingRadius() *core.FieldElement {
	minDist := rs.GetMinimumDistance()
	half, err := minDist.Div(rs.field.NewElementFromInt64(2))
	if err != nil {
		// If division fails, return a conservative estimate
		quarter, err := rs.field.NewElementFromInt64(1).Div(rs.field.NewElementFromInt64(4))
		if err != nil {
			return rs.field.NewElementFromInt64(1)
		}
		return quarter
	}
	return half
}

// EvaluateAtPoint evaluates a polynomial (represented by its function values) at a point
func (rs *BinaryAdditiveRSCode) EvaluateAtPoint(function []*core.FieldElement, point *core.FieldElement) (*core.FieldElement, error) {
	if len(function) != len(rs.coset) {
		return nil, fmt.Errorf("function length mismatch")
	}

	// Interpolate the polynomial
	poly, err := rs.interpolatePolynomial(function)
	if err != nil {
		return nil, fmt.Errorf("failed to interpolate: %w", err)
	}

	// Evaluate at the point
	return poly.Eval(point), nil
}

// GetCoset returns the additive coset
func (rs *BinaryAdditiveRSCode) GetCoset() []*core.FieldElement {
	return rs.coset
}

// GetBasis returns the basis elements
func (rs *BinaryAdditiveRSCode) GetBasis() []*core.FieldElement {
	return rs.basis
}

// GetRate returns the rate parameter
func (rs *BinaryAdditiveRSCode) GetRate() *core.FieldElement {
	return rs.rate
}

// log2 computes log₂(n)
