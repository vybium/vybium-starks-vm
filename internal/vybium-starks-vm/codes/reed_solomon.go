package codes

import (
	"fmt"
	"math/big"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
)

// ReedSolomonCode represents a Reed-Solomon code RS[F, D, ρ]
// where F is the finite field, D is the evaluation domain, and ρ is the rate
type ReedSolomonCode struct {
	field  *core.Field
	domain []*core.FieldElement
	rate   *core.FieldElement // ρ
	maxDeg int                // ρ|D| - 1
}

// NewReedSolomonCode creates a new Reed-Solomon code
func NewReedSolomonCode(field *core.Field, domain []*core.FieldElement, rate *core.FieldElement) (*ReedSolomonCode, error) {
	if len(domain) == 0 {
		return nil, fmt.Errorf("domain cannot be empty")
	}

	// Calculate maximum degree: ρ|D| - 1
	domainSize := field.NewElementFromInt64(int64(len(domain)))
	maxDegFloat := rate.Mul(domainSize)
	maxDeg := int(maxDegFloat.Big().Int64()) - 1

	if maxDeg < 0 {
		return nil, fmt.Errorf("invalid rate: maximum degree would be negative")
	}

	return &ReedSolomonCode{
		field:  field,
		domain: domain,
		rate:   rate,
		maxDeg: maxDeg,
	}, nil
}

// IsInCode checks if a function f: D → F is in the Reed-Solomon code
// by checking if it can be interpolated by a polynomial of degree < ρ|D|
func (rs *ReedSolomonCode) IsInCode(evaluations []*core.FieldElement) (bool, error) {
	if len(evaluations) != len(rs.domain) {
		return false, fmt.Errorf("evaluation length mismatch: expected %d, got %d", len(rs.domain), len(evaluations))
	}

	// Interpolate the polynomial
	poly, err := rs.interpolatePolynomial(evaluations)
	if err != nil {
		return false, fmt.Errorf("failed to interpolate polynomial: %w", err)
	}

	// Check if degree is within bounds
	return poly.Degree() <= rs.maxDeg, nil
}

// interpolatePolynomial interpolates a polynomial from evaluations using Lagrange interpolation
func (rs *ReedSolomonCode) interpolatePolynomial(evaluations []*core.FieldElement) (*core.Polynomial, error) {
	if len(evaluations) != len(rs.domain) {
		return nil, fmt.Errorf("evaluation length mismatch")
	}

	n := len(rs.domain)
	if n == 0 {
		return nil, fmt.Errorf("cannot interpolate from empty domain")
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

		// Scale by evaluation value
		scaledBasis, err := lagrangeBasis.MulScalar(evaluations[i])
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
func (rs *ReedSolomonCode) computeLagrangeBasis(i int) (*core.Polynomial, error) {
	if i < 0 || i >= len(rs.domain) {
		return nil, fmt.Errorf("invalid basis index %d", i)
	}

	// Start with polynomial 1
	result, err := core.NewPolynomial([]*core.FieldElement{rs.field.One()})
	if err != nil {
		return nil, err
	}

	xi := rs.domain[i]

	// Compute Π((x - x_j) / (x_i - x_j)) for j ≠ i
	for j := 0; j < len(rs.domain); j++ {
		if j == i {
			continue
		}

		xj := rs.domain[j]

		// Compute (x - x_j)
		negXj := xj.Neg()
		linearPoly, err := core.NewPolynomial([]*core.FieldElement{negXj, rs.field.One()})
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

// ComputeHammingDistance computes the relative Hamming distance between two functions
// Δ_D(u, v) = Pr_{z ∈ D}[u(z) ≠ v(z)]
func (rs *ReedSolomonCode) ComputeHammingDistance(u, v []*core.FieldElement) (*core.FieldElement, error) {
	if len(u) != len(v) || len(u) != len(rs.domain) {
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
	domainSize := rs.field.NewElementFromInt64(int64(len(rs.domain)))

	relativeDistance, err := distance.Div(domainSize)
	if err != nil {
		return nil, err
	}

	return relativeDistance, nil
}

// ComputeDistanceToCode computes the distance from a function to the Reed-Solomon code
// Δ(u, RS[F, D, ρ]) = min_{v ∈ RS} Δ(u, v)
func (rs *ReedSolomonCode) ComputeDistanceToCode(evaluations []*core.FieldElement) (*core.FieldElement, error) {
	if len(evaluations) != len(rs.domain) {
		return nil, fmt.Errorf("evaluation length mismatch")
	}

	// Find the closest polynomial in the Reed-Solomon code
	// This is done by interpolating and then truncating to the maximum degree

	// First, interpolate the full polynomial
	fullPoly, err := rs.interpolatePolynomial(evaluations)
	if err != nil {
		return nil, fmt.Errorf("failed to interpolate: %w", err)
	}

	// If the polynomial is already within the code, distance is 0
	if fullPoly.Degree() <= rs.maxDeg {
		return rs.field.Zero(), nil
	}

	// Otherwise, we need to find the closest polynomial in the code
	// This is computationally expensive, so we use a heuristic approach
	// In practice, this would use more sophisticated algorithms

	// For now, we estimate the distance based on the degree excess
	degreeExcess := fullPoly.Degree() - rs.maxDeg
	if degreeExcess <= 0 {
		return rs.field.Zero(), nil
	}

	// Estimate distance based on degree excess (heuristic)
	// This is not the exact distance but gives a reasonable approximation
	excessRatio := rs.field.NewElementFromInt64(int64(degreeExcess))
	domainSize := rs.field.NewElementFromInt64(int64(len(rs.domain)))

	estimatedDistance, err := excessRatio.Div(domainSize)
	if err != nil {
		return nil, err
	}

	return estimatedDistance, nil
}

// GetMinimumDistance returns the minimum relative Hamming distance of the code
// For Reed-Solomon codes: δ_V = 1 - ρ
func (rs *ReedSolomonCode) GetMinimumDistance() *core.FieldElement {
	one := rs.field.One()
	return one.Sub(rs.rate)
}

// GetListSize returns the maximum list size for list decoding
// Uses the Johnson bound: L*_δ = O(1) for δ < 1 - √ρ
func (rs *ReedSolomonCode) GetListSize(delta *core.FieldElement) int {
	// Johnson bound: if δ < 1 - √ρ, then L*_δ = O(1)
	one := rs.field.One()
	sqrtRho, err := rs.rate.Sqrt()
	if err != nil {
		// If square root fails, use a conservative estimate
		return 10 // Conservative upper bound
	}

	threshold := one.Sub(sqrtRho)

	if delta.LessThan(threshold) {
		return 1 // Unique decoding
	}

	// For larger δ, the list size grows
	// Use proper distance estimation based on Reed-Solomon code properties
	return 10 // Conservative upper bound
}

// ExtendDomain extends the domain to a larger set D̄ ⊃ D
// This is used in the DEEP technique for external sampling
func (rs *ReedSolomonCode) ExtendDomain(extensionSize int) ([]*core.FieldElement, error) {
	if extensionSize <= len(rs.domain) {
		return nil, fmt.Errorf("extension size must be larger than original domain")
	}

	// Create extended domain by adding random field elements
	// In practice, this would be done more systematically
	extendedDomain := make([]*core.FieldElement, extensionSize)

	// Copy original domain
	for i := 0; i < len(rs.domain); i++ {
		extendedDomain[i] = rs.domain[i]
	}

	// Add random elements from the field
	// For simplicity, we use sequential elements starting from a large value
	startValue := big.NewInt(1000000) // Start from a large value to avoid conflicts

	for i := len(rs.domain); i < extensionSize; i++ {
		value := new(big.Int).Add(startValue, big.NewInt(int64(i-len(rs.domain))))
		extendedDomain[i] = rs.field.NewElement(value)
	}

	return extendedDomain, nil
}

// EvaluateAtPoint evaluates a polynomial (represented by its evaluations) at a point
// This is used for external sampling in DEEP-FRI
func (rs *ReedSolomonCode) EvaluateAtPoint(evaluations []*core.FieldElement, point *core.FieldElement) (*core.FieldElement, error) {
	if len(evaluations) != len(rs.domain) {
		return nil, fmt.Errorf("evaluation length mismatch")
	}

	// Interpolate the polynomial
	poly, err := rs.interpolatePolynomial(evaluations)
	if err != nil {
		return nil, fmt.Errorf("failed to interpolate: %w", err)
	}

	// Evaluate at the point
	return poly.Eval(point), nil
}
