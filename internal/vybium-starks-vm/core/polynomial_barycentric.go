// Package core provides barycentric polynomial evaluation
package core

import (
	"fmt"
	"math/big"
)

// BarycentricEvaluate efficiently evaluates a polynomial using barycentric form
// This is O(n) instead of O(n^2) for standard Lagrange evaluation
//
// The barycentric formula:
// L(x) = Σ (w_i * y_i) / (x - x_i) / Σ w_i / (x - x_i)
//
// Where w_i are the barycentric weights:
// w_i = 1 / Π_{j≠i} (x_i - x_j)
//
// This is particularly efficient when:
// 1. Multiple evaluations are needed (weights can be cached)
// 2. The interpolation points are known in advance
// 3. The evaluation point is not one of the interpolation points
func BarycentricEvaluate(
	points []Point,
	field *Field,
	evaluationPoint *FieldElement,
) (*FieldElement, error) {
	n := len(points)
	if n == 0 {
		return nil, fmt.Errorf("no points provided")
	}

	// Special case: single point
	if n == 1 {
		return points[0].Y, nil
	}

	// Check if evaluation point is one of the interpolation points
	// If so, return the corresponding y value directly
	for _, p := range points {
		if evaluationPoint.Equal(p.X) {
			return p.Y, nil
		}
	}

	// Compute barycentric weights (preprocessing step)
	// w_i = 1 / Π_{j≠i} (x_i - x_j)
	weights, err := computeBarycentricWeights(points, field)
	if err != nil {
		return nil, err
	}

	// Compute differences (x - x_i) for all i
	differences := make([]*FieldElement, n)
	for i := 0; i < n; i++ {
		differences[i] = evaluationPoint.Sub(points[i].X)
	}

	// Batch invert differences for efficiency (Montgomery's trick)
	diffInverses, err := field.BatchInversion(differences)
	if err != nil {
		return nil, fmt.Errorf("failed to invert differences: %w", err)
	}

	// Compute numerator and denominator using barycentric formula
	// numerator = Σ (w_i * y_i) / (x - x_i)
	// denominator = Σ w_i / (x - x_i)
	numerator := field.Zero()
	denominator := field.Zero()

	for i := 0; i < n; i++ {
		// term = w_i / (x - x_i)
		term := weights[i].Mul(diffInverses[i])

		// Add to numerator: w_i * y_i / (x - x_i)
		numerator = numerator.Add(term.Mul(points[i].Y))

		// Add to denominator: w_i / (x - x_i)
		denominator = denominator.Add(term)
	}

	// Result = numerator / denominator
	return numerator.Div(denominator)
}

// computeBarycentricWeights computes the barycentric weights for interpolation
// w_i = 1 / Π_{j≠i} (x_i - x_j)
func computeBarycentricWeights(points []Point, field *Field) ([]*FieldElement, error) {
	n := len(points)
	weights := make([]*FieldElement, n)

	// Compute each weight
	for i := 0; i < n; i++ {
		product := field.One()

		for j := 0; j < n; j++ {
			if i != j {
				// product *= (x_i - x_j)
				diff := points[i].X.Sub(points[j].X)
				if diff.IsZero() {
					return nil, fmt.Errorf("duplicate interpolation points at index %d and %d", i, j)
				}
				product = product.Mul(diff)
			}
		}

		// w_i = 1 / product
		inv, err := product.Inv()
		if err != nil {
			return nil, fmt.Errorf("failed to compute weight %d: %w", i, err)
		}
		weights[i] = inv
	}

	return weights, nil
}

// BarycentricEvaluateBatch evaluates a polynomial at multiple points using barycentric form
// More efficient than individual evaluations when weights can be shared
func BarycentricEvaluateBatch(
	points []Point,
	field *Field,
	evaluationPoints []*FieldElement,
) ([]*FieldElement, error) {
	// Precompute weights once
	weights, err := computeBarycentricWeights(points, field)
	if err != nil {
		return nil, err
	}

	results := make([]*FieldElement, len(evaluationPoints))

	for i, evalPoint := range evaluationPoints {
		// Check if evaluation point is one of the interpolation points
		directMatch := false
		for _, p := range points {
			if evalPoint.Equal(p.X) {
				results[i] = p.Y
				directMatch = true
				break
			}
		}
		if directMatch {
			continue
		}

		// Compute differences
		differences := make([]*FieldElement, len(points))
		for j := 0; j < len(points); j++ {
			differences[j] = evalPoint.Sub(points[j].X)
		}

		// Batch invert
		diffInverses, err := field.BatchInversion(differences)
		if err != nil {
			return nil, fmt.Errorf("failed to invert differences for point %d: %w", i, err)
		}

		// Compute result using barycentric formula
		numerator := field.Zero()
		denominator := field.Zero()

		for j := 0; j < len(points); j++ {
			term := weights[j].Mul(diffInverses[j])
			numerator = numerator.Add(term.Mul(points[j].Y))
			denominator = denominator.Add(term)
		}

		results[i], err = numerator.Div(denominator)
		if err != nil {
			return nil, fmt.Errorf("failed to compute result for point %d: %w", i, err)
		}
	}

	return results, nil
}

// BarycentricInterpolation creates a polynomial in coefficient form from points
// Uses barycentric form as an intermediate representation
func BarycentricInterpolation(points []Point, field *Field) (*Polynomial, error) {
	n := len(points)
	if n == 0 {
		return nil, fmt.Errorf("no points provided")
	}

	// For small n, use direct Lagrange interpolation
	if n <= 10 {
		return LagrangeInterpolation(points, field)
	}

	// For larger n, use barycentric evaluation at power-of-2 points, then FFT
	// This is O(n log n) instead of O(n^2)

	// Find next power of 2
	size := 1
	for size < n {
		size *= 2
	}

	// Generate evaluation points (roots of unity)
	omega := field.GetPrimitiveRootOfUnity(size)
	if omega == nil {
		// Fallback to Lagrange
		return LagrangeInterpolation(points, field)
	}

	evalPoints := make([]*FieldElement, size)
	evalPoints[0] = field.One()
	for i := 1; i < size; i++ {
		evalPoints[i] = evalPoints[i-1].Mul(omega)
	}

	// Evaluate at all points using barycentric form
	values, err := BarycentricEvaluateBatch(points, field, evalPoints)
	if err != nil {
		return nil, fmt.Errorf("barycentric evaluation failed: %w", err)
	}

	// Use IFFT to get coefficients
	coeffs, err := IFFT(values, omega, field)
	if err != nil {
		return nil, fmt.Errorf("IFFT failed: %w", err)
	}

	// Trim to actual degree
	actualDegree := n - 1
	if actualDegree < len(coeffs) {
		coeffs = coeffs[:actualDegree+1]
	}

	return NewPolynomial(coeffs)
}

// IFFT performs inverse Fast Fourier Transform in the field
// Converts evaluation representation to coefficient representation
func IFFT(values []*FieldElement, omega *FieldElement, field *Field) ([]*FieldElement, error) {
	n := len(values)
	if n == 0 {
		return []*FieldElement{}, nil
	}

	// Check if n is power of 2
	if n&(n-1) != 0 {
		return nil, fmt.Errorf("IFFT requires power-of-2 size, got %d", n)
	}

	// Use omega^(-1) for inverse FFT
	omegaInv, err := omega.Inv()
	if err != nil {
		return nil, fmt.Errorf("failed to invert omega: %w", err)
	}

	// Perform FFT with omega^(-1)
	coeffs, err := FFT(values, omegaInv, field)
	if err != nil {
		return nil, err
	}

	// Scale by 1/n
	nInv, err := field.NewElementFromInt64(int64(n)).Inv()
	if err != nil {
		return nil, fmt.Errorf("failed to compute 1/n: %w", err)
	}

	for i := 0; i < n; i++ {
		coeffs[i] = coeffs[i].Mul(nInv)
	}

	return coeffs, nil
}

// FFT performs Fast Fourier Transform in the field
// Uses Cooley-Tukey radix-2 decimation-in-time algorithm
func FFT(values []*FieldElement, omega *FieldElement, field *Field) ([]*FieldElement, error) {
	n := len(values)
	if n <= 1 {
		return values, nil
	}

	// Check if n is power of 2
	if n&(n-1) != 0 {
		return nil, fmt.Errorf("FFT requires power-of-2 size, got %d", n)
	}

	// Bit-reversal permutation (in-place)
	result := make([]*FieldElement, n)
	copy(result, values)

	logN := 0
	temp := n
	for temp > 1 {
		logN++
		temp >>= 1
	}

	for i := 0; i < n; i++ {
		j := reverseBits(i, logN)
		if i < j {
			result[i], result[j] = result[j], result[i]
		}
	}

	// Cooley-Tukey butterfly
	for s := 1; s <= logN; s++ {
		m := 1 << s
		halfM := m >> 1

		// Compute omega^(n/m)
		exponent := big.NewInt(int64(n / m))
		wm := omega.Exp(exponent)

		for k := 0; k < n; k += m {
			w := field.One()

			for j := 0; j < halfM; j++ {
				t := w.Mul(result[k+j+halfM])
				u := result[k+j]
				result[k+j] = u.Add(t)
				result[k+j+halfM] = u.Sub(t)
				w = w.Mul(wm)
			}
		}
	}

	return result, nil
}

// reverseBits reverses the bits of an integer
func reverseBits(n int, bitLength int) int {
	result := 0
	for i := 0; i < bitLength; i++ {
		if n&(1<<i) != 0 {
			result |= 1 << (bitLength - 1 - i)
		}
	}
	return result
}

// GetPrimitiveRootOfUnity finds a primitive nth root of unity in the field
// Returns nil if no such root exists (n doesn't divide field order - 1)
func (f *Field) GetPrimitiveRootOfUnity(n int) *FieldElement {
	// For a prime field F_p, primitive nth root of unity exists iff n divides (p-1)

	pMinus1 := new(big.Int).Sub(f.modulus, big.NewInt(1))

	// Check if n divides (p-1)
	if new(big.Int).Mod(pMinus1, big.NewInt(int64(n))).Cmp(big.NewInt(0)) != 0 {
		return nil
	}

	// Find a generator g of the multiplicative group
	// Then omega = g^((p-1)/n) is a primitive nth root of unity

	// Try small candidates for generator
	for g := int64(2); g < 100; g++ {
		candidate := f.NewElementFromInt64(g)

		// Check if g^((p-1)/n) has order n
		exponent := new(big.Int).Div(pMinus1, big.NewInt(int64(n)))
		omega := candidate.Exp(exponent)

		// Verify omega^n = 1 and omega^k != 1 for k < n
		if omega.Exp(big.NewInt(int64(n))).Equal(f.One()) {
			// Check that omega has exactly order n
			hasOrderN := true
			for k := 1; k < n; k++ {
				if omega.Exp(big.NewInt(int64(k))).Equal(f.One()) {
					hasOrderN = false
					break
				}
			}

			if hasOrderN {
				return omega
			}
		}
	}

	return nil
}
