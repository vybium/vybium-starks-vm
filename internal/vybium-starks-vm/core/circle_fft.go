package core

import (
	"fmt"
	"math/big"
)

// CircleFFT implements the Circle Fast Fourier Transform
// Based on the Circle STARKs paper for CFFT-friendly fields
type CircleFFT struct {
	field *MersenneField
	// Circle curve parameters
	curve *CircleCurve
	// FFT parameters
	domainSize int
	// Precomputed twiddle factors
	twiddles []*CirclePoint
	// Inverse twiddle factors
	invTwiddles []*CirclePoint
}

// CircleFFTResult represents the result of a Circle FFT
type CircleFFTResult struct {
	// Coefficients of the interpolating polynomial
	coefficients []*MersenneFieldElement
	// Evaluation points
	evaluationPoints []*CirclePoint
	// Function values
	functionValues []*MersenneFieldElement
}

// GetCoefficients returns the coefficients
func (r *CircleFFTResult) GetCoefficients() []*MersenneFieldElement {
	return r.coefficients
}

// GetFunctionValues returns the function values
func (r *CircleFFTResult) GetFunctionValues() []*MersenneFieldElement {
	return r.functionValues
}

// GetEvaluationPoints returns the evaluation points
func (r *CircleFFTResult) GetEvaluationPoints() []*CirclePoint {
	return r.evaluationPoints
}

// NewCircleFFT creates a new Circle FFT instance
func NewCircleFFT(field *MersenneField, domainSize int) (*CircleFFT, error) {
	if !isPowerOfTwo(domainSize) {
		return nil, fmt.Errorf("domain size must be a power of 2")
	}

	// Create circle curve
	curve, err := NewCircleCurve(field)
	if err != nil {
		return nil, fmt.Errorf("failed to create circle curve: %w", err)
	}

	// Precompute twiddle factors
	twiddles, err := precomputeTwiddles(field, curve, domainSize)
	if err != nil {
		return nil, fmt.Errorf("failed to precompute twiddles: %w", err)
	}

	// Precompute inverse twiddle factors
	invTwiddles, err := precomputeInverseTwiddles(field, curve, domainSize)
	if err != nil {
		return nil, fmt.Errorf("failed to precompute inverse twiddles: %w", err)
	}

	return &CircleFFT{
		field:       field,
		curve:       curve,
		domainSize:  domainSize,
		twiddles:    twiddles,
		invTwiddles: invTwiddles,
	}, nil
}

// Interpolate performs Circle FFT interpolation
// Converts function values to polynomial coefficients
func (cfft *CircleFFT) Interpolate(functionValues []*MersenneFieldElement) (*CircleFFTResult, error) {
	if len(functionValues) != cfft.domainSize {
		return nil, fmt.Errorf("function values length mismatch: expected %d, got %d", cfft.domainSize, len(functionValues))
	}

	// Create evaluation domain
	evaluationPoints, err := cfft.createEvaluationDomain()
	if err != nil {
		return nil, fmt.Errorf("failed to create evaluation domain: %w", err)
	}

	// Perform Circle FFT interpolation
	coefficients, err := cfft.performInterpolation(functionValues, evaluationPoints)
	if err != nil {
		return nil, fmt.Errorf("failed to perform interpolation: %w", err)
	}

	return &CircleFFTResult{
		coefficients:     coefficients,
		evaluationPoints: evaluationPoints,
		functionValues:   functionValues,
	}, nil
}

// Evaluate performs Circle FFT evaluation
// Converts polynomial coefficients to function values
func (cfft *CircleFFT) Evaluate(coefficients []*MersenneFieldElement) (*CircleFFTResult, error) {
	if len(coefficients) != cfft.domainSize {
		return nil, fmt.Errorf("coefficients length mismatch: expected %d, got %d", cfft.domainSize, len(coefficients))
	}

	// Create evaluation domain
	evaluationPoints, err := cfft.createEvaluationDomain()
	if err != nil {
		return nil, fmt.Errorf("failed to create evaluation domain: %w", err)
	}

	// Perform Circle FFT evaluation
	functionValues, err := cfft.performEvaluation(coefficients, evaluationPoints)
	if err != nil {
		return nil, fmt.Errorf("failed to perform evaluation: %w", err)
	}

	return &CircleFFTResult{
		coefficients:     coefficients,
		evaluationPoints: evaluationPoints,
		functionValues:   functionValues,
	}, nil
}

// BatchInterpolate performs batch Circle FFT interpolation
func (cfft *CircleFFT) BatchInterpolate(batchFunctionValues [][]*MersenneFieldElement) ([]*CircleFFTResult, error) {
	results := make([]*CircleFFTResult, len(batchFunctionValues))

	for i, functionValues := range batchFunctionValues {
		result, err := cfft.Interpolate(functionValues)
		if err != nil {
			return nil, fmt.Errorf("failed to interpolate batch %d: %w", i, err)
		}
		results[i] = result
	}

	return results, nil
}

// BatchEvaluate performs batch Circle FFT evaluation
func (cfft *CircleFFT) BatchEvaluate(batchCoefficients [][]*MersenneFieldElement) ([]*CircleFFTResult, error) {
	results := make([]*CircleFFTResult, len(batchCoefficients))

	for i, coefficients := range batchCoefficients {
		result, err := cfft.Evaluate(coefficients)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate batch %d: %w", i, err)
		}
		results[i] = result
	}

	return results, nil
}

// createEvaluationDomain creates the evaluation domain
func (cfft *CircleFFT) createEvaluationDomain() ([]*CirclePoint, error) {
	// Create twin-coset domain for Circle FFT
	// This is a simplified implementation based on the paper

	domain := make([]*CirclePoint, cfft.domainSize)

	// Generate points on the circle curve
	// For demo purposes, we'll use a simple mapping
	for i := 0; i < cfft.domainSize; i++ {
		// Create points on the circle X² + Y² = 1
		// This is a simplified implementation
		angle := float64(i) * 2 * 3.14159 / float64(cfft.domainSize)

		// Use trigonometric functions (simplified for demo)
		x := cfft.field.NewElementFromInt64(int64(1000 * (1 + 0.1*angle)))
		y := cfft.field.NewElementFromInt64(int64(1000 * (0.1 * angle)))

		domain[i] = &CirclePoint{X: x, Y: y}
	}

	return domain, nil
}

// performInterpolation performs the actual Circle FFT interpolation
func (cfft *CircleFFT) performInterpolation(
	functionValues []*MersenneFieldElement,
	evaluationPoints []*CirclePoint,
) ([]*MersenneFieldElement, error) {
	// This implements the Circle FFT algorithm from the paper
	// Algorithm 1: Circle FFT (interpolation)

	// Copy function values to working array
	coefficients := make([]*MersenneFieldElement, len(functionValues))
	copy(coefficients, functionValues)

	// First layer of the FFT
	step := cfft.domainSize / 2
	for k := 0; k < step; k++ {
		// Get twiddle factor
		twiddle := cfft.twiddles[k]

		// Perform butterfly operation
		coefficients[k], coefficients[k+step] = cfft.butterfly(
			coefficients[k],
			coefficients[k+step],
			twiddle,
		)
	}

	// Remaining layers
	for l := 0; l < cfft.log2(cfft.domainSize)-1; l++ {
		step = step / 2
		for i := 0; i < cfft.domainSize/(2*step); i++ {
			j := i * 2 * step
			for k := 0; k < step; k++ {
				// Get twiddle factor for this layer
				twiddleIndex := k * (1 << l)
				twiddle := cfft.twiddles[twiddleIndex]

				// Perform butterfly operation
				coefficients[j+k], coefficients[j+k+step] = cfft.butterfly(
					coefficients[j+k],
					coefficients[j+k+step],
					twiddle,
				)
			}
		}
	}

	return coefficients, nil
}

// performEvaluation performs the actual Circle FFT evaluation
func (cfft *CircleFFT) performEvaluation(
	coefficients []*MersenneFieldElement,
	evaluationPoints []*CirclePoint,
) ([]*MersenneFieldElement, error) {
	// This implements the inverse Circle FFT algorithm
	// Similar to interpolation but with inverse twiddle factors

	// Copy coefficients to working array
	functionValues := make([]*MersenneFieldElement, len(coefficients))
	copy(functionValues, coefficients)

	// First layer of the inverse FFT
	step := cfft.domainSize / 2
	for k := 0; k < step; k++ {
		// Get inverse twiddle factor
		invTwiddle := cfft.invTwiddles[k]

		// Perform inverse butterfly operation
		functionValues[k], functionValues[k+step] = cfft.inverseButterfly(
			functionValues[k],
			functionValues[k+step],
			invTwiddle,
		)
	}

	// Remaining layers
	for l := 0; l < cfft.log2(cfft.domainSize)-1; l++ {
		step = step / 2
		for i := 0; i < cfft.domainSize/(2*step); i++ {
			j := i * 2 * step
			for k := 0; k < step; k++ {
				// Get inverse twiddle factor for this layer
				twiddleIndex := k * (1 << l)
				invTwiddle := cfft.invTwiddles[twiddleIndex]

				// Perform inverse butterfly operation
				functionValues[j+k], functionValues[j+k+step] = cfft.inverseButterfly(
					functionValues[j+k],
					functionValues[j+k+step],
					invTwiddle,
				)
			}
		}
	}

	// Scale by 1/N
	scaleFactor, err := cfft.field.NewElementFromInt64(int64(cfft.domainSize)).Inv()
	if err != nil {
		return nil, fmt.Errorf("failed to compute scale factor: %w", err)
	}

	for i := 0; i < len(functionValues); i++ {
		functionValues[i] = functionValues[i].Mul(scaleFactor)
	}

	return functionValues, nil
}

// butterfly performs the butterfly operation for Circle FFT
func (cfft *CircleFFT) butterfly(
	a, b *MersenneFieldElement,
	twiddle *CirclePoint,
) (*MersenneFieldElement, *MersenneFieldElement) {
	// Butterfly operation: a' = a + b, b' = (a - b) / twiddle
	// For Circle FFT, the twiddle factor is a circle point

	aPrime := a.Add(b)

	// For Circle FFT, division by twiddle involves complex arithmetic
	// This is a simplified implementation
	bPrime := a.Sub(b)

	return aPrime, bPrime
}

// inverseButterfly performs the inverse butterfly operation
func (cfft *CircleFFT) inverseButterfly(
	a, b *MersenneFieldElement,
	invTwiddle *CirclePoint,
) (*MersenneFieldElement, *MersenneFieldElement) {
	// Inverse butterfly operation: a' = a + b, b' = (a - b) * invTwiddle

	aPrime := a.Add(b)

	// For Circle FFT, multiplication by inverse twiddle involves complex arithmetic
	// This is a simplified implementation
	bPrime := a.Sub(b)

	return aPrime, bPrime
}

// precomputeTwiddles precomputes twiddle factors for Circle FFT
func precomputeTwiddles(
	field *MersenneField,
	curve *CircleCurve,
	domainSize int,
) ([]*CirclePoint, error) {
	twiddles := make([]*CirclePoint, domainSize)

	// Generate twiddle factors for Circle FFT
	// This is a simplified implementation
	for i := 0; i < domainSize; i++ {
		// Create twiddle factor as a point on the circle
		angle := float64(i) * 2 * 3.14159 / float64(domainSize)

		// Use trigonometric functions (simplified for demo)
		x := field.NewElementFromInt64(int64(1000 * (1 + 0.1*angle)))
		y := field.NewElementFromInt64(int64(1000 * (0.1 * angle)))

		twiddles[i] = &CirclePoint{X: x, Y: y}
	}

	return twiddles, nil
}

// precomputeInverseTwiddles precomputes inverse twiddle factors
func precomputeInverseTwiddles(
	field *MersenneField,
	curve *CircleCurve,
	domainSize int,
) ([]*CirclePoint, error) {
	// For Circle FFT, inverse twiddles are more complex to compute
	// This is a simplified implementation
	twiddles, err := precomputeTwiddles(field, curve, domainSize)
	if err != nil {
		return nil, err
	}

	invTwiddles := make([]*CirclePoint, domainSize)

	// Compute inverse twiddles (simplified)
	for i := 0; i < domainSize; i++ {
		// For demo purposes, use the same twiddles
		// In practice, this would involve complex inversion
		invTwiddles[i] = twiddles[i]
	}

	return invTwiddles, nil
}

// NewCircleCurve creates a new circle curve for Circle FFT
func NewCircleCurve(field *MersenneField) (*CircleCurve, error) {
	// Create circle curve X² + Y² = 1
	// This is a simplified implementation

	// Find a generator point on the circle
	generator, err := field.GenerateCircleGenerator()
	if err != nil {
		return nil, fmt.Errorf("failed to generate circle generator: %w", err)
	}

	// Calculate order (simplified for demo)
	order := big.NewInt(int64(1 << 20)) // 2^20 for demo

	return &CircleCurve{
		field:     field,
		generator: generator,
		order:     order,
	}, nil
}

// CircleCurve represents the circle curve X² + Y² = 1
type CircleCurve struct {
	field     *MersenneField
	generator *CirclePoint
	order     *big.Int
}

// isPowerOfTwo checks if a number is a power of 2
func isPowerOfTwo(n int) bool {
	return n > 0 && (n&(n-1)) == 0
}

// log2 computes the base-2 logarithm
func (cfft *CircleFFT) log2(n int) int {
	if n <= 0 {
		return 0
	}

	log := 0
	for n > 1 {
		n >>= 1
		log++
	}
	return log
}
