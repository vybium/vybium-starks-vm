package protocols

import (
	"fmt"
	"math"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
)

// STARKParameters contains the parameters for the STARK proof system
type STARKParameters struct {
	// SecurityLevel is the conjectured security level in bits
	// The system has soundness error 2^(-SecurityLevel)
	SecurityLevel int

	// FRIExpansionFactor is the ratio between the randomized trace domain
	// and the FRI domain. Must be a power of 2.
	FRIExpansionFactor int

	// NumTraceRandomizers is the number of randomizers for the execution trace
	// These are integral for achieving zero-knowledge
	NumTraceRandomizers int

	// NumCollinearityChecks is the number of collinearity checks in FRI
	NumCollinearityChecks int
}

// DefaultSTARKParameters returns the default STARK parameters
// These give a conjectured security level of 160 bits
func DefaultSTARKParameters() STARKParameters {
	return STARKParameters{
		SecurityLevel:         160,
		FRIExpansionFactor:    4,  // 4x blowup
		NumTraceRandomizers:   20, // For zero-knowledge
		NumCollinearityChecks: 80, // For soundness
	}
}

// NewSTARKParameters creates custom STARK parameters
func NewSTARKParameters(securityLevel int) STARKParameters {
	// Compute derived parameters based on security level
	numChecks := securityLevel / 2 // Conservative estimate
	if numChecks < 40 {
		numChecks = 40
	}

	return STARKParameters{
		SecurityLevel:         securityLevel,
		FRIExpansionFactor:    4,
		NumTraceRandomizers:   20,
		NumCollinearityChecks: numChecks,
	}
}

// Validate checks if the parameters are valid
func (sp *STARKParameters) Validate() error {
	if sp.SecurityLevel < 80 {
		return fmt.Errorf("security level must be at least 80 bits, got %d", sp.SecurityLevel)
	}

	if sp.FRIExpansionFactor < 2 || !isPowerOfTwo(sp.FRIExpansionFactor) {
		return fmt.Errorf("FRI expansion factor must be a power of 2 >= 2, got %d", sp.FRIExpansionFactor)
	}

	if sp.NumTraceRandomizers < 1 {
		return fmt.Errorf("number of trace randomizers must be at least 1, got %d", sp.NumTraceRandomizers)
	}

	if sp.NumCollinearityChecks < sp.SecurityLevel/3 {
		return fmt.Errorf("number of collinearity checks too low for security level")
	}

	return nil
}

// RandomizedTraceLength computes the length of the trace-randomized, padded trace
// Guaranteed to be a power of two
func (sp *STARKParameters) RandomizedTraceLength(paddedHeight int) int {
	totalLength := paddedHeight + sp.NumTraceRandomizers
	return nextPowerOfTwo(totalLength)
}

// InterpolantDegree returns the degree of the interpolant polynomial
func (sp *STARKParameters) InterpolantDegree(paddedHeight int) int {
	return sp.RandomizedTraceLength(paddedHeight) - 1
}

// MaxDegree returns the upper bound for the maximum degree of quotients
// This depends on the AIR constraints
func (sp *STARKParameters) MaxDegree(paddedHeight int) int {
	interpolantDegree := sp.InterpolantDegree(paddedHeight)

	// For Vybium STARKs VM, transition constraints have degree 2 (quadratic)
	// Boundary constraints have degree 1 (linear)
	// The composition has degree at most 2 * interpolantDegree
	maxConstraintDegree := 2

	return maxConstraintDegree * interpolantDegree
}

// FRIDomain creates the FRI protocol for this STARK
func (sp *STARKParameters) FRIDomain(paddedHeight int, field *core.Field) (*FRIProtocol, error) {
	if err := sp.Validate(); err != nil {
		return nil, fmt.Errorf("invalid STARK parameters: %w", err)
	}

	// Compute FRI domain size
	randomizedLen := sp.RandomizedTraceLength(paddedHeight)
	friDomainSize := randomizedLen * sp.FRIExpansionFactor

	// Ensure FRI domain is a power of 2
	friDomainSize = nextPowerOfTwo(friDomainSize)

	// Compute rate parameter
	// rate = ρ = 2^(-R) where R is the rate parameter
	// For expansion factor 4, we have rate = 1/4 = 2^(-2)
	rateLog := int(math.Log2(float64(sp.FRIExpansionFactor)))
	rate := field.NewElementFromInt64(1)
	two := field.NewElementFromInt64(2)
	for i := 0; i < rateLog; i++ {
		var err error
		rate, err = rate.Div(two)
		if err != nil {
			return nil, fmt.Errorf("failed to compute rate: %w", err)
		}
	}

	// Compute generator omega for the FRI domain
	// omega should be a primitive (friDomainSize)-th root of unity
	omega := field.GetPrimitiveRootOfUnity(friDomainSize)
	if omega == nil {
		return nil, fmt.Errorf("failed to compute %d-th root of unity", friDomainSize)
	}

	return NewFRIProtocol(field, rate, omega), nil
}

// ComputeSecurityLevel estimates the actual security level achieved
// based on the parameters and proof size
func (sp *STARKParameters) ComputeSecurityLevel(paddedHeight int) float64 {
	// Security comes from:
	// 1. FRI soundness: ~log2(domain_size) * num_checks / expansion_factor
	// 2. Number of collinearity checks

	randomizedLen := sp.RandomizedTraceLength(paddedHeight)
	friDomainSize := float64(randomizedLen * sp.FRIExpansionFactor)

	// Simplified security estimate
	friSecurity := math.Log2(friDomainSize) * float64(sp.NumCollinearityChecks) / float64(sp.FRIExpansionFactor)

	// Take the minimum of intended security and achieved security
	achieved := math.Min(float64(sp.SecurityLevel), friSecurity)

	return achieved
}

// String returns a human-readable representation of the parameters
func (sp *STARKParameters) String() string {
	return fmt.Sprintf("STARK{Security: %d bits, FRI: %dx, Randomizers: %d, Checks: %d}",
		sp.SecurityLevel,
		sp.FRIExpansionFactor,
		sp.NumTraceRandomizers,
		sp.NumCollinearityChecks)
}

// Helper functions are defined in domains.go
