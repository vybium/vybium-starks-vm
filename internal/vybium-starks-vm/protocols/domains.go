package protocols

import (
	"fmt"

	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/polynomial"
)

// Helper functions
func isPowerOfTwo(n int) bool {
	return n > 0 && (n&(n-1)) == 0
}

func nextPowerOfTwo(n int) int {
	if n <= 1 {
		return 1
	}
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	n++
	return n
}

// ArithmeticDomain represents a domain for polynomial operations
// This is a coset of a multiplicative subgroup: {offset * generator^i : i = 0..length-1}
//
// All domains have power-of-2 lengths for efficient NTT operations.
type ArithmeticDomain struct {
	// Offset shifts the domain (use field.One() for no offset)
	Offset field.Element

	// Generator is a primitive n-th root of unity where n = length
	Generator field.Element

	// Length is the number of elements in the domain (must be power of 2)
	Length int
}

// NewArithmeticDomain creates a domain with the given length and no offset
func NewArithmeticDomain(length int) (*ArithmeticDomain, error) {
	if !isPowerOfTwo(length) {
		return nil, fmt.Errorf("domain length must be a power of 2, got %d", length)
	}

	// Get primitive root of unity for this length from vybium-crypto
	generator := field.PrimitiveRootOfUnity(uint64(length))

	return &ArithmeticDomain{
		Offset:    field.One,
		Generator: generator,
		Length:    length,
	}, nil
}

// WithOffset returns a new domain with the given offset
func (d *ArithmeticDomain) WithOffset(offset field.Element) *ArithmeticDomain {
	return &ArithmeticDomain{
		Offset:    offset,
		Generator: d.Generator,
		Length:    d.Length,
	}
}

// Halve returns a domain with half the length
// Both offset and generator are squared (not halved)

func (d *ArithmeticDomain) Halve() (*ArithmeticDomain, error) {
	if d.Length < 2 {
		return nil, fmt.Errorf("cannot halve domain of length %d", d.Length)
	}

	// Offset for half domain is offset^2
	halfOffset := d.Offset.Mul(d.Offset)
	// Generator for half domain is generator^2
	halfGenerator := d.Generator.Mul(d.Generator)

	return &ArithmeticDomain{
		Offset:    halfOffset,
		Generator: halfGenerator,
		Length:    d.Length / 2,
	}, nil
}

// Double returns a domain with double the length
func (d *ArithmeticDomain) Double() (*ArithmeticDomain, error) {
	doubleLength := d.Length * 2

	// Get generator for double length
	generator := field.PrimitiveRootOfUnity(uint64(doubleLength))

	return &ArithmeticDomain{
		Offset:    d.Offset,
		Generator: generator,
		Length:    doubleLength,
	}, nil
}

// Elements returns all elements in the domain: {offset * generator^i : i = 0..length-1}
func (d *ArithmeticDomain) Elements() []field.Element {
	elements := make([]field.Element, d.Length)
	current := d.Offset
	for i := 0; i < d.Length; i++ {
		elements[i] = current
		current = current.Mul(d.Generator)
	}
	return elements
}

// Evaluate evaluates a polynomial (in coefficient form) over the entire domain
func (d *ArithmeticDomain) Evaluate(poly *polynomial.Polynomial) ([]field.Element, error) {
	// Use direct evaluation (NTT would be more efficient but requires implementation)
	domainElements := d.Elements()
	values := make([]field.Element, len(domainElements))

	for i, x := range domainElements {
		values[i] = poly.Evaluate(x)
	}

	return values, nil
}

// String returns a human-readable representation
func (d *ArithmeticDomain) String() string {
	return fmt.Sprintf("Domain{length: %d, offset: %v, generator: %v}",
		d.Length, d.Offset, d.Generator)
}

// ProverDomains contains all arithmetic domains used by the prover
//
// Following Triton VM's design:
// - trace: the original execution trace domain
// - randomized_trace: extended for zero-knowledge randomizers
// - quotient: for computing constraint quotients
// - fri: for the FRI low-degree test
type ProverDomains struct {
	// Trace domain: dictated by the AET height
	Trace *ArithmeticDomain

	// Randomized trace domain: includes trace randomizers for zero-knowledge
	// Must be exactly 2x the trace domain length
	RandomizedTrace *ArithmeticDomain

	// Quotient domain: large enough for constraint computations
	Quotient *ArithmeticDomain

	// FRI domain: for the FRI protocol
	FRI *ArithmeticDomain
}

// DeriveProverDomains computes all domains needed for proving
//
// Domain derivation follows standard STARK practices:
// 1. Compute randomized trace length (padded_height + num_randomizers, rounded to power of 2)
// 2. Trace domain is half of randomized trace domain (CRITICAL: must be derived, not created directly)
// 3. Quotient domain length is next power of 2 >= max_degree
// 4. FRI domain is provided by FRI parameters
func DeriveProverDomains(
	paddedHeight int,
	numTraceRandomizers int,
	friDomain *ArithmeticDomain,
	maxDegree int,
) (*ProverDomains, error) {
	// Randomized trace domain includes both trace and randomizers
	// This must be computed first, then trace domain is derived from it
	randomizedTraceLen := paddedHeight + numTraceRandomizers
	randomizedTraceLen = nextPowerOfTwo(randomizedTraceLen)
	randomizedTraceDomain, err := NewArithmeticDomain(randomizedTraceLen)
	if err != nil {
		return nil, fmt.Errorf("failed to create randomized trace domain: %w", err)
	}

	// Trace domain is derived by halving the randomized trace domain
	// This ensures proper algebraic relationship between domains
	// Note: trace domain length may be > padded height if numTraceRandomizers > paddedHeight
	
	traceDomain, err := randomizedTraceDomain.Halve()
	if err != nil {
		return nil, fmt.Errorf("failed to halve randomized trace domain: %w", err)
	}

	// Quotient domain length is next power of 2 >= max_degree
	quotientDomainLen := nextPowerOfTwo(maxDegree)
	quotientDomain, err := NewArithmeticDomain(quotientDomainLen)
	if err != nil {
		return nil, fmt.Errorf("failed to create quotient domain: %w", err)
	}

	// Apply FRI offset to quotient domain (important for soundness)
	quotientDomain = quotientDomain.WithOffset(friDomain.Offset)

	return &ProverDomains{
		Trace:           traceDomain,
		RandomizedTrace: randomizedTraceDomain,
		Quotient:        quotientDomain,
		FRI:             friDomain,
	}, nil
}

// String returns a human-readable representation of all domains
func (pd *ProverDomains) String() string {
	return fmt.Sprintf(`ProverDomains{
  Trace: %s
  RandomizedTrace: %s
  Quotient: %s
  FRI: %s
}`, pd.Trace, pd.RandomizedTrace, pd.Quotient, pd.FRI)
}
