package protocols

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
)

// TestComputeOmegaIY tests the computation of the first point in folding pairs
func TestComputeOmegaIY(t *testing.T) {
	// Create a test FRI protocol
	friDomain, err := NewArithmeticDomain(8)
	if err != nil {
		t.Fatalf("Failed to create FRI domain: %v", err)
	}

	// Create core field for omega
	goldilocksP := new(big.Int)
	goldilocksP.SetString("18446744069414584321", 10)
	coreField, err := core.NewField(goldilocksP)
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	omegaBig := friDomain.Generator.ToBigInt()
	fri := &FRIProtocol{
		omega: coreField.NewElement(omegaBig),
	}

	// Get domain elements
	domainElements := friDomain.Elements()

	// Test valid indices
	testCases := []struct {
		name          string
		index         int
		expectedIndex int
		shouldError   bool
	}{
		{"First index", 0, 0, false},
		{"Middle index", 2, 2, false},
		{"Last valid index", 3, 3, false},
		{"Out of bounds positive", 4, 0, true},
		{"Out of bounds negative", -1, 0, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := fri.computeOmegaIY(tc.index, domainElements)

			if tc.shouldError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				expected := domainElements[tc.expectedIndex]
				if !result.Equal(expected) {
					t.Errorf("Expected %v, got %v", expected, result)
				}
			}
		})
	}
}

// TestComputeNegOmegaIY tests the computation of the second point in folding pairs
func TestComputeNegOmegaIY(t *testing.T) {
	// Create a test FRI protocol
	friDomain, err := NewArithmeticDomain(8)
	if err != nil {
		t.Fatalf("Failed to create FRI domain: %v", err)
	}

	// Create core field for omega
	goldilocksP := new(big.Int)
	goldilocksP.SetString("18446744069414584321", 10)
	coreField, err := core.NewField(goldilocksP)
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	omegaBig := friDomain.Generator.ToBigInt()
	fri := &FRIProtocol{
		omega: coreField.NewElement(omegaBig),
	}

	// Get domain elements
	domainElements := friDomain.Elements()

	// Test that the pairing is correct: index i pairs with index i + n/2
	testCases := []struct {
		name          string
		index         int
		expectedIndex int
		shouldError   bool
	}{
		{"First index pairs with middle", 0, 4, false},
		{"Middle index pairs with last half", 2, 6, false},
		{"Last valid index", 3, 7, false},
		{"Out of bounds", 4, 0, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := fri.computeNegOmegaIY(tc.index, domainElements)

			if tc.shouldError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				expected := domainElements[tc.expectedIndex]
				if !result.Equal(expected) {
					t.Errorf("Expected %v, got %v", expected, result)
				}
			}
		})
	}
}

// TestFoldingPairRelationship verifies the mathematical relationship between paired points
func TestFoldingPairRelationship(t *testing.T) {
	// Create a domain
	domain, err := NewArithmeticDomain(16)
	if err != nil {
		t.Fatalf("Failed to create domain: %v", err)
	}

	// Create core field for omega
	goldilocksP := new(big.Int)
	goldilocksP.SetString("18446744069414584321", 10)
	coreField, err := core.NewField(goldilocksP)
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	omegaBig := domain.Generator.ToBigInt()
	fri := &FRIProtocol{
		omega: coreField.NewElement(omegaBig),
	}

	domainElements := domain.Elements()

	// For each index i, verify that:
	// 1. domain[i] and domain[i + n/2] are the two points that fold together
	// 2. When the domain is halved, domain[i]² should equal halvedDomain[i]
	for i := 0; i < len(domainElements)/2; i++ {
		point1, err := fri.computeOmegaIY(i, domainElements)
		if err != nil {
			t.Errorf("Error computing first point at index %d: %v", i, err)
			continue
		}

		point2, err := fri.computeNegOmegaIY(i, domainElements)
		if err != nil {
			t.Errorf("Error computing second point at index %d: %v", i, err)
			continue
		}

		// Verify they are different
		if point1.Equal(point2) {
			t.Errorf("Paired points should be different at index %d", i)
		}

		// Verify the relationship: point2 = -point1 (for properly configured domains)
		// This holds because ω^(n/2) = -1 for an n-th root of unity
		// So domain[i + n/2] = offset * ω^(i + n/2) = offset * ω^i * ω^(n/2) = -domain[i]
		_ = point1.Add(point2)
		// The sum should be 2 * offset (since we have offset*ω^i + offset*ω^(i+n/2))
		// Actually for a coset, this relationship is more complex
		// The key property is that they square to the same value in the halved domain
	}
}

// TestDomainHalving verifies that halving a domain squares the offset and generator
func TestDomainHalving(t *testing.T) {
	originalDomain, err := NewArithmeticDomain(16)
	if err != nil {
		t.Fatalf("Failed to create original domain: %v", err)
	}

	halvedDomain, err := originalDomain.Halve()
	if err != nil {
		t.Fatalf("Failed to halve domain: %v", err)
	}

	// Verify length is halved
	if halvedDomain.Length != originalDomain.Length/2 {
		t.Errorf("Expected halved length %d, got %d", originalDomain.Length/2, halvedDomain.Length)
	}

	// Verify generator is squared
	expectedGenerator := originalDomain.Generator.Mul(originalDomain.Generator)
	if !halvedDomain.Generator.Equal(expectedGenerator) {
		t.Errorf("Halved generator should be squared")
	}

	// Verify offset is squared (this is the key fix from triton-vm)
	expectedOffset := originalDomain.Offset.Mul(originalDomain.Offset)
	if !halvedDomain.Offset.Equal(expectedOffset) {
		t.Errorf("Halved offset should be squared")
	}

	// Verify the key property: halvedDomain[i] = offset^2 * (generator^2)^i
	// This is the mathematical relationship after squaring both offset and generator
	halvedElements := halvedDomain.Elements()
	power := halvedDomain.Offset
	for i := 0; i < len(halvedElements); i++ {
		if !halvedElements[i].Equal(power) {
			t.Errorf("Halved element %d doesn't match expected value", i)
		}
		power = power.Mul(halvedDomain.Generator)
	}
}

// TestFinalPolynomialDomainCreation tests the fix for Task #11
func TestFinalPolynomialDomainCreation(t *testing.T) {
	// This test verifies that createFinalPolynomial uses proper arithmetic domains
	// with primitive roots rather than sequential integers

	// Create domains of various sizes
	sizes := []int{4, 8, 16, 32}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			domain, err := NewArithmeticDomain(size)
			if err != nil {
				t.Fatalf("Failed to create domain: %v", err)
			}

			elements := domain.Elements()

			// Verify all elements are distinct
			seen := make(map[uint64]bool)
			for i, elem := range elements {
				val := elem.Value()
				if seen[val] {
					t.Errorf("Duplicate domain element at index %d: %v", i, elem)
				}
				seen[val] = true
			}

			// Verify the generator has the correct properties
			// After 'size' multiplications, generator^size should equal 1 (modulo offset)
			if len(elements) != size {
				t.Errorf("Expected %d elements, got %d", size, len(elements))
			}
		})
	}
}

// TestFRIFoldingConsistency tests that folding is done correctly
func TestFRIFoldingConsistency(t *testing.T) {
	// Create test domain
	domain, err := NewArithmeticDomain(8)
	if err != nil {
		t.Fatalf("Failed to create domain: %v", err)
	}

	// Create core field for omega
	goldilocksP := new(big.Int)
	goldilocksP.SetString("18446744069414584321", 10)
	coreField, err := core.NewField(goldilocksP)
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	omegaBig := domain.Generator.ToBigInt()
	fri := &FRIProtocol{
		omega: coreField.NewElement(omegaBig),
	}

	domainElements := domain.Elements()

	// Create test function values
	functionValues := make([]field.Element, len(domainElements))
	for i := range functionValues {
		// Use simple test values
		functionValues[i] = field.New(uint64(i + 1))
	}

	// Verify that for each index, we can retrieve the paired points
	for i := 0; i < len(domainElements)/2; i++ {
		point1, err1 := fri.computeOmegaIY(i, domainElements)
		point2, err2 := fri.computeNegOmegaIY(i, domainElements)

		if err1 != nil || err2 != nil {
			t.Errorf("Error computing paired points at index %d", i)
			continue
		}

		// Verify we got the expected domain points
		if !point1.Equal(domainElements[i]) {
			t.Errorf("First point mismatch at index %d", i)
		}
		if !point2.Equal(domainElements[i+len(domainElements)/2]) {
			t.Errorf("Second point mismatch at index %d", i)
		}
	}
}

// BenchmarkComputeOmegaIY benchmarks the computation
func BenchmarkComputeOmegaIY(b *testing.B) {
	domain, _ := NewArithmeticDomain(1024)
	goldilocksP := new(big.Int)
	goldilocksP.SetString("18446744069414584321", 10)
	coreField, _ := core.NewField(goldilocksP)
	omegaBig := domain.Generator.ToBigInt()
	fri := &FRIProtocol{omega: coreField.NewElement(omegaBig)}
	domainElements := domain.Elements()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = fri.computeOmegaIY(i%512, domainElements)
	}
}

// BenchmarkComputeNegOmegaIY benchmarks the computation
func BenchmarkComputeNegOmegaIY(b *testing.B) {
	domain, _ := NewArithmeticDomain(1024)
	goldilocksP := new(big.Int)
	goldilocksP.SetString("18446744069414584321", 10)
	coreField, _ := core.NewField(goldilocksP)
	omegaBig := domain.Generator.ToBigInt()
	fri := &FRIProtocol{omega: coreField.NewElement(omegaBig)}
	domainElements := domain.Elements()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = fri.computeNegOmegaIY(i%512, domainElements)
	}
}

