package protocols

import (
	"math/big"
	"testing"

	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
)

// TestClaimValidation tests claim creation and validation
func TestClaimValidation(t *testing.T) {
	t.Run("ValidClaim", func(t *testing.T) {
		// Create a 5-element program digest (TIP-0006 compliant)
		programDigest := make([]field.Element, 5)
		for i := range programDigest {
			programDigest[i] = field.New(uint64(i + 1))
		}

		claim := NewClaim(programDigest)

		if err := claim.Validate(); err != nil {
			t.Errorf("Valid claim failed validation: %v", err)
		}
	})

	t.Run("InvalidClaim_WrongDigestSize", func(t *testing.T) {
		// Program digest must be exactly 5 elements
		programDigest := make([]field.Element, 3) // Wrong size

		claim := NewClaim(programDigest)

		if err := claim.Validate(); err == nil {
			t.Error("Expected invalid digest size to fail validation")
		}
	})

	t.Run("ClaimWithInput", func(t *testing.T) {
		programDigest := make([]field.Element, 5)
		for i := range programDigest {
			programDigest[i] = field.New(uint64(i + 1))
		}

		input := []field.Element{
			field.New(1),
			field.New(2),
		}
		claim := NewClaim(programDigest).WithInput(input)

		if err := claim.Validate(); err != nil {
			t.Errorf("Claim with input failed validation: %v", err)
		}

		if len(claim.PublicInput) != 2 {
			t.Errorf("Expected 2 input elements, got %d", len(claim.PublicInput))
		}
	})

	t.Run("ClaimWithOutput", func(t *testing.T) {
		programDigest := make([]field.Element, 5)
		for i := range programDigest {
			programDigest[i] = field.New(uint64(i + 1))
		}

		output := []field.Element{
			field.New(42),
		}
		claim := NewClaim(programDigest).WithOutput(output)

		if err := claim.Validate(); err != nil {
			t.Errorf("Claim with output failed validation: %v", err)
		}

		if len(claim.PublicOutput) != 1 {
			t.Errorf("Expected 1 output element, got %d", len(claim.PublicOutput))
		}
	})

	t.Run("ClaimHash", func(t *testing.T) {
		programDigest := make([]field.Element, 5)
		for i := range programDigest {
			programDigest[i] = field.New(uint64(i + 1))
		}

		claim := NewClaim(programDigest)

		hash, err := claim.Hash()
		if err != nil {
			t.Errorf("Failed to hash claim: %v", err)
		}

		// Hash should be a valid field element
		_ = hash
	})
}

// TestProofValidation tests proof structure validation
func TestProofValidation(t *testing.T) {
	t.Run("CreateEmptyProof", func(t *testing.T) {
		proof := NewProof()

		if proof == nil {
			t.Fatal("NewProof returned nil")
		}

		if proof.Items == nil {
			t.Error("Proof items should be initialized")
		}
	})

	t.Run("AddProofItems", func(t *testing.T) {
		proof := NewProof()

		// Add a merkle root
		merkleRoot := []byte{1, 2, 3, 4, 5}
		proof.Items = append(proof.Items, ProofItem{
			Type: ProofItemMerkleRoot,
			Data: merkleRoot,
		})

		if len(proof.Items) != 1 {
			t.Errorf("Expected 1 proof item, got %d", len(proof.Items))
		}
	})
}

// TestArithmeticDomain tests arithmetic domain creation
func TestArithmeticDomain(t *testing.T) {
	t.Run("CreateDomain", func(t *testing.T) {
		length := 256 // Must be power of 2

		domain, err := NewArithmeticDomain(length)
		if err != nil {
			t.Fatalf("NewArithmeticDomain failed: %v", err)
		}

		if domain == nil {
			t.Fatal("NewArithmeticDomain returned nil")
		}

		if domain.Length != length {
			t.Errorf("Expected domain length %d, got %d", length, domain.Length)
		}
	})

	t.Run("InvalidDomainSize", func(t *testing.T) {
		// Non-power of 2 should fail
		length := 100

		_, err := NewArithmeticDomain(length)

		if err == nil {
			t.Error("Expected error for non-power-of-2 domain size")
		}
	})
}

// TestSTARKParameters tests STARK parameter validation
func TestSTARKParameters(t *testing.T) {
	t.Run("ValidParameters", func(t *testing.T) {
		params := &STARKParameters{
			SecurityLevel:         128,
			FRIExpansionFactor:    4,
			NumCollinearityChecks: 80, // Need at least 80 for 128-bit security
			NumTraceRandomizers:   16,
		}

		if err := params.Validate(); err != nil {
			t.Errorf("Valid parameters failed validation: %v", err)
		}
	})

	t.Run("InvalidParameters_LowSecurity", func(t *testing.T) {
		params := &STARKParameters{
			SecurityLevel:         64, // Too low
			FRIExpansionFactor:    4,
			NumCollinearityChecks: 40,
			NumTraceRandomizers:   16,
		}

		if err := params.Validate(); err == nil {
			t.Error("Expected low security level to fail validation")
		}
	})

	t.Run("InvalidParameters_LowExpansion", func(t *testing.T) {
		params := &STARKParameters{
			SecurityLevel:         128,
			FRIExpansionFactor:    1, // Too low
			NumCollinearityChecks: 80,
			NumTraceRandomizers:   16,
		}

		if err := params.Validate(); err == nil {
			t.Error("Expected low expansion factor to fail validation")
		}
	})
}

// TestProverCreation tests prover instantiation
func TestProverCreation(t *testing.T) {
	t.Run("CreateProver", func(t *testing.T) {
		params := STARKParameters{
			SecurityLevel:         128,
			FRIExpansionFactor:    4,
			NumCollinearityChecks: 80,
			NumTraceRandomizers:   20,
		}

		prover, err := NewProver(params)
		if err != nil {
			t.Fatalf("Failed to create prover: %v", err)
		}

		if prover == nil {
			t.Fatal("Prover is nil")
		}
	})
}

// TestVerifierCreation tests verifier instantiation
func TestVerifierCreation(t *testing.T) {
	prime := new(big.Int)
	prime.SetString("2013265921", 10)
	field, err := core.NewField(prime)
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	t.Run("CreateVerifier", func(t *testing.T) {
		params := STARKParameters{
			SecurityLevel:         128,
			FRIExpansionFactor:    4,
			NumCollinearityChecks: 80,
			NumTraceRandomizers:   20,
		}

		verifier, err := NewVerifier(field, params)
		if err != nil {
			t.Fatalf("Failed to create verifier: %v", err)
		}

		if verifier == nil {
			t.Fatal("Verifier is nil")
		}
	})
}

// TestProcessorConstraints tests processor constraint creation
func TestProcessorConstraints(t *testing.T) {
	t.Run("CreateConstraints", func(t *testing.T) {
		constraints := CreateProcessorConstraints()

		if constraints == nil {
			t.Fatal("CreateProcessorConstraints returned nil")
		}

		// Constraints structure exists
		// Note: Constraint fields may be private
	})
}

// TestProverDomains tests domain derivation for prover
func TestProverDomains(t *testing.T) {
	t.Run("DeriveDomains", func(t *testing.T) {
		traceLength := 256
		friExpansion := 4
		numRandomizers := 20

		// Create FRI domain first (required parameter)
		friDomainSize := traceLength * friExpansion
		friDomain, err := NewArithmeticDomain(friDomainSize)
		if err != nil {
			t.Fatalf("Failed to create FRI domain: %v", err)
		}

		// Derive all domains (trace domain will be halved from randomized trace domain)
		domains, err := DeriveProverDomains(
			traceLength,
			numRandomizers,
			friDomain,
			512, // maxDegree
		)
		if err != nil {
			t.Fatalf("Failed to derive domains: %v", err)
		}

		if domains == nil {
			t.Fatal("Domains is nil")
		}

		// Verify domain sizes and relationships
		if domains.Trace == nil {
			t.Error("Trace domain is nil")
		}
		if domains.RandomizedTrace == nil {
			t.Error("Randomized trace domain is nil")
		}
		// CRITICAL: Verify trace domain is exactly half of randomized trace domain
		if domains.Trace.Length != domains.RandomizedTrace.Length/2 {
			t.Errorf("Trace domain length (%d) should be half of randomized trace domain length (%d)",
				domains.Trace.Length, domains.RandomizedTrace.Length)
		}
		// Verify trace domain generator is squared version of randomized trace generator
		expectedGenerator := domains.RandomizedTrace.Generator.Mul(domains.RandomizedTrace.Generator)
		if !domains.Trace.Generator.Equal(expectedGenerator) {
			t.Error("Trace domain generator should be randomized trace generator squared")
		}
	})
}

// TestAIRConstraints tests AIR constraint generation
func TestAIRConstraints(t *testing.T) {
	prime := new(big.Int)
	prime.SetString("2013265921", 10)
	field, err := core.NewField(prime)
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	t.Run("CreateAIRConstraints", func(t *testing.T) {
		traceLength := 256
		stateWidth := 10
		rate := field.NewElementFromInt64(2)

		air := NewAIR(field, traceLength, stateWidth, rate)

		if air == nil {
			t.Fatal("AIR is nil")
		}
	})
}
