package protocols

import (
	"math/big"
	"testing"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
)

func TestSTARKProverCreation(t *testing.T) {
	t.Run("CreateProverWithValidParameters", func(t *testing.T) {
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

	t.Run("CreateProverWithInvalidParameters", func(t *testing.T) {
		params := STARKParameters{
			SecurityLevel:         64, // Too low
			FRIExpansionFactor:    2,
			NumCollinearityChecks: 20,
			NumTraceRandomizers:   10,
		}

		_, err := NewProver(params)
		if err == nil {
			t.Error("Expected error for invalid parameters")
		}
	})
}

func TestSTARKVerifierCreation(t *testing.T) {
	prime := new(big.Int)
	prime.SetString("2013265921", 10)
	field, err := core.NewField(prime)
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	t.Run("CreateVerifierWithValidParameters", func(t *testing.T) {
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

func TestSTARKParametersValidation(t *testing.T) {
	t.Run("ValidParameters", func(t *testing.T) {
		params := STARKParameters{
			SecurityLevel:         128,
			FRIExpansionFactor:    4,
			NumCollinearityChecks: 80,
			NumTraceRandomizers:   20,
		}

		err := params.Validate()
		if err != nil {
			t.Errorf("Valid parameters failed validation: %v", err)
		}
	})

	t.Run("InvalidSecurityLevel", func(t *testing.T) {
		params := STARKParameters{
			SecurityLevel:         64, // Too low
			FRIExpansionFactor:    4,
			NumCollinearityChecks: 80,
			NumTraceRandomizers:   20,
		}

		err := params.Validate()
		if err == nil {
			t.Error("Expected error for low security level")
		}
	})

	t.Run("InvalidExpansionFactor", func(t *testing.T) {
		params := STARKParameters{
			SecurityLevel:         128,
			FRIExpansionFactor:    1, // Too low
			NumCollinearityChecks: 80,
			NumTraceRandomizers:   20,
		}

		err := params.Validate()
		if err == nil {
			t.Error("Expected error for low expansion factor")
		}
	})

	t.Run("InvalidCollinearityChecks", func(t *testing.T) {
		params := STARKParameters{
			SecurityLevel:         128,
			FRIExpansionFactor:    4,
			NumCollinearityChecks: 10, // Too low for 128-bit security
			NumTraceRandomizers:   20,
		}

		err := params.Validate()
		if err == nil {
			t.Error("Expected error for insufficient collinearity checks")
		}
	})
}

func TestProofStructure(t *testing.T) {
	t.Run("CreateEmptyProof", func(t *testing.T) {
		proof := NewProof()

		if proof == nil {
			t.Fatal("Proof is nil")
		}

		if proof.Items == nil {
			t.Error("Proof items should be initialized")
		}
	})

	t.Run("AddItemsToProof", func(t *testing.T) {
		proof := NewProof()

		// Add various proof items
		proof.Items = append(proof.Items, ProofItem{
			Type: ProofItemMerkleRoot,
			Data: []byte{1, 2, 3, 4},
		})

		proof.Items = append(proof.Items, ProofItem{
			Type: ProofItemFRICodeword,
			Data: []byte{5, 6, 7, 8},
		})

		if len(proof.Items) != 2 {
			t.Errorf("Expected 2 proof items, got %d", len(proof.Items))
		}
	})
}
