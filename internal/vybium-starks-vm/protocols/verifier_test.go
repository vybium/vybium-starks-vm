package protocols

import (
	"math/big"
	"testing"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
)

// TestHighSecurityProofVerification tests verifier with high-security parameters
// This addresses the parity analysis requirement to test 192-bit and 256-bit security
func TestHighSecurityProofVerification(t *testing.T) {
	prime := new(big.Int)
	prime.SetString("2013265921", 10)
	field, err := core.NewField(prime)
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	testCases := []struct {
		name          string
		securityLevel int
	}{
		{
			name:          "192-bit security",
			securityLevel: 192,
		},
		{
			name:          "256-bit security",
			securityLevel: 256,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := NewSTARKParameters(tc.securityLevel)
			if err := params.Validate(); err != nil {
				t.Fatalf("Invalid parameters for %d-bit security: %v", tc.securityLevel, err)
			}

			verifier, err := NewVerifier(field, params)
			if err != nil {
				t.Fatalf("Failed to create verifier with %d-bit security: %v", tc.securityLevel, err)
			}

			if verifier == nil {
				t.Fatal("Verifier is nil")
			}

			// Verify parameters are correctly set
			if verifier.params.SecurityLevel != tc.securityLevel {
				t.Errorf("Expected security level %d, got %d", tc.securityLevel, verifier.params.SecurityLevel)
			}

			// Verify collinearity checks are sufficient
			minChecks := tc.securityLevel / 3
			if verifier.params.NumCollinearityChecks < minChecks {
				t.Errorf("NumCollinearityChecks (%d) should be at least %d for %d-bit security",
					verifier.params.NumCollinearityChecks, minChecks, tc.securityLevel)
			}
		})
	}
}

// TestHighSecurityParametersValidation tests that high-security parameters are valid
func TestHighSecurityParametersValidation(t *testing.T) {
	testCases := []struct {
		name          string
		securityLevel int
		shouldPass    bool
	}{
		{
			name:          "128-bit security",
			securityLevel: 128,
			shouldPass:    true,
		},
		{
			name:          "192-bit security",
			securityLevel: 192,
			shouldPass:    true,
		},
		{
			name:          "256-bit security",
			securityLevel: 256,
			shouldPass:    true,
		},
		{
			name:          "80-bit security (minimum)",
			securityLevel: 80,
			shouldPass:    true,
		},
		{
			name:          "79-bit security (too low)",
			securityLevel: 79,
			shouldPass:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := NewSTARKParameters(tc.securityLevel)
			err := params.Validate()

			if tc.shouldPass {
				if err != nil {
					t.Errorf("Expected valid parameters for %d-bit security, got error: %v", tc.securityLevel, err)
				}
			} else {
				if err == nil {
					t.Errorf("Expected invalid parameters for %d-bit security, but validation passed", tc.securityLevel)
				}
			}
		})
	}
}
