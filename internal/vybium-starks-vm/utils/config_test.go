package utils

import (
	"math/big"
	"testing"
)

// TestDefaultConfig tests the DefaultConfig function
func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	// Check default values
	if config.FieldModulus.Cmp(big.NewInt(0)) <= 0 {
		t.Error("FieldModulus should be positive")
	}

	if config.SecurityLevel <= 0 {
		t.Error("SecurityLevel should be positive")
	}

	if config.TraceLength <= 0 {
		t.Error("TraceLength should be positive")
	}

	if config.EvaluationDomain <= 0 {
		t.Error("EvaluationDomain should be positive")
	}

	if config.FRIQueries <= 0 {
		t.Error("FRIQueries should be positive")
	}

	if config.HashFunction == "" {
		t.Error("HashFunction should not be empty")
	}

	// Validate the default config
	if err := config.Validate(); err != nil {
		t.Errorf("DefaultConfig() should be valid: %v", err)
	}
}

// TestConfigValidate tests the Validate method
func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		config    *Config
		expectErr bool
	}{
		{
			name:      "valid default config",
			config:    DefaultConfig(),
			expectErr: false,
		},
		{
			name: "invalid field modulus (too small)",
			config: &Config{
				FieldModulus:     big.NewInt(1),
				SecurityLevel:    128,
				TraceLength:      1023,
				EvaluationDomain: 2048,
				FRIQueries:       3,
				HashFunction:     "sha256",
			},
			expectErr: true,
		},
		{
			name: "invalid security level (zero)",
			config: &Config{
				FieldModulus:     big.NewInt(3221225473),
				SecurityLevel:    0,
				TraceLength:      1023,
				EvaluationDomain: 2048,
				FRIQueries:       3,
				HashFunction:     "sha256",
			},
			expectErr: true,
		},
		{
			name: "invalid trace length (zero)",
			config: &Config{
				FieldModulus:     big.NewInt(3221225473),
				SecurityLevel:    128,
				TraceLength:      0,
				EvaluationDomain: 2048,
				FRIQueries:       3,
				HashFunction:     "sha256",
			},
			expectErr: true,
		},
		{
			name: "invalid evaluation domain (too small)",
			config: &Config{
				FieldModulus:     big.NewInt(3221225473),
				SecurityLevel:    128,
				TraceLength:      1023,
				EvaluationDomain: 1000, // < 2 * TraceLength
				FRIQueries:       3,
				HashFunction:     "sha256",
			},
			expectErr: true,
		},
		{
			name: "invalid FRI queries (zero)",
			config: &Config{
				FieldModulus:     big.NewInt(3221225473),
				SecurityLevel:    128,
				TraceLength:      1023,
				EvaluationDomain: 2048,
				FRIQueries:       0,
				HashFunction:     "sha256",
			},
			expectErr: true,
		},
		{
			name: "invalid hash function",
			config: &Config{
				FieldModulus:     big.NewInt(3221225473),
				SecurityLevel:    128,
				TraceLength:      1023,
				EvaluationDomain: 2048,
				FRIQueries:       3,
				HashFunction:     "invalid",
			},
			expectErr: true,
		},
		{
			name: "valid sha256",
			config: &Config{
				FieldModulus:     big.NewInt(3221225473),
				SecurityLevel:    128,
				TraceLength:      1023,
				EvaluationDomain: 2048,
				FRIQueries:       3,
				HashFunction:     "sha256",
			},
			expectErr: false,
		},
		{
			name: "valid sha3",
			config: &Config{
				FieldModulus:     big.NewInt(3221225473),
				SecurityLevel:    128,
				TraceLength:      1023,
				EvaluationDomain: 2048,
				FRIQueries:       3,
				HashFunction:     "sha3",
			},
			expectErr: false,
		},
		{
			name: "valid poseidon",
			config: &Config{
				FieldModulus:     big.NewInt(3221225473),
				SecurityLevel:    128,
				TraceLength:      1023,
				EvaluationDomain: 2048,
				FRIQueries:       3,
				HashFunction:     "poseidon",
			},
			expectErr: false,
		},
		{
			name: "valid rescue",
			config: &Config{
				FieldModulus:     big.NewInt(3221225473),
				SecurityLevel:    128,
				TraceLength:      1023,
				EvaluationDomain: 2048,
				FRIQueries:       3,
				HashFunction:     "rescue",
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.expectErr {
				t.Errorf("Validate() error = %v, expectErr = %v", err, tt.expectErr)
			}
		})
	}
}

// TestConfigWithMethods tests the With* methods
func TestConfigWithMethods(t *testing.T) {
	config := DefaultConfig()

	// Test WithFieldModulus
	newModulus := big.NewInt(123456789)
	config.WithFieldModulus(newModulus)
	if config.FieldModulus.Cmp(newModulus) != 0 {
		t.Errorf("WithFieldModulus() failed: expected %v, got %v", newModulus, config.FieldModulus)
	}

	// Test WithSecurityLevel
	config.WithSecurityLevel(256)
	if config.SecurityLevel != 256 {
		t.Errorf("WithSecurityLevel() failed: expected 256, got %d", config.SecurityLevel)
	}

	// Test WithTraceLength
	config.WithTraceLength(2047)
	if config.TraceLength != 2047 {
		t.Errorf("WithTraceLength() failed: expected 2047, got %d", config.TraceLength)
	}

	// Test WithEvaluationDomain
	config.WithEvaluationDomain(4096)
	if config.EvaluationDomain != 4096 {
		t.Errorf("WithEvaluationDomain() failed: expected 4096, got %d", config.EvaluationDomain)
	}

	// Test WithFRIQueries
	config.WithFRIQueries(5)
	if config.FRIQueries != 5 {
		t.Errorf("WithFRIQueries() failed: expected 5, got %d", config.FRIQueries)
	}

	// Test WithHashFunction
	config.WithHashFunction("sha256")
	if config.HashFunction != "sha256" {
		t.Errorf("WithHashFunction() failed: expected sha256, got %s", config.HashFunction)
	}
}

// TestConfigWithMethodsChaining tests chaining With* methods
func TestConfigWithMethodsChaining(t *testing.T) {
	config := DefaultConfig().
		WithSecurityLevel(192).
		WithTraceLength(511).
		WithEvaluationDomain(1024).
		WithFRIQueries(4).
		WithHashFunction("sha3")

	if config.SecurityLevel != 192 {
		t.Errorf("SecurityLevel: expected 192, got %d", config.SecurityLevel)
	}
	if config.TraceLength != 511 {
		t.Errorf("TraceLength: expected 511, got %d", config.TraceLength)
	}
	if config.EvaluationDomain != 1024 {
		t.Errorf("EvaluationDomain: expected 1024, got %d", config.EvaluationDomain)
	}
	if config.FRIQueries != 4 {
		t.Errorf("FRIQueries: expected 4, got %d", config.FRIQueries)
	}
	if config.HashFunction != "sha3" {
		t.Errorf("HashFunction: expected sha3, got %s", config.HashFunction)
	}
}

// TestConfigClone tests the Clone method
func TestConfigClone(t *testing.T) {
	original := DefaultConfig()
	original.SecurityLevel = 256
	original.TraceLength = 2047
	original.HashFunction = "poseidon"

	cloned := original.Clone()

	// Verify values match
	if cloned.FieldModulus.Cmp(original.FieldModulus) != 0 {
		t.Error("Cloned FieldModulus doesn't match")
	}
	if cloned.SecurityLevel != original.SecurityLevel {
		t.Error("Cloned SecurityLevel doesn't match")
	}
	if cloned.TraceLength != original.TraceLength {
		t.Error("Cloned TraceLength doesn't match")
	}
	if cloned.EvaluationDomain != original.EvaluationDomain {
		t.Error("Cloned EvaluationDomain doesn't match")
	}
	if cloned.FRIQueries != original.FRIQueries {
		t.Error("Cloned FRIQueries doesn't match")
	}
	if cloned.HashFunction != original.HashFunction {
		t.Error("Cloned HashFunction doesn't match")
	}

	// Verify it's a deep copy (modifying one doesn't affect the other)
	cloned.SecurityLevel = 512
	if original.SecurityLevel == 512 {
		t.Error("Modifying clone affected original")
	}

	// Verify FieldModulus is a deep copy
	cloned.FieldModulus.SetInt64(999999)
	if original.FieldModulus.Int64() == 999999 {
		t.Error("Modifying cloned FieldModulus affected original")
	}
}

// TestConfigValidationEdgeCases tests edge cases in validation
func TestConfigValidationEdgeCases(t *testing.T) {
	// Evaluation domain exactly 2 * trace length (should be valid)
	config := &Config{
		FieldModulus:     big.NewInt(3221225473),
		SecurityLevel:    128,
		TraceLength:      1024,
		EvaluationDomain: 2048, // exactly 2 * TraceLength
		FRIQueries:       3,
		HashFunction:     "sha256",
	}

	if err := config.Validate(); err != nil {
		t.Errorf("Config with EvaluationDomain = 2*TraceLength should be valid: %v", err)
	}

	// Evaluation domain one less than 2 * trace length (should be invalid)
	config.EvaluationDomain = 2047
	if err := config.Validate(); err == nil {
		t.Error("Config with EvaluationDomain < 2*TraceLength should be invalid")
	}

	// Minimum field modulus (3 should be valid)
	config = &Config{
		FieldModulus:     big.NewInt(3),
		SecurityLevel:    128,
		TraceLength:      1024,
		EvaluationDomain: 2048,
		FRIQueries:       3,
		HashFunction:     "sha256",
	}

	if err := config.Validate(); err != nil {
		t.Errorf("Config with FieldModulus = 3 should be valid: %v", err)
	}
}

// TestConfigImmutabilityOfDefault tests that DefaultConfig returns independent instances
func TestConfigImmutabilityOfDefault(t *testing.T) {
	config1 := DefaultConfig()
	config2 := DefaultConfig()

	// Modify config1
	config1.SecurityLevel = 999

	// config2 should not be affected
	if config2.SecurityLevel == 999 {
		t.Error("DefaultConfig() returns shared instances (should return independent instances)")
	}
}

// BenchmarkDefaultConfig benchmarks DefaultConfig creation
func BenchmarkDefaultConfig(b *testing.B) {
	for i := 0; i < b.N; i++ {
		DefaultConfig()
	}
}

// BenchmarkConfigValidate benchmarks config validation
func BenchmarkConfigValidate(b *testing.B) {
	config := DefaultConfig()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config.Validate()
	}
}

// BenchmarkConfigClone benchmarks config cloning
func BenchmarkConfigClone(b *testing.B) {
	config := DefaultConfig()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config.Clone()
	}
}

