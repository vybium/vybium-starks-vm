package utils

import (
	"fmt"
	"math/big"
)

// Config represents the configuration for zkSTARKs proof generation
type Config struct {
	// Field parameters
	FieldModulus *big.Int

	// Security parameters
	SecurityLevel int // Number of queries for FRI verification

	// Proof parameters
	TraceLength      int // Length of the computation trace
	EvaluationDomain int // Size of the evaluation domain (must be >= 2 * TraceLength)

	// FRI parameters
	FRIQueries int // Number of FRI queries

	// Hash function
	HashFunction string // "sha256" or "sha3"
}

// DefaultConfig returns a default configuration for the Fibonacci example
func DefaultConfig() *Config {
	return &Config{
		FieldModulus:     big.NewInt(3221225473), // 3 * 2^30 + 1
		SecurityLevel:    128,
		TraceLength:      1023,
		EvaluationDomain: 8192,
		FRIQueries:       3,
		HashFunction:     "sha3",
	}
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.FieldModulus.Cmp(big.NewInt(2)) <= 0 {
		return fmt.Errorf("field modulus must be greater than 2")
	}

	if c.SecurityLevel <= 0 {
		return fmt.Errorf("security level must be positive")
	}

	if c.TraceLength <= 0 {
		return fmt.Errorf("trace length must be positive")
	}

	if c.EvaluationDomain < 2*c.TraceLength {
		return fmt.Errorf("evaluation domain size (%d) must be at least 2 * trace length (%d)",
			c.EvaluationDomain, c.TraceLength)
	}

	if c.FRIQueries <= 0 {
		return fmt.Errorf("FRI queries must be positive")
	}

	if c.HashFunction != "sha256" && c.HashFunction != "sha3" && c.HashFunction != "poseidon" && c.HashFunction != "rescue" {
		return fmt.Errorf("hash function must be 'sha256', 'sha3', 'poseidon', or 'rescue', got '%s'", c.HashFunction)
	}

	return nil
}

// WithFieldModulus sets the field modulus
func (c *Config) WithFieldModulus(modulus *big.Int) *Config {
	c.FieldModulus = new(big.Int).Set(modulus)
	return c
}

// WithSecurityLevel sets the security level
func (c *Config) WithSecurityLevel(level int) *Config {
	c.SecurityLevel = level
	return c
}

// WithTraceLength sets the trace length
func (c *Config) WithTraceLength(length int) *Config {
	c.TraceLength = length
	return c
}

// WithEvaluationDomain sets the evaluation domain size
func (c *Config) WithEvaluationDomain(size int) *Config {
	c.EvaluationDomain = size
	return c
}

// WithFRIQueries sets the number of FRI queries
func (c *Config) WithFRIQueries(queries int) *Config {
	c.FRIQueries = queries
	return c
}

// WithHashFunction sets the hash function
func (c *Config) WithHashFunction(hashFunc string) *Config {
	c.HashFunction = hashFunc
	return c
}

// Clone creates a copy of the configuration
func (c *Config) Clone() *Config {
	return &Config{
		FieldModulus:     new(big.Int).Set(c.FieldModulus),
		SecurityLevel:    c.SecurityLevel,
		TraceLength:      c.TraceLength,
		EvaluationDomain: c.EvaluationDomain,
		FRIQueries:       c.FRIQueries,
		HashFunction:     c.HashFunction,
	}
}
