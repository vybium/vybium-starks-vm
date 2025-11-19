package protocols

import (
	"fmt"

	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/hash"
)

// Claim contains the public information of a verifiably correct computation.
// A corresponding Proof is needed to verify the computation.
//
// This follows Triton VM's Claim structure, adapted for Vybium STARKs VM.
type Claim struct {
	// ProgramDigest is the hash digest of the program that was executed
	// This ties the proof to a specific program (5 field elements per TIP-0006)
	ProgramDigest []field.Element

	// Version of the Vybium STARKs VM ISA and proof system
	// Helps ensure proofs are only valid for their intended version
	Version uint32

	// PublicInput is the public input to the computation
	PublicInput []field.Element

	// PublicOutput is the public output of the computation
	PublicOutput []field.Element
}

// NewClaim creates a new Claim with a program digest
func NewClaim(programDigest []field.Element) *Claim {
	return &Claim{
		ProgramDigest: programDigest,
		Version:       CurrentVersion,
		PublicInput:   make([]field.Element, 0),
		PublicOutput:  make([]field.Element, 0),
	}
}

// WithInput sets the public input for the claim
func (c *Claim) WithInput(input []field.Element) *Claim {
	c.PublicInput = input
	return c
}

// WithOutput sets the public output for the claim
func (c *Claim) WithOutput(output []field.Element) *Claim {
	c.PublicOutput = output
	return c
}

// Validate checks if the claim is well-formed
func (c *Claim) Validate() error {
	if len(c.ProgramDigest) != 5 {
		return fmt.Errorf("program digest must be exactly 5 elements (per TIP-0006), got %d", len(c.ProgramDigest))
	}

	// No need to check individual elements as field.Element is a value type
	// All field elements are always valid

	return nil
}

// Hash computes a hash of the claim for Fiat-Shamir
func (c *Claim) Hash() (field.Element, error) {
	if err := c.Validate(); err != nil {
		return field.Zero, fmt.Errorf("invalid claim: %w", err)
	}

	// Collect all elements to hash
	elements := make([]field.Element, 0)
	elements = append(elements, c.ProgramDigest...)
	elements = append(elements, field.New(uint64(c.Version)))
	elements = append(elements, c.PublicInput...)
	elements = append(elements, c.PublicOutput...)

	// Use Tip5 hash for field-friendly hashing (10-element rate)
	// For larger claims, hash using variable-length mode
	digest := hash.HashVarlen(elements)

	// Return first element of digest as the claim hash
	return digest[0], nil
}

// CurrentVersion is the version of the Vybium STARKs VM ISA and STARK proof system
// This changes whenever either the ISA or proof system changes
const CurrentVersion uint32 = 0
