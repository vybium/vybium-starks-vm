package vybiumstarksvm

import (
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/protocols"
)

// FieldElement represents an element in a finite field
// This is the public type for field elements used throughout Vybium STARKs VM
type FieldElement = core.FieldElement

// Field represents a finite field
type Field = core.Field

// Proof represents a zkSTARK proof
type Proof = protocols.Proof

// Claim represents public information about a computation
type Claim = protocols.Claim

// Program represents a Vybium STARKs VM program
type Program struct {
	Instructions []Instruction
}

// Instruction represents a single VM instruction
type Instruction struct {
	Opcode   byte
	Argument *FieldElement
}

// Config represents configuration for the STARK prover/verifier
type Config struct {
	// Field modulus for finite field arithmetic
	FieldModulus string

	// Security level in bits (128 or 256)
	SecurityLevel int

	// Trace length (must be power of 2)
	TraceLength int

	// Evaluation domain size
	EvaluationDomain int

	// Number of FRI queries for soundness
	FRIQueries int

	// Blowup factor for low-degree extension
	BlowupFactor int
}

// VMConfig represents configuration for the Vybium STARKs VM
type VMConfig struct {
	// Field modulus for finite field arithmetic
	FieldModulus string

	// Enable program attestation (TIP-0006)
	ProgramAttestation bool

	// Enable permutation checks (TIP-0007)
	PermutationChecks bool

	// Enable lookup tables (TIP-0005)
	LookupTables bool
}

// ExecutionTrace represents the execution trace of a VM program
type ExecutionTrace struct {
	// Main execution trace (state transitions)
	Trace [][]*FieldElement

	// Auxiliary columns for cross-table arguments
	Auxiliary [][]*FieldElement

	// Public input
	PublicInput []*FieldElement

	// Public output
	PublicOutput []*FieldElement

	// Cycle count
	CycleCount int

	// Internal AET (for proof generation)
	// This is not exported in the public API but used internally
	internalAET interface{}
}

// ProofVerificationResult represents the result of proof verification
type ProofVerificationResult struct {
	// Whether the proof is valid
	Valid bool

	// Error message if verification failed
	Error string

	// Verification time in milliseconds
	VerificationTimeMs int64
}
