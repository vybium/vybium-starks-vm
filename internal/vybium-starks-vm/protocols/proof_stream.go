package protocols

import (
	"fmt"

	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/hash"
	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/xfield"
)

// ProofStreamError represents errors that can occur during proof stream operations
type ProofStreamError struct {
	Type    ProofStreamErrorType
	Message string
}

type ProofStreamErrorType int

const (
	ProofStreamErrorEmptyQueue ProofStreamErrorType = iota
	ProofStreamErrorInvalidItem
	ProofStreamErrorEncodingFailed
	ProofStreamErrorDecodingFailed
)

func (e ProofStreamError) Error() string {
	return fmt.Sprintf("ProofStream error [%d]: %s", e.Type, e.Message)
}

// ProofStream manages the Fiat-Shamir transcript and proof serialization.
// This is equivalent to triton-vm's ProofStream.
//
// The proof stream maintains:
// - A sequence of proof items (enqueued by prover, dequeued by verifier)
// - A Tip5 sponge state for Fiat-Shamir randomness generation
// - An index tracking the current position in the item queue
type ProofStream struct {
	// Items are the proof components in order
	Items []ProofItem

	// ItemsIndex tracks the current position when dequeuing (for verifier)
	ItemsIndex int

	// Sponge maintains the Fiat-Shamir state
	Sponge *hash.Tip5
}

// NewProofStream creates a new empty proof stream.
// This is equivalent to triton-vm's ProofStream::new()
func NewProofStream() *ProofStream {
	return &ProofStream{
		Items:      make([]ProofItem, 0),
		ItemsIndex: 0,
		Sponge:     hash.Init(),
	}
}

// TranscriptLength returns the number of field elements required to encode the proof.
// This is equivalent to triton-vm's ProofStream::transcript_length()
func (ps *ProofStream) TranscriptLength() int {
	proof := ps.ToProof()
	// Count field elements in proof
	count := 0
	for _, item := range proof.Items {
		switch item.Type {
		case ProofItemFieldElement:
			count++
		case ProofItemFieldElements:
			if elems, ok := item.Data.([]field.Element); ok {
				count += len(elems)
			}
		case ProofItemMerkleRoot:
			// Merkle root is 5 field elements (DigestLen)
			count += hash.DigestLen
		case ProofItemLog2PaddedHeight:
			count++ // u32 encoded as field element
		}
	}
	return count
}

// AlterFiatShamirStateWith alters the Fiat-Shamir sponge state with the encoding of the given item.
// Does NOT record the item in the proof stream.
// This is useful for items that are not sent to the verifier, e.g., the Claim.
//
// This is equivalent to triton-vm's ProofStream::alter_fiat_shamir_state_with()
func (ps *ProofStream) AlterFiatShamirStateWith(item BFieldCodec) error {
	encoded, err := item.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode item: %w", err)
	}
	ps.Sponge.PadAndAbsorbAll(encoded)
	return nil
}

// Enqueue sends a proof item from prover to verifier.
// Some items do not need to be included in the Fiat-Shamir heuristic,
// i.e., they do not need to modify the sponge state. For those items,
// namely those that evaluate to false according to IncludeInFiatShamirHeuristic(),
// the sponge state is not modified.
//
// This is equivalent to triton-vm's ProofStream::enqueue()
func (ps *ProofStream) Enqueue(item ProofItem) error {
	if item.IncludeInFiatShamirHeuristic() {
		// Encode and absorb into sponge
		encoded, err := item.Encode()
		if err != nil {
			return fmt.Errorf("failed to encode proof item: %w", err)
		}
		ps.Sponge.PadAndAbsorbAll(encoded)
	}
	ps.Items = append(ps.Items, item)
	return nil
}

// Dequeue receives a proof item from prover as verifier.
// See Enqueue() for more details.
//
// This is equivalent to triton-vm's ProofStream::dequeue()
func (ps *ProofStream) Dequeue() (ProofItem, error) {
	if ps.ItemsIndex >= len(ps.Items) {
		return ProofItem{}, ProofStreamError{
			Type:    ProofStreamErrorEmptyQueue,
			Message: "no more items in proof stream",
		}
	}

	item := ps.Items[ps.ItemsIndex]
	if item.IncludeInFiatShamirHeuristic() {
		// Encode and absorb into sponge (verifier side)
		encoded, err := item.Encode()
		if err != nil {
			return ProofItem{}, fmt.Errorf("failed to encode proof item: %w", err)
		}
		ps.Sponge.PadAndAbsorbAll(encoded)
	}
	ps.ItemsIndex++
	return item, nil
}

// SampleIndices produces numIndices uniform random numbers in the interval [0, upperBound).
// The upperBound must be a power of 2.
//
// This is equivalent to triton-vm's ProofStream::sample_indices()
func (ps *ProofStream) SampleIndices(upperBound int, numIndices int) ([]int, error) {
	// Verify upperBound is power of 2
	if upperBound == 0 || (upperBound&(upperBound-1)) != 0 {
		return nil, fmt.Errorf("upperBound must be a power of 2, got %d", upperBound)
	}

	// Verify upperBound <= field.Max
	if uint64(upperBound) > field.P-1 {
		return nil, fmt.Errorf("upperBound %d exceeds field maximum", upperBound)
	}

	indices := ps.Sponge.SampleIndices(uint32(upperBound), numIndices)
	result := make([]int, len(indices))
	for i, idx := range indices {
		result[i] = int(idx)
	}
	return result, nil
}

// SampleScalars produces numScalars random XFieldElement values.
//
// This is equivalent to triton-vm's ProofStream::sample_scalars()
func (ps *ProofStream) SampleScalars(numScalars int) ([]xfield.XFieldElement, error) {
	return ps.Sponge.SampleScalars(numScalars)
}

// ToProof converts the proof stream to a Proof.
// This is equivalent to triton-vm's ProofStream::into() for Proof
func (ps *ProofStream) ToProof() *Proof {
	return &Proof{
		Items: ps.Items,
	}
}

// FromProof creates a ProofStream from a Proof by reconstructing the Fiat-Shamir state.
// This is equivalent to triton-vm's ProofStream::try_from() for Proof
//
// The sponge state is reconstructed by processing all proof items that should be included
// in the Fiat-Shamir heuristic, in the order they were originally enqueued.
func ProofStreamFromProof(proof *Proof) (*ProofStream, error) {
	stream := NewProofStream()
	stream.Items = make([]ProofItem, len(proof.Items))
	copy(stream.Items, proof.Items)

	// Reconstruct the Fiat-Shamir sponge state by processing items in order
	// Only items that should be included in the heuristic are absorbed
	for _, item := range proof.Items {
		if item.IncludeInFiatShamirHeuristic() {
			encoded, err := item.Encode()
			if err != nil {
				return nil, fmt.Errorf("failed to encode proof item during reconstruction: %w", err)
			}
			stream.Sponge.PadAndAbsorbAll(encoded)
		}
	}

	return stream, nil
}

// BFieldCodec defines the interface for types that can be encoded/decoded to/from field element sequences
// for use in proof streams and Fiat-Shamir transcript generation.
//
// This interface is used by ProofStream to encode items into the Fiat-Shamir sponge state.
// Types implementing this interface can be passed to AlterFiatShamirStateWith() to update
// the transcript without adding the item to the proof stream itself.
//
// This is equivalent to triton-vm's BFieldCodec trait usage in ProofStream.
type BFieldCodec interface {
	// Encode converts the value to a sequence of field elements.
	// Returns an error if encoding fails.
	Encode() ([]field.Element, error)

	// Decode reconstructs the value from a sequence of field elements.
	// Returns an error if the sequence is malformed or incomplete.
	Decode(data []field.Element) error
}
