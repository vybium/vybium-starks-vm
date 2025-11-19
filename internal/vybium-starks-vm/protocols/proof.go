package protocols

import (
	"fmt"

	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/hash"
)

// Proof contains the cryptographic information to verify a computation.
// Should be used together with a Claim.
//
// The proof is structured as a sequence of ProofItems that the verifier
// processes in order to verify the computation.
//
// Note: Field arithmetic is now handled by vybium-crypto field.Element
// which is self-contained, so no field parameter is needed.
type Proof struct {
	// Items are the proof components (Merkle roots, FRI data, etc.)
	Items []ProofItem
}

// ProofItem represents a single component of a proof
type ProofItem struct {
	Type ProofItemType
	Data interface{}
}

// ProofItemType identifies the type of proof item
type ProofItemType int

const (
	// ProofItemMerkleRoot is a Merkle tree root commitment
	// Included in Fiat-Shamir heuristic: true
	ProofItemMerkleRoot ProofItemType = iota

	// ProofItemOutOfDomainMainRow is an out-of-domain main row evaluation
	// Included in Fiat-Shamir heuristic: true
	ProofItemOutOfDomainMainRow

	// ProofItemOutOfDomainAuxRow is an out-of-domain auxiliary row evaluation
	// Included in Fiat-Shamir heuristic: true
	ProofItemOutOfDomainAuxRow

	// ProofItemOutOfDomainQuotientSegments is out-of-domain quotient segments
	// Included in Fiat-Shamir heuristic: true
	ProofItemOutOfDomainQuotientSegments

	// ProofItemAuthenticationStructure is a Merkle authentication structure
	// Included in Fiat-Shamir heuristic: false (implied by Merkle root)
	ProofItemAuthenticationStructure

	// ProofItemMasterMainTableRows are master main table rows
	// Included in Fiat-Shamir heuristic: false (implied by Merkle root)
	ProofItemMasterMainTableRows

	// ProofItemMasterAuxTableRows are master auxiliary table rows
	// Included in Fiat-Shamir heuristic: false (implied by Merkle root)
	ProofItemMasterAuxTableRows

	// ProofItemLog2PaddedHeight is the log2 of the padded trace height
	// Included in Fiat-Shamir heuristic: false
	ProofItemLog2PaddedHeight

	// ProofItemQuotientSegmentsElements are quotient segment elements
	// Included in Fiat-Shamir heuristic: false
	ProofItemQuotientSegmentsElements

	// ProofItemFRICodeword is a FRI codeword commitment
	// Included in Fiat-Shamir heuristic: false
	ProofItemFRICodeword

	// ProofItemFRIPolynomial is a FRI polynomial
	// Included in Fiat-Shamir heuristic: false
	ProofItemFRIPolynomial

	// ProofItemFRIResponse is a FRI query response
	// Included in Fiat-Shamir heuristic: false
	ProofItemFRIResponse

	// ProofItemMerkleProof is a Merkle authentication path (legacy)
	// Included in Fiat-Shamir heuristic: false
	ProofItemMerkleProof

	// ProofItemFieldElement is a single field element
	// Included in Fiat-Shamir heuristic: true
	ProofItemFieldElement

	// ProofItemFieldElements is a slice of field elements
	// Included in Fiat-Shamir heuristic: true
	ProofItemFieldElements
)

// IncludeInFiatShamirHeuristic returns whether this proof item should be included
// in the Fiat-Shamir heuristic.
//
// The Fiat-Shamir heuristic is sound only if all elements in the (current) transcript
// are considered. However, certain elements indirectly appear more than once.
// For example, a Merkle root is a commitment to any number of elements. If the Merkle
// root is part of the transcript, has been considered in the Fiat-Shamir heuristic,
// and assuming collision resistance of the hash function in use, none of the
// committed-to elements have to be considered in the Fiat-Shamir heuristic again.
//
// This is equivalent to triton-vm's ProofItem::include_in_fiat_shamir_heuristic()
func (pi ProofItem) IncludeInFiatShamirHeuristic() bool {
	switch pi.Type {
	case ProofItemMerkleRoot,
		ProofItemOutOfDomainMainRow,
		ProofItemOutOfDomainAuxRow,
		ProofItemOutOfDomainQuotientSegments,
		ProofItemFieldElement,
		ProofItemFieldElements:
		return true
	case ProofItemAuthenticationStructure,
		ProofItemMasterMainTableRows,
		ProofItemMasterAuxTableRows,
		ProofItemLog2PaddedHeight,
		ProofItemQuotientSegmentsElements,
		ProofItemFRICodeword,
		ProofItemFRIPolynomial,
		ProofItemFRIResponse,
		ProofItemMerkleProof:
		return false
	default:
		return false
	}
}

// Encode encodes the proof item to a sequence of field elements for Fiat-Shamir.
// This is equivalent to triton-vm's BFieldCodec::encode() for ProofItem
func (pi ProofItem) Encode() ([]field.Element, error) {
	// Import bfieldcodec for encoding
	// For now, implement basic encoding based on type
	switch pi.Type {
	case ProofItemMerkleRoot:
		if root, ok := pi.Data.([]byte); ok {
			// Convert bytes to field elements (Digest is 5 elements)
			if len(root) != hash.DigestLen*8 {
				return nil, fmt.Errorf("invalid Merkle root length: expected %d bytes, got %d", hash.DigestLen*8, len(root))
			}
			result := make([]field.Element, hash.DigestLen)
			for i := 0; i < hash.DigestLen; i++ {
				var bytes [8]byte
				copy(bytes[:], root[i*8:(i+1)*8])
				result[i] = field.FromBytes(bytes)
			}
			return result, nil
		}
		return nil, fmt.Errorf("invalid Merkle root data type")

	case ProofItemLog2PaddedHeight:
		if height, ok := pi.Data.(int); ok {
			return []field.Element{field.New(uint64(height))}, nil
		}
		return nil, fmt.Errorf("invalid log2 height data type")

	case ProofItemFieldElement:
		if elem, ok := pi.Data.(field.Element); ok {
			return []field.Element{elem}, nil
		}
		return nil, fmt.Errorf("invalid field element data type")

	case ProofItemFieldElements:
		if elems, ok := pi.Data.([]field.Element); ok {
			return elems, nil
		}
		return nil, fmt.Errorf("invalid field elements data type")

	default:
		// For other types, return empty (they don't need encoding for Fiat-Shamir)
		return []field.Element{}, nil
	}
}

// NewProof creates a new empty proof
func NewProof() *Proof {
	return &Proof{
		Items: make([]ProofItem, 0),
	}
}

// AddItem adds a proof item to the proof
func (p *Proof) AddItem(itemType ProofItemType, data interface{}) {
	p.Items = append(p.Items, ProofItem{
		Type: itemType,
		Data: data,
	})
}

// AddMerkleRoot adds a Merkle root to the proof
func (p *Proof) AddMerkleRoot(root []byte) {
	p.AddItem(ProofItemMerkleRoot, root)
}

// AddLog2Height adds the log2 of padded height to the proof
func (p *Proof) AddLog2Height(log2Height int) {
	p.AddItem(ProofItemLog2PaddedHeight, log2Height)
}

// AddFieldElement adds a single field element to the proof
func (p *Proof) AddFieldElement(elem field.Element) {
	p.AddItem(ProofItemFieldElement, elem)
}

// AddFieldElements adds multiple field elements to the proof
func (p *Proof) AddFieldElements(elems []field.Element) {
	p.AddItem(ProofItemFieldElements, elems)
}

// AddOODPoint adds the out-of-domain evaluation point
func (p *Proof) AddOODPoint(point field.Element) {
	p.AddFieldElement(point)
}

// AddOODEvaluations adds the out-of-domain evaluations
func (p *Proof) AddOODEvaluations(evals []field.Element) {
	p.AddFieldElements(evals)
}

// AddFRILayer adds a FRI layer (for compatibility with FRI protocol)
func (p *Proof) AddFRILayer(layer FRILayer) {
	// Add Merkle root
	p.AddMerkleRoot(layer.MerkleRoot)
	// Add challenge if present
	if !layer.Challenge.IsZero() {
		p.AddFieldElement(layer.Challenge)
	}
}

// AddFinalPolynomialCoefficients adds the final polynomial coefficients
func (p *Proof) AddFinalPolynomialCoefficients(coeffs []field.Element) {
	p.AddFieldElements(coeffs)
}

// AddSoundnessError adds the soundness error metric
func (p *Proof) AddSoundnessError(err field.Element) {
	p.AddFieldElement(err)
}

// GetPaddedHeight extracts the padded height from the proof
func (p *Proof) GetPaddedHeight() (int, error) {
	for _, item := range p.Items {
		if item.Type == ProofItemLog2PaddedHeight {
			log2Height, ok := item.Data.(int)
			if !ok {
				return 0, fmt.Errorf("invalid log2 height data type")
			}
			return 1 << log2Height, nil
		}
	}
	return 0, fmt.Errorf("no padded height found in proof")
}

// GetMerkleRoots extracts all Merkle roots from the proof
func (p *Proof) GetMerkleRoots() [][]byte {
	roots := make([][]byte, 0)
	for _, item := range p.Items {
		if item.Type == ProofItemMerkleRoot {
			if root, ok := item.Data.([]byte); ok {
				roots = append(roots, root)
			}
		}
	}
	return roots
}

// Validate checks if the proof is well-formed
func (p *Proof) Validate() error {
	if len(p.Items) == 0 {
		return fmt.Errorf("proof cannot be empty")
	}

	// Check that we have at least one Merkle root
	hasRoot := false
	hasHeight := false

	for _, item := range p.Items {
		if item.Type == ProofItemMerkleRoot {
			hasRoot = true
		}
		if item.Type == ProofItemLog2PaddedHeight {
			hasHeight = true
		}
	}

	if !hasRoot {
		return fmt.Errorf("proof must contain at least one Merkle root")
	}

	if !hasHeight {
		return fmt.Errorf("proof must contain padded height")
	}

	return nil
}

// Size returns the approximate size of the proof in bytes
func (p *Proof) Size() int {
	size := 0
	for _, item := range p.Items {
		switch item.Type {
		case ProofItemMerkleRoot:
			if root, ok := item.Data.([]byte); ok {
				size += len(root)
			}
		case ProofItemLog2PaddedHeight:
			size += 4 // int size
		case ProofItemFieldElement:
			size += 8 // field.Element is uint64 (8 bytes)
		case ProofItemFieldElements:
			if elems, ok := item.Data.([]field.Element); ok {
				size += len(elems) * 8
			}
		case ProofItemMerkleProof:
			if proof, ok := item.Data.([][]byte); ok {
				for _, node := range proof {
					size += len(node)
				}
			}
		}
	}
	return size
}

// String returns a human-readable representation of the proof
func (p *Proof) String() string {
	return fmt.Sprintf("Proof{Items: %d, Size: %d bytes}", len(p.Items), p.Size())
}
