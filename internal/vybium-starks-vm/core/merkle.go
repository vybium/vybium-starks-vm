package core

import (
	"crypto/sha256"
	"fmt"
	"math/big"
)

// MerkleTree represents a Merkle tree for committing to data
type MerkleTree struct {
	root   []byte
	leaves [][]byte
	levels [][][]byte
}

// NewMerkleTree creates a new Merkle tree from the given data
func NewMerkleTree(data [][]byte) (*MerkleTree, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("cannot create Merkle tree with empty data")
	}

	// Hash all leaves
	leaves := make([][]byte, len(data))
	for i, item := range data {
		leaves[i] = computeHash(item)
	}

	// Build tree levels
	levels := [][][]byte{leaves}
	currentLevel := leaves

	for len(currentLevel) > 1 {
		nextLevel := make([][]byte, 0, (len(currentLevel)+1)/2)

		for i := 0; i < len(currentLevel); i += 2 {
			var hash []byte
			if i+1 < len(currentLevel) {
				// Hash two nodes together
				combined := append(currentLevel[i], currentLevel[i+1]...)
				hash = computeHash(combined)
			} else {
				// Odd number of nodes, hash the last node with itself
				combined := append(currentLevel[i], currentLevel[i]...)
				hash = computeHash(combined)
			}
			nextLevel = append(nextLevel, hash)
		}

		levels = append(levels, nextLevel)
		currentLevel = nextLevel
	}

	return &MerkleTree{
		root:   currentLevel[0],
		leaves: leaves,
		levels: levels,
	}, nil
}

// Root returns the Merkle root
func (mt *MerkleTree) Root() []byte {
	return mt.root
}

// Proof generates a Merkle proof for the given index
func (mt *MerkleTree) Proof(index int) ([]ProofNode, error) {
	if index < 0 || index >= len(mt.leaves) {
		return nil, fmt.Errorf("index %d out of range [0, %d)", index, len(mt.leaves))
	}

	var proof []ProofNode
	currentIndex := index

	for level := 0; level < len(mt.levels)-1; level++ {
		currentLevel := mt.levels[level]

		// Find sibling
		var siblingIndex int
		var isRight bool

		if currentIndex%2 == 0 {
			// Current node is left child
			siblingIndex = currentIndex + 1
			isRight = true
		} else {
			// Current node is right child
			siblingIndex = currentIndex - 1
			isRight = false
		}

		// Add sibling to proof if it exists
		if siblingIndex < len(currentLevel) {
			proof = append(proof, ProofNode{
				Hash:    currentLevel[siblingIndex],
				IsRight: isRight,
			})
		}

		// Move to parent level
		currentIndex /= 2
	}

	return proof, nil
}

// VerifyProof verifies a Merkle proof
func VerifyProof(root []byte, leaf []byte, proof []ProofNode, index int) bool {
	hash := computeHash(leaf)
	currentIndex := index

	for _, node := range proof {
		var combined []byte
		if node.IsRight {
			// Sibling is on the right, current hash goes on the left
			combined = append(hash, node.Hash...)
		} else {
			// Sibling is on the left, current hash goes on the right
			combined = append(node.Hash, hash...)
		}
		hash = computeHash(combined)
		currentIndex /= 2
	}

	return string(hash) == string(root)
}

// ProofNode represents a node in a Merkle proof
type ProofNode struct {
	Hash    []byte
	IsRight bool // true if this node is the right child, false if left
}

// computeHash computes hash of the input using field-friendly hash function
func computeHash(data []byte) []byte {
	// Use Poseidon hash for better performance in zero-knowledge proofs
	field, _ := NewField(big.NewInt(3221225473)) // Default field
	hashBytes, err := HashBytesToBytes(field, "poseidon", data)
	if err != nil {
		// Fallback to SHA256 if field-friendly hash fails
		h := sha256.Sum256(data)
		return h[:]
	}
	return hashBytes
}

// MerkleRoot computes the Merkle root of the given data (convenience function)
func MerkleRoot(data [][]byte) ([]byte, error) {
	tree, err := NewMerkleTree(data)
	if err != nil {
		return nil, err
	}
	return tree.Root(), nil
}
