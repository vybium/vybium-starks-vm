package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/sha3"

	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
)

// Channel represents a Fiat-Shamir transcript channel
type Channel struct {
	state    []byte
	proof    []string
	hashFunc string
}

// NewChannel creates a new Fiat-Shamir channel
func NewChannel(hashFunc string) *Channel {
	if hashFunc == "" {
		hashFunc = "sha3"
	}
	return &Channel{
		state:    []byte{0},
		proof:    make([]string, 0, 64),
		hashFunc: hashFunc,
	}
}

// Send appends data to the channel state
func (c *Channel) Send(data []byte) {
	c.proof = append(c.proof, fmt.Sprintf("send:%s", hex.EncodeToString(data)))
	c.state = c.hash(append(c.state, data...))
}

// ReceiveRandomInt generates a random integer in the range [min, max]
// Returns nil if min > max (invalid range)
func (c *Channel) ReceiveRandomInt(min, max *big.Int) *big.Int {
	if min.Cmp(max) > 0 {
		// Return nil for invalid range (caller should handle)
		return nil
	}

	// Convert state to integer
	stateAsInt := new(big.Int).SetBytes(c.state)

	// Compute range size
	rangeSize := new(big.Int).Sub(max, min)
	rangeSize.Add(rangeSize, big.NewInt(1))

	// Generate random number in range
	random := new(big.Int).Mod(stateAsInt, rangeSize)
	random.Add(random, min)

	// Update proof and state
	c.proof = append(c.proof, fmt.Sprintf("receiveRandInt:%s", random.String()))
	c.state = c.hash(c.state)

	return random
}

// ReceiveRandomFieldElement generates a random field element
// NOTE: This still returns *core.FieldElement for compatibility with protocols
// VM code should use ReceiveRandomBFieldElement() instead
func (c *Channel) ReceiveRandomFieldElement(oldField *core.Field) *core.FieldElement {
	max := new(big.Int).Sub(oldField.Modulus(), big.NewInt(1))
	random := c.ReceiveRandomInt(big.NewInt(0), max)
	return oldField.NewElement(random)
}

// ReceiveRandomBFieldElement generates a random BFieldElement for VM use
func (c *Channel) ReceiveRandomBFieldElement() field.Element {
	// For BFieldElement, generate a random value in the Goldilocks field
	max := big.NewInt(0).SetUint64(field.P - 1)
	random := c.ReceiveRandomInt(big.NewInt(0), max)
	// Convert to BFieldElement
	return field.New(random.Uint64())
}

// State returns the current channel state
func (c *Channel) State() []byte {
	return append([]byte(nil), c.state...)
}

// Proof returns the proof transcript
func (c *Channel) Proof() []string {
	return append([]string(nil), c.proof...)
}

// hash computes the hash of the input using the configured hash function
func (c *Channel) hash(data []byte) []byte {
	switch c.hashFunc {
	case "sha256":
		h := sha256.Sum256(data)
		return h[:]
	case "sha3":
		h := sha3.Sum256(data)
		return h[:]
	case "poseidon", "rescue":
		// For field-friendly hash functions, we need a field
		// Use a default field and convert back to bytes
		field, _ := core.NewField(big.NewInt(3221225473)) // Default field
		hashBytes, err := core.HashBytesToBytes(field, c.hashFunc, data)
		if err != nil {
			// Fallback to SHA3 if field-friendly hash fails
			h := sha3.Sum256(data)
			return h[:]
		}
		return hashBytes
	default:
		// Fallback to SHA3 for unsupported hash functions (graceful degradation)
		h := sha3.Sum256(data)
		return h[:]
	}
}

// String returns a string representation of the channel proof
func (c *Channel) String() string {
	return strings.Join(c.proof, " ")
}
