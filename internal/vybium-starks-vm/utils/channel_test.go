package utils

import (
	"math/big"
	"testing"

	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
)

// TestNewChannel tests creating a new channel
func TestNewChannel(t *testing.T) {
	tests := []struct {
		name         string
		hashFunc     string
		expectedHash string
	}{
		{"default (empty string)", "", "sha3"},
		{"sha256", "sha256", "sha256"},
		{"sha3", "sha3", "sha3"},
		{"poseidon", "poseidon", "poseidon"},
		{"rescue", "rescue", "rescue"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := NewChannel(tt.hashFunc)
			if ch == nil {
				t.Fatal("NewChannel returned nil")
			}
			if ch.hashFunc != tt.expectedHash {
				t.Errorf("Expected hash function %s, got %s", tt.expectedHash, ch.hashFunc)
			}
			if len(ch.state) == 0 {
				t.Error("Channel state not initialized")
			}
		})
	}
}

// TestChannelSend tests sending data to the channel
func TestChannelSend(t *testing.T) {
	ch := NewChannel("sha256")
	initialState := ch.State()

	// Send some data
	data := []byte("test data")
	ch.Send(data)

	// State should have changed
	newState := ch.State()
	if string(initialState) == string(newState) {
		t.Error("Channel state should change after Send")
	}

	// Proof should contain the send operation
	proof := ch.Proof()
	if len(proof) == 0 {
		t.Error("Proof should contain send operation")
	}
}

// TestChannelReceiveRandomInt tests generating random integers
func TestChannelReceiveRandomInt(t *testing.T) {
	ch := NewChannel("sha256")

	// Test valid range
	min := big.NewInt(10)
	max := big.NewInt(100)
	result := ch.ReceiveRandomInt(min, max)

	if result == nil {
		t.Fatal("ReceiveRandomInt returned nil for valid range")
	}

	if result.Cmp(min) < 0 || result.Cmp(max) > 0 {
		t.Errorf("Result %v out of range [%v, %v]", result, min, max)
	}

	// Test invalid range (min > max)
	result2 := ch.ReceiveRandomInt(max, min)
	if result2 != nil {
		t.Error("ReceiveRandomInt should return nil for invalid range")
	}

	// Test equal min and max
	result3 := ch.ReceiveRandomInt(min, min)
	if result3 == nil {
		t.Fatal("ReceiveRandomInt returned nil for min==max")
	}
	if result3.Cmp(min) != 0 {
		t.Errorf("Expected %v for min==max, got %v", min, result3)
	}
}

// TestChannelReceiveRandomFieldElement tests generating random field elements
func TestChannelReceiveRandomFieldElement(t *testing.T) {
	ch := NewChannel("sha3")

	oldField, err := core.NewField(big.NewInt(101))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	elem := ch.ReceiveRandomFieldElement(oldField)
	if elem == nil {
		t.Fatal("ReceiveRandomFieldElement returned nil")
	}

	// Element should be within field bounds
	if elem.Big().Cmp(big.NewInt(0)) < 0 || elem.Big().Cmp(big.NewInt(101)) >= 0 {
		t.Errorf("Field element %v out of bounds", elem.Big())
	}
}

// TestChannelReceiveRandomBFieldElement tests generating random BFieldElements
func TestChannelReceiveRandomBFieldElement(t *testing.T) {
	ch := NewChannel("sha256")

	elem := ch.ReceiveRandomBFieldElement()

	// Element should be within Goldilocks field bounds
	if elem.Value() >= field.P {
		t.Errorf("BFieldElement value %d >= field modulus %d", elem.Value(), field.P)
	}
}

// TestChannelState tests retrieving channel state
func TestChannelState(t *testing.T) {
	ch := NewChannel("sha256")

	state1 := ch.State()
	state2 := ch.State()

	// Should return a copy, not the same slice
	if &state1[0] == &state2[0] {
		t.Error("State() should return a copy, not the internal state")
	}

	// Modifying returned state shouldn't affect channel
	state1[0] = 0xFF
	state3 := ch.State()
	if state1[0] == state3[0] {
		t.Error("Modifying returned state affected channel state")
	}
}

// TestChannelProof tests retrieving channel proof
func TestChannelProof(t *testing.T) {
	ch := NewChannel("sha256")

	// Send some data to create proof entries
	ch.Send([]byte("test1"))
	ch.Send([]byte("test2"))

	proof1 := ch.Proof()
	proof2 := ch.Proof()

	// Should return a copy
	if len(proof1) != len(proof2) {
		t.Error("Proof() should return consistent results")
	}

	// Modifying returned proof shouldn't affect channel
	proof1[0] = "modified"
	proof3 := ch.Proof()
	if proof1[0] == proof3[0] {
		t.Error("Modifying returned proof affected channel proof")
	}
}

// TestChannelString tests string representation
func TestChannelString(t *testing.T) {
	ch := NewChannel("sha256")

	// Initially empty
	str1 := ch.String()
	if str1 != "" {
		t.Error("Empty channel should have empty string")
	}

	// Add some operations
	ch.Send([]byte("data"))
	str2 := ch.String()
	if str2 == "" {
		t.Error("Channel with operations should have non-empty string")
	}
	if !containsString(str2, "send:") {
		t.Error("String should contain 'send:' prefix")
	}
}

// TestChannelHashFunctions tests different hash functions
func TestChannelHashFunctions(t *testing.T) {
	hashFuncs := []string{"sha256", "sha3", "poseidon", "rescue", "unknown"}

	for _, hashFunc := range hashFuncs {
		t.Run(hashFunc, func(t *testing.T) {
			ch := NewChannel(hashFunc)

			// Should not panic
			ch.Send([]byte("test data"))

			// Should produce some output
			state := ch.State()
			if len(state) == 0 {
				t.Error("Hash function should produce non-empty state")
			}
		})
	}
}

// TestChannelDeterminism tests that channels are deterministic
func TestChannelDeterminism(t *testing.T) {
	// Create two channels with same hash function
	ch1 := NewChannel("sha256")
	ch2 := NewChannel("sha256")

	// Send same data to both
	data := []byte("test data")
	ch1.Send(data)
	ch2.Send(data)

	// States should be identical
	state1 := ch1.State()
	state2 := ch2.State()

	if string(state1) != string(state2) {
		t.Error("Channels with same inputs should have same state")
	}

	// Random integers with same state should be identical
	result1 := ch1.ReceiveRandomInt(big.NewInt(0), big.NewInt(100))
	result2 := ch2.ReceiveRandomInt(big.NewInt(0), big.NewInt(100))

	if result1.Cmp(result2) != 0 {
		t.Errorf("Deterministic channels produced different random values: %v vs %v", result1, result2)
	}
}

// TestChannelStateProgression tests that state progresses correctly
func TestChannelStateProgression(t *testing.T) {
	ch := NewChannel("sha256")

	states := make([]string, 5)
	states[0] = string(ch.State())

	// Each operation should change the state
	for i := 1; i < 5; i++ {
		if i%2 == 0 {
			ch.Send([]byte{byte(i)})
		} else {
			ch.ReceiveRandomInt(big.NewInt(0), big.NewInt(100))
		}
		states[i] = string(ch.State())
	}

	// All states should be different
	for i := 0; i < 5; i++ {
		for j := i + 1; j < 5; j++ {
			if states[i] == states[j] {
				t.Errorf("States at steps %d and %d are identical", i, j)
			}
		}
	}
}

// TestChannelProofReplay tests that proof transcript is complete
func TestChannelProofReplay(t *testing.T) {
	ch := NewChannel("sha256")

	// Perform various operations
	ch.Send([]byte("operation1"))
	ch.ReceiveRandomInt(big.NewInt(0), big.NewInt(100))
	ch.Send([]byte("operation2"))
	ch.ReceiveRandomBFieldElement()

	proof := ch.Proof()

	// Should have 4 entries
	if len(proof) != 4 {
		t.Errorf("Expected 4 proof entries, got %d", len(proof))
	}

	// Check entries contain expected prefixes
	if !containsString(proof[0], "send:") {
		t.Error("First entry should be a send")
	}
	if !containsString(proof[1], "receiveRandInt:") {
		t.Error("Second entry should be receiveRandInt")
	}
}

// TestChannelLargeRange tests random int generation with large ranges
func TestChannelLargeRange(t *testing.T) {
	ch := NewChannel("sha256")

	// Test with very large range
	min := big.NewInt(0)
	max := new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil)

	result := ch.ReceiveRandomInt(min, max)
	if result == nil {
		t.Fatal("ReceiveRandomInt failed for large range")
	}

	if result.Cmp(min) < 0 || result.Cmp(max) > 0 {
		t.Error("Result out of bounds for large range")
	}
}

// TestChannelZeroRange tests random int with zero at boundaries
func TestChannelZeroRange(t *testing.T) {
	ch := NewChannel("sha3")

	// Test range [0, 0]
	result := ch.ReceiveRandomInt(big.NewInt(0), big.NewInt(0))
	if result == nil {
		t.Fatal("ReceiveRandomInt failed for [0,0] range")
	}
	if result.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("Expected 0 for [0,0] range, got %v", result)
	}
}

// Helper function
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
		findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// BenchmarkChannelSend benchmarks sending data
func BenchmarkChannelSend(b *testing.B) {
	ch := NewChannel("sha256")
	data := []byte("benchmark data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ch.Send(data)
	}
}

// BenchmarkChannelReceiveRandomInt benchmarks random int generation
func BenchmarkChannelReceiveRandomInt(b *testing.B) {
	ch := NewChannel("sha256")
	min := big.NewInt(0)
	max := big.NewInt(1000000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ch.ReceiveRandomInt(min, max)
	}
}

// BenchmarkChannelReceiveRandomBFieldElement benchmarks BFieldElement generation
func BenchmarkChannelReceiveRandomBFieldElement(b *testing.B) {
	ch := NewChannel("sha256")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ch.ReceiveRandomBFieldElement()
	}
}

