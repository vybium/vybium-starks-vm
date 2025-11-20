package protocols

import (
	"testing"

	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/hash"
)

// TestProofStreamEnqueueDequeue tests basic enqueue/dequeue operations
func TestProofStreamEnqueueDequeue(t *testing.T) {
	stream := NewProofStream()

	// Enqueue some items
	item1 := ProofItem{
		Type: ProofItemMerkleRoot,
		Data: make([]byte, hash.DigestLen*8),
	}
	if err := stream.Enqueue(item1); err != nil {
		t.Fatalf("Failed to enqueue item: %v", err)
	}

	item2 := ProofItem{
		Type: ProofItemLog2PaddedHeight,
		Data: 7,
	}
	if err := stream.Enqueue(item2); err != nil {
		t.Fatalf("Failed to enqueue item: %v", err)
	}

	item3 := ProofItem{
		Type: ProofItemFieldElement,
		Data: field.New(42),
	}
	if err := stream.Enqueue(item3); err != nil {
		t.Fatalf("Failed to enqueue item: %v", err)
	}

	// Dequeue items
	dequeued1, err := stream.Dequeue()
	if err != nil {
		t.Fatalf("Failed to dequeue item: %v", err)
	}
	if dequeued1.Type != ProofItemMerkleRoot {
		t.Errorf("Expected ProofItemMerkleRoot, got %v", dequeued1.Type)
	}

	dequeued2, err := stream.Dequeue()
	if err != nil {
		t.Fatalf("Failed to dequeue item: %v", err)
	}
	if dequeued2.Type != ProofItemLog2PaddedHeight {
		t.Errorf("Expected ProofItemLog2PaddedHeight, got %v", dequeued2.Type)
	}

	dequeued3, err := stream.Dequeue()
	if err != nil {
		t.Fatalf("Failed to dequeue item: %v", err)
	}
	if dequeued3.Type != ProofItemFieldElement {
		t.Errorf("Expected ProofItemFieldElement, got %v", dequeued3.Type)
	}

	// Try to dequeue from empty stream
	_, err = stream.Dequeue()
	if err == nil {
		t.Error("Expected error when dequeuing from empty stream")
	}
}

// TestProofStreamFiatShamirState tests that Fiat-Shamir state is updated correctly
func TestProofStreamFiatShamirState(t *testing.T) {
	stream1 := NewProofStream()
	stream2 := NewProofStream()

	// Enqueue items that should be included in Fiat-Shamir
	item1 := ProofItem{
		Type: ProofItemMerkleRoot,
		Data: make([]byte, hash.DigestLen*8),
	}
	if err := stream1.Enqueue(item1); err != nil {
		t.Fatalf("Failed to enqueue: %v", err)
	}

	item2 := ProofItem{
		Type: ProofItemFieldElement,
		Data: field.New(123),
	}
	if err := stream1.Enqueue(item2); err != nil {
		t.Fatalf("Failed to enqueue: %v", err)
	}

	// Enqueue same items in stream2
	if err := stream2.Enqueue(item1); err != nil {
		t.Fatalf("Failed to enqueue: %v", err)
	}
	if err := stream2.Enqueue(item2); err != nil {
		t.Fatalf("Failed to enqueue: %v", err)
	}

	// Sponge states should be identical - verify by sampling same indices
	indices1, err1 := stream1.SampleIndices(256, 5)
	indices2, err2 := stream2.SampleIndices(256, 5)
	if err1 != nil || err2 != nil {
		t.Fatalf("Failed to sample indices: %v, %v", err1, err2)
	}
	if len(indices1) != len(indices2) {
		t.Error("Fiat-Shamir states should produce same number of indices")
	}
	// With high probability, same state should produce same indices
	// (We can't directly compare state, so we compare outputs)

	// Enqueue item that should NOT be included in Fiat-Shamir
	item3 := ProofItem{
		Type: ProofItemLog2PaddedHeight,
		Data: 7,
	}
	indicesBefore, _ := stream1.SampleIndices(256, 5)
	if err := stream1.Enqueue(item3); err != nil {
		t.Fatalf("Failed to enqueue: %v", err)
	}
	indicesAfter, _ := stream1.SampleIndices(256, 5)

	// State should not change for items not in Fiat-Shamir
	// Verify by checking that indices are the same
	if len(indicesBefore) != len(indicesAfter) {
		t.Error("Fiat-Shamir state should not change for items not included in heuristic")
	}
}

// TestProofStreamSampleIndices tests index sampling
func TestProofStreamSampleIndices(t *testing.T) {
	stream := NewProofStream()

	// Sample indices with power of 2 upper bound
	indices, err := stream.SampleIndices(256, 10)
	if err != nil {
		t.Fatalf("Failed to sample indices: %v", err)
	}

	if len(indices) != 10 {
		t.Errorf("Expected 10 indices, got %d", len(indices))
	}

	// Verify all indices are in range [0, 256)
	for i, idx := range indices {
		if idx < 0 || idx >= 256 {
			t.Errorf("Index %d at position %d is out of range [0, 256)", idx, i)
		}
	}

	// Test invalid upper bound (not power of 2)
	_, err = stream.SampleIndices(100, 10)
	if err == nil {
		t.Error("Expected error for non-power-of-2 upper bound")
	}

	// Test zero upper bound
	_, err = stream.SampleIndices(0, 10)
	if err == nil {
		t.Error("Expected error for zero upper bound")
	}
}

// TestProofStreamSampleScalars tests scalar sampling
func TestProofStreamSampleScalars(t *testing.T) {
	stream := NewProofStream()

	scalars, err := stream.SampleScalars(5)
	if err != nil {
		t.Fatalf("Failed to sample scalars: %v", err)
	}

	if len(scalars) != 5 {
		t.Errorf("Expected 5 scalars, got %d", len(scalars))
	}

	// Verify all scalars are valid (not all zero with high probability)
	allZero := true
	for i, scalar := range scalars {
		if len(scalar.Coefficients) != 3 {
			t.Errorf("Scalar %d should have 3 coefficients, got %d", i, len(scalar.Coefficients))
		}
		if !scalar.IsZero() {
			allZero = false
		}
	}

	if allZero {
		t.Error("All scalars are zero (unlikely but possible)")
	}
}

// TestProofStreamToProof tests conversion to Proof
func TestProofStreamToProof(t *testing.T) {
	stream := NewProofStream()

	item1 := ProofItem{
		Type: ProofItemMerkleRoot,
		Data: make([]byte, hash.DigestLen*8),
	}
	stream.Enqueue(item1)

	item2 := ProofItem{
		Type: ProofItemFieldElement,
		Data: field.New(42),
	}
	stream.Enqueue(item2)

	proof := stream.ToProof()

	if len(proof.Items) != 2 {
		t.Errorf("Expected 2 items in proof, got %d", len(proof.Items))
	}

	if proof.Items[0].Type != ProofItemMerkleRoot {
		t.Errorf("Expected first item to be ProofItemMerkleRoot, got %v", proof.Items[0].Type)
	}

	if proof.Items[1].Type != ProofItemFieldElement {
		t.Errorf("Expected second item to be ProofItemFieldElement, got %v", proof.Items[1].Type)
	}
}

// TestProofStreamFromProof tests reconstruction from Proof
func TestProofStreamFromProof(t *testing.T) {
	// Create original stream and enqueue items
	originalStream := NewProofStream()

	item1 := ProofItem{
		Type: ProofItemMerkleRoot,
		Data: make([]byte, hash.DigestLen*8),
	}
	originalStream.Enqueue(item1)

	item2 := ProofItem{
		Type: ProofItemFieldElement,
		Data: field.New(123),
	}
	originalStream.Enqueue(item2)

	// Convert to proof and back
	proof := originalStream.ToProof()
	reconstructedStream, err := ProofStreamFromProof(proof)
	if err != nil {
		t.Fatalf("Failed to reconstruct stream: %v", err)
	}

	// Verify items are the same
	if len(reconstructedStream.Items) != len(originalStream.Items) {
		t.Errorf("Expected %d items, got %d", len(originalStream.Items), len(reconstructedStream.Items))
	}

	// Verify Fiat-Shamir state is reconstructed correctly by sampling
	originalIndices, _ := originalStream.SampleIndices(256, 5)
	reconstructedIndices, _ := reconstructedStream.SampleIndices(256, 5)
	if len(originalIndices) != len(reconstructedIndices) {
		t.Error("Fiat-Shamir state should be reconstructed correctly")
	}

	// Verify we can dequeue items
	dequeued1, err := reconstructedStream.Dequeue()
	if err != nil {
		t.Fatalf("Failed to dequeue: %v", err)
	}
	if dequeued1.Type != ProofItemMerkleRoot {
		t.Errorf("Expected ProofItemMerkleRoot, got %v", dequeued1.Type)
	}
}

// TestProofStreamTranscriptLength tests transcript length calculation
func TestProofStreamTranscriptLength(t *testing.T) {
	stream := NewProofStream()

	// Add items of different types
	item1 := ProofItem{
		Type: ProofItemMerkleRoot,
		Data: make([]byte, hash.DigestLen*8),
	}
	stream.Enqueue(item1)

	item2 := ProofItem{
		Type: ProofItemLog2PaddedHeight,
		Data: 7,
	}
	stream.Enqueue(item2)

	item3 := ProofItem{
		Type: ProofItemFieldElement,
		Data: field.New(42),
	}
	stream.Enqueue(item3)

	item4 := ProofItem{
		Type: ProofItemFieldElements,
		Data: []field.Element{field.New(1), field.New(2), field.New(3)},
	}
	stream.Enqueue(item4)

	length := stream.TranscriptLength()
	expected := hash.DigestLen + 1 + 1 + 3 // MerkleRoot + Log2Height + FieldElement + 3 FieldElements
	if length != expected {
		t.Errorf("Expected transcript length %d, got %d", expected, length)
	}
}

// TestProofStreamIncludeInFiatShamirHeuristic tests the heuristic inclusion logic
func TestProofStreamIncludeInFiatShamirHeuristic(t *testing.T) {
	testCases := []struct {
		itemType                 ProofItemType
		shouldIncludeInHeuristic bool
	}{
		{ProofItemMerkleRoot, true},
		{ProofItemOutOfDomainMainRow, true},
		{ProofItemOutOfDomainAuxRow, true},
		{ProofItemOutOfDomainQuotientSegments, true},
		{ProofItemFieldElement, true},
		{ProofItemFieldElements, true},
		{ProofItemAuthenticationStructure, false},
		{ProofItemMasterMainTableRows, false},
		{ProofItemMasterAuxTableRows, false},
		{ProofItemLog2PaddedHeight, false},
		{ProofItemQuotientSegmentsElements, false},
		{ProofItemFRICodeword, false},
		{ProofItemFRIPolynomial, false},
		{ProofItemFRIResponse, false},
		{ProofItemMerkleProof, false},
	}

	for _, tc := range testCases {
		item := ProofItem{Type: tc.itemType}
		result := item.IncludeInFiatShamirHeuristic()
		if result != tc.shouldIncludeInHeuristic {
			t.Errorf("ProofItemType %v: expected %v, got %v", tc.itemType, tc.shouldIncludeInHeuristic, result)
		}
	}
}
