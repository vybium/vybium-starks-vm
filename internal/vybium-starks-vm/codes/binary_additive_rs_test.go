package codes

import (
	"math/big"
	"testing"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
)

// TestNewBinaryAdditiveRSCode tests creating a binary additive RS code
func TestNewBinaryAdditiveRSCode(t *testing.T) {
	field, err := core.NewField(big.NewInt(17))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	// Create a coset of size 4 (2^2)
	coset := []*core.FieldElement{
		field.NewElementFromInt64(1),
		field.NewElementFromInt64(2),
		field.NewElementFromInt64(4),
		field.NewElementFromInt64(8),
	}

	// Basis should have 2 elements (log2(4))
	basis := []*core.FieldElement{
		field.NewElementFromInt64(2),
		field.NewElementFromInt64(4),
	}

	rate := field.NewElementFromInt64(1)
	rate, _ = rate.Div(field.NewElementFromInt64(2))

	rs, err := NewBinaryAdditiveRSCode(field, rate, coset, basis)
	if err != nil {
		t.Fatalf("NewBinaryAdditiveRSCode() failed: %v", err)
	}

	if rs == nil {
		t.Fatal("NewBinaryAdditiveRSCode() returned nil")
	}

	if len(rs.GetCoset()) != 4 {
		t.Errorf("Expected coset size 4, got %d", len(rs.GetCoset()))
	}

	if len(rs.GetBasis()) != 2 {
		t.Errorf("Expected basis size 2, got %d", len(rs.GetBasis()))
	}
}

// TestBinaryAdditiveRSCodeEmptyCoset tests error handling for empty coset
func TestBinaryAdditiveRSCodeEmptyCoset(t *testing.T) {
	field, err := core.NewField(big.NewInt(17))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	coset := []*core.FieldElement{}
	basis := []*core.FieldElement{field.NewElementFromInt64(2)}
	rate := field.NewElementFromInt64(1)

	rs, err := NewBinaryAdditiveRSCode(field, rate, coset, basis)
	if err == nil {
		t.Error("NewBinaryAdditiveRSCode() should fail with empty coset")
	}
	if rs != nil {
		t.Error("NewBinaryAdditiveRSCode() should return nil on error")
	}
}

// TestBinaryAdditiveRSCodeEmptyBasis tests error handling for empty basis
func TestBinaryAdditiveRSCodeEmptyBasis(t *testing.T) {
	field, err := core.NewField(big.NewInt(17))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	coset := []*core.FieldElement{
		field.NewElementFromInt64(1),
		field.NewElementFromInt64(2),
	}
	basis := []*core.FieldElement{}
	rate := field.NewElementFromInt64(1)

	rs, err := NewBinaryAdditiveRSCode(field, rate, coset, basis)
	if err == nil {
		t.Error("NewBinaryAdditiveRSCode() should fail with empty basis")
	}
	if rs != nil {
		t.Error("NewBinaryAdditiveRSCode() should return nil on error")
	}
}

// TestBinaryAdditiveRSCodeNonPowerOfTwoCoset tests error for non-power-of-2 coset
func TestBinaryAdditiveRSCodeNonPowerOfTwoCoset(t *testing.T) {
	field, err := core.NewField(big.NewInt(17))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	// Coset of size 3 (not a power of 2)
	coset := []*core.FieldElement{
		field.NewElementFromInt64(1),
		field.NewElementFromInt64(2),
		field.NewElementFromInt64(3),
	}
	basis := []*core.FieldElement{field.NewElementFromInt64(2)}
	rate := field.NewElementFromInt64(1)

	rs, err := NewBinaryAdditiveRSCode(field, rate, coset, basis)
	if err == nil {
		t.Error("NewBinaryAdditiveRSCode() should fail with non-power-of-2 coset size")
	}
	if rs != nil {
		t.Error("NewBinaryAdditiveRSCode() should return nil on error")
	}
}

// TestBinaryAdditiveRSCodeBasisSizeMismatch tests error for incorrect basis size
func TestBinaryAdditiveRSCodeBasisSizeMismatch(t *testing.T) {
	field, err := core.NewField(big.NewInt(17))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	// Coset of size 4 requires basis of size 2
	coset := []*core.FieldElement{
		field.NewElementFromInt64(1),
		field.NewElementFromInt64(2),
		field.NewElementFromInt64(4),
		field.NewElementFromInt64(8),
	}
	// But provide basis of size 1
	basis := []*core.FieldElement{field.NewElementFromInt64(2)}
	rate := field.NewElementFromInt64(1)

	rs, err := NewBinaryAdditiveRSCode(field, rate, coset, basis)
	if err == nil {
		t.Error("NewBinaryAdditiveRSCode() should fail with incorrect basis size")
	}
	if rs != nil {
		t.Error("NewBinaryAdditiveRSCode() should return nil on error")
	}
}

// TestCreateCyclicGroupCoset tests creating a cyclic group coset
func TestCreateCyclicGroupCoset(t *testing.T) {
	field, err := core.NewField(big.NewInt(17))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	omega := field.NewElementFromInt64(2)
	size := 4

	coset, basis, err := CreateCyclicGroupCoset(field, omega, size)
	if err != nil {
		t.Fatalf("CreateCyclicGroupCoset() failed: %v", err)
	}

	if len(coset) != size {
		t.Errorf("Expected coset size %d, got %d", size, len(coset))
	}

	// First element should be 1 (ω^0)
	if !coset[0].Equal(field.One()) {
		t.Error("First coset element should be 1")
	}

	// Second element should be ω
	if !coset[1].Equal(omega) {
		t.Error("Second coset element should be ω")
	}

	// Basis size should be log2(size)
	expectedBasisSize := 2 // log2(4)
	if len(basis) != expectedBasisSize {
		t.Errorf("Expected basis size %d, got %d", expectedBasisSize, len(basis))
	}

	// First basis element should be ω
	if !basis[0].Equal(omega) {
		t.Error("First basis element should be ω")
	}
}

// TestCreateCyclicGroupCosetNonPowerOfTwo tests error for non-power-of-2 size
func TestCreateCyclicGroupCosetNonPowerOfTwo(t *testing.T) {
	field, err := core.NewField(big.NewInt(17))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	omega := field.NewElementFromInt64(2)
	size := 3 // Not a power of 2

	coset, basis, err := CreateCyclicGroupCoset(field, omega, size)
	if err == nil {
		t.Error("CreateCyclicGroupCoset() should fail with non-power-of-2 size")
	}
	if coset != nil || basis != nil {
		t.Error("CreateCyclicGroupCoset() should return nil on error")
	}
}

// TestBinaryAdditiveRSCodeIsInCode tests checking if function is in code
func TestBinaryAdditiveRSCodeIsInCode(t *testing.T) {
	field, err := core.NewField(big.NewInt(17))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	omega := field.NewElementFromInt64(2)
	coset, basis, err := CreateCyclicGroupCoset(field, omega, 4)
	if err != nil {
		t.Fatalf("CreateCyclicGroupCoset() failed: %v", err)
	}

	rate := field.NewElementFromInt64(1)
	rate, _ = rate.Div(field.NewElementFromInt64(2))

	rs, err := NewBinaryAdditiveRSCode(field, rate, coset, basis)
	if err != nil {
		t.Fatalf("NewBinaryAdditiveRSCode() failed: %v", err)
	}

	// Linear function f(x) = x should be in the code (degree 1)
	function := []*core.FieldElement{
		field.NewElementFromInt64(1),
		field.NewElementFromInt64(2),
		field.NewElementFromInt64(4),
		field.NewElementFromInt64(8),
	}

	inCode, err := rs.IsInCode(function)
	if err != nil {
		t.Fatalf("IsInCode() failed: %v", err)
	}

	if !inCode {
		t.Error("Linear function should be in half-rate code")
	}
}

// TestBinaryAdditiveRSCodeComputeHammingDistance tests Hamming distance computation
func TestBinaryAdditiveRSCodeComputeHammingDistance(t *testing.T) {
	field, err := core.NewField(big.NewInt(17))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	omega := field.NewElementFromInt64(2)
	coset, basis, err := CreateCyclicGroupCoset(field, omega, 4)
	if err != nil {
		t.Fatalf("CreateCyclicGroupCoset() failed: %v", err)
	}

	rate := field.NewElementFromInt64(1)
	rs, err := NewBinaryAdditiveRSCode(field, rate, coset, basis)
	if err != nil {
		t.Fatalf("NewBinaryAdditiveRSCode() failed: %v", err)
	}

	// Two functions that differ in 2 out of 4 positions
	u := []*core.FieldElement{
		field.NewElementFromInt64(1),
		field.NewElementFromInt64(2),
		field.NewElementFromInt64(3),
		field.NewElementFromInt64(4),
	}

	v := []*core.FieldElement{
		field.NewElementFromInt64(1),
		field.NewElementFromInt64(2),
		field.NewElementFromInt64(99), // Different
		field.NewElementFromInt64(99), // Different
	}

	distance, err := rs.ComputeHammingDistance(u, v)
	if err != nil {
		t.Fatalf("ComputeHammingDistance() failed: %v", err)
	}

	// Distance should be 2/4 = 0.5 in field arithmetic
	expected := field.NewElementFromInt64(1)
	expected, _ = expected.Div(field.NewElementFromInt64(2))

	if !distance.Equal(expected) {
		t.Errorf("Expected distance 0.5, got %v", distance.Big())
	}
}

// TestBinaryAdditiveRSCodeGetMinimumDistance tests minimum distance calculation
func TestBinaryAdditiveRSCodeGetMinimumDistance(t *testing.T) {
	field, err := core.NewField(big.NewInt(17))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	omega := field.NewElementFromInt64(2)
	coset, basis, err := CreateCyclicGroupCoset(field, omega, 4)
	if err != nil {
		t.Fatalf("CreateCyclicGroupCoset() failed: %v", err)
	}

	// Rate: 0.5
	rate := field.NewElementFromInt64(1)
	rate, _ = rate.Div(field.NewElementFromInt64(2))

	rs, err := NewBinaryAdditiveRSCode(field, rate, coset, basis)
	if err != nil {
		t.Fatalf("NewBinaryAdditiveRSCode() failed: %v", err)
	}

	// Minimum distance should be 1 - rate = 1 - 0.5 = 0.5
	minDist := rs.GetMinimumDistance()

	expected := field.NewElementFromInt64(1)
	expected, _ = expected.Div(field.NewElementFromInt64(2))

	if !minDist.Equal(expected) {
		t.Errorf("Expected minimum distance 0.5, got %v", minDist.Big())
	}
}

// TestBinaryAdditiveRSCodeGetUniqueDecodingRadius tests unique decoding radius
func TestBinaryAdditiveRSCodeGetUniqueDecodingRadius(t *testing.T) {
	field, err := core.NewField(big.NewInt(17))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	omega := field.NewElementFromInt64(2)
	coset, basis, err := CreateCyclicGroupCoset(field, omega, 4)
	if err != nil {
		t.Fatalf("CreateCyclicGroupCoset() failed: %v", err)
	}

	rate := field.NewElementFromInt64(1)
	rate, _ = rate.Div(field.NewElementFromInt64(2))

	rs, err := NewBinaryAdditiveRSCode(field, rate, coset, basis)
	if err != nil {
		t.Fatalf("NewBinaryAdditiveRSCode() failed: %v", err)
	}

	// Unique decoding radius should be (1 - rate) / 2 = 0.5 / 2 = 0.25
	radius := rs.GetUniqueDecodingRadius()

	expected := field.NewElementFromInt64(1)
	expected, _ = expected.Div(field.NewElementFromInt64(4))

	if !radius.Equal(expected) {
		t.Errorf("Expected unique decoding radius 0.25, got %v", radius.Big())
	}
}

// TestBinaryAdditiveRSCodeEvaluateAtPoint tests point evaluation
func TestBinaryAdditiveRSCodeEvaluateAtPoint(t *testing.T) {
	field, err := core.NewField(big.NewInt(17))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	omega := field.NewElementFromInt64(2)
	coset, basis, err := CreateCyclicGroupCoset(field, omega, 2)
	if err != nil {
		t.Fatalf("CreateCyclicGroupCoset() failed: %v", err)
	}

	rate := field.NewElementFromInt64(1)
	rs, err := NewBinaryAdditiveRSCode(field, rate, coset, basis)
	if err != nil {
		t.Fatalf("NewBinaryAdditiveRSCode() failed: %v", err)
	}

	// Constant polynomial f(x) = 5
	function := []*core.FieldElement{
		field.NewElementFromInt64(5),
		field.NewElementFromInt64(5),
	}

	// Evaluate at x = 3
	result, err := rs.EvaluateAtPoint(function, field.NewElementFromInt64(3))
	if err != nil {
		t.Fatalf("EvaluateAtPoint() failed: %v", err)
	}

	// Constant polynomial should evaluate to 5 everywhere
	if !result.Equal(field.NewElementFromInt64(5)) {
		t.Errorf("f(3) = %v, expected 5", result.Big())
	}
}

// TestBinaryAdditiveRSCodeComputeDistanceToCode tests distance to code computation
func TestBinaryAdditiveRSCodeComputeDistanceToCode(t *testing.T) {
	field, err := core.NewField(big.NewInt(17))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	omega := field.NewElementFromInt64(2)
	coset, basis, err := CreateCyclicGroupCoset(field, omega, 4)
	if err != nil {
		t.Fatalf("CreateCyclicGroupCoset() failed: %v", err)
	}

	rate := field.NewElementFromInt64(1)
	rate, _ = rate.Div(field.NewElementFromInt64(2))

	rs, err := NewBinaryAdditiveRSCode(field, rate, coset, basis)
	if err != nil {
		t.Fatalf("NewBinaryAdditiveRSCode() failed: %v", err)
	}

	// Function that's in the code (degree 1 polynomial)
	function := []*core.FieldElement{
		field.NewElementFromInt64(1),
		field.NewElementFromInt64(2),
		field.NewElementFromInt64(4),
		field.NewElementFromInt64(8),
	}

	distance, err := rs.ComputeDistanceToCode(function)
	if err != nil {
		t.Fatalf("ComputeDistanceToCode() failed: %v", err)
	}

	// Distance should be 0 (already in code)
	if !distance.IsZero() {
		t.Errorf("Distance to code should be 0 for polynomial in code, got %v", distance.Big())
	}
}

// TestBinaryAdditiveRSCodeGetters tests getter methods
func TestBinaryAdditiveRSCodeGetters(t *testing.T) {
	field, err := core.NewField(big.NewInt(17))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	omega := field.NewElementFromInt64(2)
	coset, basis, err := CreateCyclicGroupCoset(field, omega, 4)
	if err != nil {
		t.Fatalf("CreateCyclicGroupCoset() failed: %v", err)
	}

	rate := field.NewElementFromInt64(1)
	rate, _ = rate.Div(field.NewElementFromInt64(2))

	rs, err := NewBinaryAdditiveRSCode(field, rate, coset, basis)
	if err != nil {
		t.Fatalf("NewBinaryAdditiveRSCode() failed: %v", err)
	}

	// Test GetCoset
	returnedCoset := rs.GetCoset()
	if len(returnedCoset) != len(coset) {
		t.Errorf("GetCoset() length mismatch: expected %d, got %d", len(coset), len(returnedCoset))
	}

	// Test GetBasis
	returnedBasis := rs.GetBasis()
	if len(returnedBasis) != len(basis) {
		t.Errorf("GetBasis() length mismatch: expected %d, got %d", len(basis), len(returnedBasis))
	}

	// Test GetRate
	returnedRate := rs.GetRate()
	if !returnedRate.Equal(rate) {
		t.Errorf("GetRate() mismatch: expected %v, got %v", rate.Big(), returnedRate.Big())
	}
}

// TestBinaryAdditiveRSCodeFunctionLengthMismatch tests error handling for wrong function length
func TestBinaryAdditiveRSCodeFunctionLengthMismatch(t *testing.T) {
	field, err := core.NewField(big.NewInt(17))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	omega := field.NewElementFromInt64(2)
	coset, basis, err := CreateCyclicGroupCoset(field, omega, 4)
	if err != nil {
		t.Fatalf("CreateCyclicGroupCoset() failed: %v", err)
	}

	rate := field.NewElementFromInt64(1)
	rs, err := NewBinaryAdditiveRSCode(field, rate, coset, basis)
	if err != nil {
		t.Fatalf("NewBinaryAdditiveRSCode() failed: %v", err)
	}

	// Function with wrong length
	wrongLengthFunction := []*core.FieldElement{
		field.NewElementFromInt64(1),
		field.NewElementFromInt64(2),
	}

	// All these should fail with length mismatch
	_, err = rs.IsInCode(wrongLengthFunction)
	if err == nil {
		t.Error("IsInCode() should fail with wrong function length")
	}

	_, err = rs.EvaluateAtPoint(wrongLengthFunction, field.NewElementFromInt64(3))
	if err == nil {
		t.Error("EvaluateAtPoint() should fail with wrong function length")
	}

	_, err = rs.ComputeDistanceToCode(wrongLengthFunction)
	if err == nil {
		t.Error("ComputeDistanceToCode() should fail with wrong function length")
	}
}

// BenchmarkBinaryAdditiveRSCodeIsInCode benchmarks IsInCode
func BenchmarkBinaryAdditiveRSCodeIsInCode(b *testing.B) {
	field, _ := core.NewField(big.NewInt(17))
	omega := field.NewElementFromInt64(2)
	coset, basis, _ := CreateCyclicGroupCoset(field, omega, 16)
	rate := field.NewElementFromInt64(1)
	rate, _ = rate.Div(field.NewElementFromInt64(2))
	rs, _ := NewBinaryAdditiveRSCode(field, rate, coset, basis)

	function := make([]*core.FieldElement, 16)
	for i := range function {
		function[i] = field.NewElementFromInt64(int64(i + 1))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rs.IsInCode(function)
	}
}

// BenchmarkCreateCyclicGroupCoset benchmarks cyclic group coset creation
func BenchmarkCreateCyclicGroupCoset(b *testing.B) {
	field, _ := core.NewField(big.NewInt(17))
	omega := field.NewElementFromInt64(2)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CreateCyclicGroupCoset(field, omega, 16)
	}
}
