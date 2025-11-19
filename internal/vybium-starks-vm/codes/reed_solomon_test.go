package codes

import (
	"math/big"
	"testing"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
)

// TestNewReedSolomonCode tests creating a Reed-Solomon code
func TestNewReedSolomonCode(t *testing.T) {
	field, err := core.NewField(big.NewInt(17)) // Small prime for testing
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	// Create domain: {1, 2, 3, 4}
	domain := []*core.FieldElement{
		field.NewElementFromInt64(1),
		field.NewElementFromInt64(2),
		field.NewElementFromInt64(3),
		field.NewElementFromInt64(4),
	}

	// Rate: 0.5 (half-rate code)
	rate := field.NewElementFromInt64(1)
	rate, _ = rate.Div(field.NewElementFromInt64(2))

	rs, err := NewReedSolomonCode(field, domain, rate)
	if err != nil {
		t.Fatalf("NewReedSolomonCode() failed: %v", err)
	}

	if rs == nil {
		t.Fatal("NewReedSolomonCode() returned nil")
	}

	// maxDeg should be rate * |D| - 1 = 0.5 * 4 - 1 = 1
	if rs.maxDeg != 1 {
		t.Errorf("Expected maxDeg = 1, got %d", rs.maxDeg)
	}
}

// TestReedSolomonCodeWithEmptyDomain tests error handling for empty domain
func TestReedSolomonCodeWithEmptyDomain(t *testing.T) {
	field, err := core.NewField(big.NewInt(17))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	domain := []*core.FieldElement{}
	rate := field.NewElementFromInt64(1)

	rs, err := NewReedSolomonCode(field, domain, rate)
	if err == nil {
		t.Error("NewReedSolomonCode() should fail with empty domain")
	}
	if rs != nil {
		t.Error("NewReedSolomonCode() should return nil on error")
	}
}

// TestReedSolomonCodeIsInCode tests checking if evaluations are in the code
func TestReedSolomonCodeIsInCode(t *testing.T) {
	field, err := core.NewField(big.NewInt(17))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	// Create domain: {1, 2, 3, 4}
	domain := []*core.FieldElement{
		field.NewElementFromInt64(1),
		field.NewElementFromInt64(2),
		field.NewElementFromInt64(3),
		field.NewElementFromInt64(4),
	}

	// Rate: 0.5
	rate := field.NewElementFromInt64(1)
	rate, _ = rate.Div(field.NewElementFromInt64(2))

	rs, err := NewReedSolomonCode(field, domain, rate)
	if err != nil {
		t.Fatalf("NewReedSolomonCode() failed: %v", err)
	}

	// Test polynomial f(x) = x (degree 1, should be in code)
	evaluations := []*core.FieldElement{
		field.NewElementFromInt64(1),  // f(1) = 1
		field.NewElementFromInt64(2),  // f(2) = 2
		field.NewElementFromInt64(3),  // f(3) = 3
		field.NewElementFromInt64(4),  // f(4) = 4
	}

	inCode, err := rs.IsInCode(evaluations)
	if err != nil {
		t.Fatalf("IsInCode() failed: %v", err)
	}

	if !inCode {
		t.Error("Linear polynomial should be in half-rate code")
	}
}

// TestReedSolomonCodeIsInCodeHighDegree tests high-degree polynomial
func TestReedSolomonCodeIsInCodeHighDegree(t *testing.T) {
	field, err := core.NewField(big.NewInt(17))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	// Create domain: {1, 2, 3, 4}
	domain := []*core.FieldElement{
		field.NewElementFromInt64(1),
		field.NewElementFromInt64(2),
		field.NewElementFromInt64(3),
		field.NewElementFromInt64(4),
	}

	// Rate: 0.25 (quarter-rate code, maxDeg = 0)
	rate := field.NewElementFromInt64(1)
	rate, _ = rate.Div(field.NewElementFromInt64(4))

	rs, err := NewReedSolomonCode(field, domain, rate)
	if err != nil {
		t.Fatalf("NewReedSolomonCode() failed: %v", err)
	}

	// Test polynomial f(x) = x^2 (degree 2, should NOT be in code with maxDeg = 0)
	evaluations := []*core.FieldElement{
		field.NewElementFromInt64(1),   // f(1) = 1
		field.NewElementFromInt64(4),   // f(2) = 4
		field.NewElementFromInt64(9),   // f(3) = 9
		field.NewElementFromInt64(16),  // f(4) = 16 mod 17
	}

	inCode, err := rs.IsInCode(evaluations)
	if err != nil {
		t.Fatalf("IsInCode() failed: %v", err)
	}

	if inCode {
		t.Error("Quadratic polynomial should NOT be in quarter-rate code")
	}
}

// TestReedSolomonCodeInterpolatePolynomial tests polynomial interpolation
func TestReedSolomonCodeInterpolatePolynomial(t *testing.T) {
	field, err := core.NewField(big.NewInt(17))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	// Create domain: {1, 2}
	domain := []*core.FieldElement{
		field.NewElementFromInt64(1),
		field.NewElementFromInt64(2),
	}

	rate := field.NewElementFromInt64(1)
	rs, err := NewReedSolomonCode(field, domain, rate)
	if err != nil {
		t.Fatalf("NewReedSolomonCode() failed: %v", err)
	}

	// Constant polynomial f(x) = 5
	evaluations := []*core.FieldElement{
		field.NewElementFromInt64(5),
		field.NewElementFromInt64(5),
	}

	poly, err := rs.interpolatePolynomial(evaluations)
	if err != nil {
		t.Fatalf("interpolatePolynomial() failed: %v", err)
	}

	// Verify interpolated polynomial evaluates correctly
	result1 := poly.Eval(field.NewElementFromInt64(1))
	result2 := poly.Eval(field.NewElementFromInt64(2))

	if !result1.Equal(field.NewElementFromInt64(5)) {
		t.Errorf("poly(1) = %v, expected 5", result1.Big())
	}
	if !result2.Equal(field.NewElementFromInt64(5)) {
		t.Errorf("poly(2) = %v, expected 5", result2.Big())
	}
}

// TestReedSolomonCodeComputeLagrangeBasis tests Lagrange basis computation
func TestReedSolomonCodeComputeLagrangeBasis(t *testing.T) {
	field, err := core.NewField(big.NewInt(17))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	// Create domain: {1, 2, 3}
	domain := []*core.FieldElement{
		field.NewElementFromInt64(1),
		field.NewElementFromInt64(2),
		field.NewElementFromInt64(3),
	}

	rate := field.NewElementFromInt64(1)
	rs, err := NewReedSolomonCode(field, domain, rate)
	if err != nil {
		t.Fatalf("NewReedSolomonCode() failed: %v", err)
	}

	// Compute first Lagrange basis polynomial L_0(x)
	L0, err := rs.computeLagrangeBasis(0)
	if err != nil {
		t.Fatalf("computeLagrangeBasis(0) failed: %v", err)
	}

	// L_0(x) should be 1 at x=1 and 0 at x=2,3
	if !L0.Eval(field.NewElementFromInt64(1)).Equal(field.One()) {
		t.Error("L_0(1) should be 1")
	}
	if !L0.Eval(field.NewElementFromInt64(2)).IsZero() {
		t.Error("L_0(2) should be 0")
	}
	if !L0.Eval(field.NewElementFromInt64(3)).IsZero() {
		t.Error("L_0(3) should be 0")
	}
}

// TestReedSolomonCodeComputeHammingDistance tests Hamming distance computation
func TestReedSolomonCodeComputeHammingDistance(t *testing.T) {
	field, err := core.NewField(big.NewInt(17))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	domain := []*core.FieldElement{
		field.NewElementFromInt64(1),
		field.NewElementFromInt64(2),
		field.NewElementFromInt64(3),
		field.NewElementFromInt64(4),
	}

	rate := field.NewElementFromInt64(1)
	rs, err := NewReedSolomonCode(field, domain, rate)
	if err != nil {
		t.Fatalf("NewReedSolomonCode() failed: %v", err)
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

	// Distance should be 2/4 = 0.5
	expected := field.NewElementFromInt64(1)
	expected, _ = expected.Div(field.NewElementFromInt64(2))

	if !distance.Equal(expected) {
		t.Errorf("Expected distance 0.5, got %v", distance.Big())
	}
}

// TestReedSolomonCodeGetMinimumDistance tests minimum distance calculation
func TestReedSolomonCodeGetMinimumDistance(t *testing.T) {
	field, err := core.NewField(big.NewInt(17))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	domain := []*core.FieldElement{
		field.NewElementFromInt64(1),
		field.NewElementFromInt64(2),
		field.NewElementFromInt64(3),
		field.NewElementFromInt64(4),
	}

	// Rate: 0.5
	rate := field.NewElementFromInt64(1)
	rate, _ = rate.Div(field.NewElementFromInt64(2))

	rs, err := NewReedSolomonCode(field, domain, rate)
	if err != nil {
		t.Fatalf("NewReedSolomonCode() failed: %v", err)
	}

	// Minimum distance should be 1 - rate = 1 - 0.5 = 0.5
	minDist := rs.GetMinimumDistance()

	expected := field.NewElementFromInt64(1)
	expected, _ = expected.Div(field.NewElementFromInt64(2))

	if !minDist.Equal(expected) {
		t.Errorf("Expected minimum distance 0.5, got %v", minDist.Big())
	}
}

// TestReedSolomonCodeExtendDomain tests domain extension
func TestReedSolomonCodeExtendDomain(t *testing.T) {
	field, err := core.NewField(big.NewInt(17))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	domain := []*core.FieldElement{
		field.NewElementFromInt64(1),
		field.NewElementFromInt64(2),
	}

	rate := field.NewElementFromInt64(1)
	rs, err := NewReedSolomonCode(field, domain, rate)
	if err != nil {
		t.Fatalf("NewReedSolomonCode() failed: %v", err)
	}

	// Extend to 4 elements
	extended, err := rs.ExtendDomain(4)
	if err != nil {
		t.Fatalf("ExtendDomain() failed: %v", err)
	}

	if len(extended) != 4 {
		t.Errorf("Expected extended domain length 4, got %d", len(extended))
	}

	// First two elements should match original domain
	if !extended[0].Equal(domain[0]) {
		t.Error("Extended domain should preserve original domain elements")
	}
	if !extended[1].Equal(domain[1]) {
		t.Error("Extended domain should preserve original domain elements")
	}
}

// TestReedSolomonCodeExtendDomainError tests error handling
func TestReedSolomonCodeExtendDomainError(t *testing.T) {
	field, err := core.NewField(big.NewInt(17))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	domain := []*core.FieldElement{
		field.NewElementFromInt64(1),
		field.NewElementFromInt64(2),
		field.NewElementFromInt64(3),
	}

	rate := field.NewElementFromInt64(1)
	rs, err := NewReedSolomonCode(field, domain, rate)
	if err != nil {
		t.Fatalf("NewReedSolomonCode() failed: %v", err)
	}

	// Try to "extend" to smaller size (should fail)
	_, err = rs.ExtendDomain(2)
	if err == nil {
		t.Error("ExtendDomain() should fail when extension size <= original size")
	}
}

// TestReedSolomonCodeEvaluateAtPoint tests point evaluation
func TestReedSolomonCodeEvaluateAtPoint(t *testing.T) {
	field, err := core.NewField(big.NewInt(17))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	// Create domain: {1, 2}
	domain := []*core.FieldElement{
		field.NewElementFromInt64(1),
		field.NewElementFromInt64(2),
	}

	rate := field.NewElementFromInt64(1)
	rs, err := NewReedSolomonCode(field, domain, rate)
	if err != nil {
		t.Fatalf("NewReedSolomonCode() failed: %v", err)
	}

	// Linear polynomial f(x) = x
	evaluations := []*core.FieldElement{
		field.NewElementFromInt64(1),  // f(1) = 1
		field.NewElementFromInt64(2),  // f(2) = 2
	}

	// Evaluate at x = 3
	result, err := rs.EvaluateAtPoint(evaluations, field.NewElementFromInt64(3))
	if err != nil {
		t.Fatalf("EvaluateAtPoint() failed: %v", err)
	}

	// f(3) should be 3
	if !result.Equal(field.NewElementFromInt64(3)) {
		t.Errorf("f(3) = %v, expected 3", result.Big())
	}
}

// TestReedSolomonCodeComputeDistanceToCode tests distance to code computation
func TestReedSolomonCodeComputeDistanceToCode(t *testing.T) {
	field, err := core.NewField(big.NewInt(17))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	domain := []*core.FieldElement{
		field.NewElementFromInt64(1),
		field.NewElementFromInt64(2),
		field.NewElementFromInt64(3),
		field.NewElementFromInt64(4),
	}

	// Rate: 0.5 (maxDeg = 1)
	rate := field.NewElementFromInt64(1)
	rate, _ = rate.Div(field.NewElementFromInt64(2))

	rs, err := NewReedSolomonCode(field, domain, rate)
	if err != nil {
		t.Fatalf("NewReedSolomonCode() failed: %v", err)
	}

	// Evaluations of f(x) = x (degree 1, in the code)
	evaluations := []*core.FieldElement{
		field.NewElementFromInt64(1),
		field.NewElementFromInt64(2),
		field.NewElementFromInt64(3),
		field.NewElementFromInt64(4),
	}

	distance, err := rs.ComputeDistanceToCode(evaluations)
	if err != nil {
		t.Fatalf("ComputeDistanceToCode() failed: %v", err)
	}

	// Distance should be 0 (already in code)
	if !distance.IsZero() {
		t.Errorf("Distance to code should be 0 for polynomial in code, got %v", distance.Big())
	}
}

// TestReedSolomonCodeGetListSize tests list size computation
func TestReedSolomonCodeGetListSize(t *testing.T) {
	field, err := core.NewField(big.NewInt(17))
	if err != nil {
		t.Fatalf("Failed to create field: %v", err)
	}

	domain := []*core.FieldElement{
		field.NewElementFromInt64(1),
		field.NewElementFromInt64(2),
		field.NewElementFromInt64(3),
		field.NewElementFromInt64(4),
	}

	// Test with rate 1/4 (square root is well-defined in field 17)
	rate := field.NewElementFromInt64(1)
	rate, _ = rate.Div(field.NewElementFromInt64(4))

	rs, err := NewReedSolomonCode(field, domain, rate)
	if err != nil {
		t.Fatalf("NewReedSolomonCode() failed: %v", err)
	}

	// Test that function returns a valid list size (1 or 10)
	delta := field.NewElementFromInt64(1)
	delta, _ = delta.Div(field.NewElementFromInt64(10))

	listSize := rs.GetListSize(delta)
	if listSize != 1 && listSize != 10 {
		t.Errorf("Expected list size to be 1 or 10, got %d", listSize)
	}

	// Verify list size is positive
	if listSize <= 0 {
		t.Error("List size should be positive")
	}

	// Test with a different delta value
	delta2 := field.NewElementFromInt64(5)
	delta2, _ = delta2.Div(field.NewElementFromInt64(10))

	listSize2 := rs.GetListSize(delta2)
	if listSize2 != 1 && listSize2 != 10 {
		t.Errorf("Expected list size to be 1 or 10, got %d", listSize2)
	}

	// Test with rate where sqrt might fail (non-perfect-square)
	rateBad := field.NewElementFromInt64(3)
	rsBad, _ := NewReedSolomonCode(field, domain, rateBad)

	listSize3 := rsBad.GetListSize(delta)
	// Should still return a valid value (conservative bound of 10)
	if listSize3 != 10 {
		t.Errorf("Expected conservative list size 10 when sqrt might fail, got %d", listSize3)
	}
}

// BenchmarkReedSolomonCodeIsInCode benchmarks IsInCode
func BenchmarkReedSolomonCodeIsInCode(b *testing.B) {
	field, _ := core.NewField(big.NewInt(17))

	domain := make([]*core.FieldElement, 16)
	for i := range domain {
		domain[i] = field.NewElementFromInt64(int64(i + 1))
	}

	rate := field.NewElementFromInt64(1)
	rate, _ = rate.Div(field.NewElementFromInt64(2))

	rs, _ := NewReedSolomonCode(field, domain, rate)

	evaluations := make([]*core.FieldElement, 16)
	for i := range evaluations {
		evaluations[i] = field.NewElementFromInt64(int64(i + 1))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rs.IsInCode(evaluations)
	}
}

// BenchmarkReedSolomonCodeInterpolate benchmarks interpolation
func BenchmarkReedSolomonCodeInterpolate(b *testing.B) {
	field, _ := core.NewField(big.NewInt(17))

	domain := make([]*core.FieldElement, 16)
	for i := range domain {
		domain[i] = field.NewElementFromInt64(int64(i + 1))
	}

	rate := field.NewElementFromInt64(1)
	rs, _ := NewReedSolomonCode(field, domain, rate)

	evaluations := make([]*core.FieldElement, 16)
	for i := range evaluations {
		evaluations[i] = field.NewElementFromInt64(int64(i + 1))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rs.interpolatePolynomial(evaluations)
	}
}

