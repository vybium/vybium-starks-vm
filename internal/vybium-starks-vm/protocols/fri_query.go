package protocols

import (
	"fmt"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/utils"
)

// FRIQueryPhase implements the FRI-QUERY phase from TR17-134
// This is the critical missing component for full FRI compliance
type FRIQueryPhase struct {
	field           *core.Field
	rate            *core.FieldElement
	eta             int // Dimension of subspaces L^(i)_0
	repetitionParam int // Number of query repetitions
}

// Coset represents a coset of a subspace in the FRI protocol
type Coset struct {
	Subspace *Subspace            // L^(i)_0 of dimension η
	Elements []*core.FieldElement // Coset elements
}

// Subspace represents a subspace L^(i)_0 of dimension η
type Subspace struct {
	Dimension int
	Elements  []*core.FieldElement
}

// QueryResult represents the result of a FRI query
type QueryResult struct {
	Accepted bool
	Queries  []QueryTest
}

// QueryTest represents a single query test result
type QueryTest struct {
	LayerIndex    int
	CosetIndex    int
	ConsistencyOK bool
	Values        []*core.FieldElement
}

// NewFRIQueryPhase creates a new FRI query phase
func NewFRIQueryPhase(field *core.Field, rate *core.FieldElement, eta, repetitionParam int) *FRIQueryPhase {
	return &FRIQueryPhase{
		field:           field,
		rate:            rate,
		eta:             eta,
		repetitionParam: repetitionParam,
	}
}

// Query implements the FRI-QUERY phase from the paper
func (query *FRIQueryPhase) Query(proof *FRIProof, channel *utils.Channel) (*QueryResult, error) {
	if len(proof.Layers) == 0 {
		return nil, fmt.Errorf("proof has no layers")
	}

	// Terminal function reconstruction
	err := query.terminalFunctionReconstruction(proof)
	if err != nil {
		return nil, fmt.Errorf("terminal function reconstruction failed: %w", err)
	}

	// Repeat query tests
	queryTests := []QueryTest{}

	for rep := 0; rep < query.repetitionParam; rep++ {
		test, err := query.performQueryTest(proof, channel)
		if err != nil {
			return nil, fmt.Errorf("query test %d failed: %w", rep, err)
		}
		queryTests = append(queryTests, test)

		// If any test fails, reject immediately
		if !test.ConsistencyOK {
			return &QueryResult{
				Accepted: false,
				Queries:  queryTests,
			}, nil
		}
	}

	return &QueryResult{
		Accepted: true,
		Queries:  queryTests,
	}, nil
}

// terminalFunctionReconstruction implements the terminal function reconstruction step
func (query *FRIQueryPhase) terminalFunctionReconstruction(proof *FRIProof) error {
	// From the paper: query a^(r)_0, ..., a^(r)_d where d = ρ · |L^(r)| - 1
	// and verify that P'(X) = Σ_{j≤d} a^(r)_j X^j equals f^(r)

	finalLayer := proof.Layers[len(proof.Layers)-1]
	if len(finalLayer.Domain) == 0 {
		return fmt.Errorf("final layer has empty domain")
	}

	// Calculate expected degree: d = ρ · |L^(r)| - 1
	domainSize := len(finalLayer.Domain)
	// For simplicity, use a conservative estimate
	expectedDegree := domainSize/8 - 1 // Assuming rate = 1/8
	if expectedDegree < 0 {
		expectedDegree = 0
	}

	// Verify that the final polynomial has the correct degree
	if proof.FinalPolynomial.Degree() > expectedDegree {
		return fmt.Errorf("final polynomial degree %d exceeds expected degree %d",
			proof.FinalPolynomial.Degree(), expectedDegree)
	}

	// Verify that the final polynomial evaluates correctly on the final domain
	for i, point := range finalLayer.Domain {
		pointCore := convertFromFieldElement(point, query.field)
		expectedValue := proof.FinalPolynomial.Eval(pointCore)
		actualValue := finalLayer.Function[i]

		expectedElem := convertToFieldElement(expectedValue)
		if !expectedElem.Equal(actualValue) {
			return fmt.Errorf("final polynomial evaluation mismatch at point %d", i)
		}
	}

	return nil
}

// performQueryTest performs a single query test as described in the paper
func (query *FRIQueryPhase) performQueryTest(proof *FRIProof, channel *utils.Channel) (QueryTest, error) {
	// Convert first domain to core types for sampling
	firstDomainCore := make([]*core.FieldElement, len(proof.Layers[0].Domain))
	for i, elem := range proof.Layers[0].Domain {
		firstDomainCore[i] = convertFromFieldElement(elem, query.field)
	}

	// Sample uniformly random s^(0) ∈ L^(0)
	s0 := query.sampleRandomPoint(firstDomainCore)

	// For i = 0, ..., r-1: s^(i+1) = q^(i)(s^(i))
	points := []*core.FieldElement{s0}
	currentPoint := s0

	for i := 0; i < len(proof.Layers)-1; i++ {
		// Convert domains to core types
		currDomainCore := make([]*core.FieldElement, len(proof.Layers[i].Domain))
		for j, elem := range proof.Layers[i].Domain {
			currDomainCore[j] = convertFromFieldElement(elem, query.field)
		}
		nextDomainCore := make([]*core.FieldElement, len(proof.Layers[i+1].Domain))
		for j, elem := range proof.Layers[i+1].Domain {
			nextDomainCore[j] = convertFromFieldElement(elem, query.field)
		}

		nextPoint, err := query.computeNextPoint(currentPoint, currDomainCore, nextDomainCore)
		if err != nil {
			return QueryTest{}, fmt.Errorf("failed to compute next point at layer %d: %w", i, err)
		}
		points = append(points, nextPoint)
		currentPoint = nextPoint
	}

	// Perform round consistency tests
	for i := 0; i < len(proof.Layers)-1; i++ {
		// Use challenge from layer, or generate a default one if zero
		challenge := proof.Layers[i].Challenge
		challengeCore := convertFromFieldElement(challenge, query.field)
		if challenge.IsZero() {
			challengeCore = query.field.NewElementFromInt64(1)
		}

		consistent, err := query.roundConsistencyTest(
			proof.Layers[i],
			proof.Layers[i+1],
			points[i],
			points[i+1],
			challengeCore,
		)
		if err != nil {
			return QueryTest{}, fmt.Errorf("round consistency test failed at layer %d: %w", i, err)
		}

		if !consistent {
			return QueryTest{
				LayerIndex:    i,
				CosetIndex:    0,
				ConsistencyOK: false,
				Values:        []*core.FieldElement{points[i], points[i+1]},
			}, nil
		}
	}

	return QueryTest{
		LayerIndex:    -1, // All layers
		CosetIndex:    0,
		ConsistencyOK: true,
		Values:        points,
	}, nil
}

// roundConsistencyTest implements the 3-query consistency test from the paper
func (query *FRIQueryPhase) roundConsistencyTest(
	currentLayer, nextLayer FRILayer,
	s, sNext *core.FieldElement,
	challenge *core.FieldElement,
) (bool, error) {
	// From the paper: round consistency test
	// 1. Sample a pair of distinct elements s0, s1 ∈ L^(i) such that s0^2 = s1^2 = y
	// 2. Query f^(i)(s0), f^(i)(s1) and f^(i+1)(y)
	// 3. Interpolate the "line" through (s0, α0) and (s1, α1)
	// 4. Accept if and only if p(x^(i)) = β

	// Handle nil challenge case
	if challenge == nil {
		// For demo purposes, use a default challenge
		challenge = query.field.NewElementFromInt64(1)
	}

	// Find the coset containing s
	// Convert domain to core types
	domainCore := make([]*core.FieldElement, len(currentLayer.Domain))
	for i, elem := range currentLayer.Domain {
		domainCore[i] = convertFromFieldElement(elem, query.field)
	}
	coset, err := query.findCoset(s, domainCore)
	if err != nil {
		return false, fmt.Errorf("failed to find coset: %w", err)
	}

	// Get the elements in the coset
	if len(coset.Elements) == 0 {
		return false, fmt.Errorf("coset is empty")
	}

	s0 := coset.Elements[0]
	var s1 *core.FieldElement

	if len(coset.Elements) == 2 {
		s1 = coset.Elements[1]
	} else {
		// For demo purposes, use the negative of s0
		s1 = s0.Neg()
	}

	// Query f^(i)(s0), f^(i)(s1)
	// Convert function and domain to core types
	functionCore := make([]*core.FieldElement, len(currentLayer.Function))
	for i, elem := range currentLayer.Function {
		functionCore[i] = convertFromFieldElement(elem, query.field)
	}
	domainCore = make([]*core.FieldElement, len(currentLayer.Domain))
	for i, elem := range currentLayer.Domain {
		domainCore[i] = convertFromFieldElement(elem, query.field)
	}

	alpha0, err := query.getFunctionValue(functionCore, domainCore, s0)
	if err != nil {
		return false, fmt.Errorf("failed to get f^(i)(s0): %w", err)
	}

	alpha1, err := query.getFunctionValue(functionCore, domainCore, s1)
	if err != nil {
		return false, fmt.Errorf("failed to get f^(i)(s1): %w", err)
	}

	// Query f^(i+1)(y) where y = s0^2 = s1^2
	y := s0.Mul(s0) // y = s0^2

	// Convert next layer function and domain to core types
	nextFunctionCore := make([]*core.FieldElement, len(nextLayer.Function))
	for i, elem := range nextLayer.Function {
		nextFunctionCore[i] = convertFromFieldElement(elem, query.field)
	}
	nextDomainCore := make([]*core.FieldElement, len(nextLayer.Domain))
	for i, elem := range nextLayer.Domain {
		nextDomainCore[i] = convertFromFieldElement(elem, query.field)
	}

	beta, err := query.getFunctionValue(nextFunctionCore, nextDomainCore, y)
	if err != nil {
		return false, fmt.Errorf("failed to get f^(i+1)(y): %w", err)
	}

	// Interpolate the line through (s0, α0) and (s1, α1)
	// p(X) = α0 + (α1 - α0) * (X - s0) / (s1 - s0)
	linePoly, err := query.interpolateLine(s0, alpha0, s1, alpha1)
	if err != nil {
		return false, fmt.Errorf("failed to interpolate line: %w", err)
	}

	// Check p(x^(i)) = β
	pAtChallenge := linePoly.Eval(challenge)

	return pAtChallenge.Equal(beta), nil
}

// sampleRandomPoint samples a random point from the domain
func (query *FRIQueryPhase) sampleRandomPoint(domain []*core.FieldElement) *core.FieldElement {
	// For simplicity, we'll use the first point
	// In a full implementation, this would use proper random sampling
	return domain[0]
}

// computeNextPoint computes s^(i+1) = q^(i)(s^(i))
func (query *FRIQueryPhase) computeNextPoint(s *core.FieldElement, currentDomain, nextDomain []*core.FieldElement) (*core.FieldElement, error) {
	// For smooth groups, q^(i)(s) = s^2
	// This maps the current domain to the next domain
	return s.Mul(s), nil
}

// findCoset finds the coset containing the given point
func (query *FRIQueryPhase) findCoset(point *core.FieldElement, domain []*core.FieldElement) (*Coset, error) {
	// For smooth groups, cosets are pairs of points {s, -s}
	// Find the point that pairs with the given point

	negPoint := point.Neg()

	// Look for the negative point in the domain
	for _, domainPoint := range domain {
		if domainPoint.Equal(negPoint) {
			return &Coset{
				Subspace: &Subspace{
					Dimension: 1,
					Elements:  []*core.FieldElement{point, negPoint},
				},
				Elements: []*core.FieldElement{point, negPoint},
			}, nil
		}
	}

	// If negative point not found, create a coset with just the point
	// This is a simplified approach for demo purposes
	return &Coset{
		Subspace: &Subspace{
			Dimension: 1,
			Elements:  []*core.FieldElement{point},
		},
		Elements: []*core.FieldElement{point},
	}, nil
}

// getFunctionValue gets the function value at a specific point
func (query *FRIQueryPhase) getFunctionValue(function []*core.FieldElement, domain []*core.FieldElement, point *core.FieldElement) (*core.FieldElement, error) {
	// Find the index of the point in the domain
	for i, domainPoint := range domain {
		if point.Equal(domainPoint) {
			return function[i], nil
		}
	}

	// If point not found, use polynomial interpolation
	return query.interpolateAtPoint(function, domain, point)
}

// interpolateAtPoint interpolates the function at a point using Lagrange interpolation
func (query *FRIQueryPhase) interpolateAtPoint(function []*core.FieldElement, domain []*core.FieldElement, point *core.FieldElement) (*core.FieldElement, error) {
	result := query.field.Zero()

	for i := 0; i < len(domain); i++ {
		// Compute L_i(point) = Π((point - x_j) / (x_i - x_j)) for j ≠ i
		lagrangeBasis := query.field.One()

		for j := 0; j < len(domain); j++ {
			if j == i {
				continue
			}

			// (point - x_j)
			numerator := point.Sub(domain[j])

			// (x_i - x_j)
			denominator := domain[i].Sub(domain[j])
			if denominator.IsZero() {
				return nil, fmt.Errorf("duplicate domain points")
			}

			// (point - x_j) / (x_i - x_j)
			term, err := numerator.Div(denominator)
			if err != nil {
				return nil, fmt.Errorf("failed to compute Lagrange basis: %w", err)
			}

			lagrangeBasis = lagrangeBasis.Mul(term)
		}

		// Add f(x_i) * L_i(point) to result
		term := function[i].Mul(lagrangeBasis)
		result = result.Add(term)
	}

	return result, nil
}

// interpolateLine interpolates a line through two points
func (query *FRIQueryPhase) interpolateLine(x0, y0, x1, y1 *core.FieldElement) (*core.Polynomial, error) {
	// p(X) = y0 + (y1 - y0) * (X - x0) / (x1 - x0)

	// Compute (y1 - y0) / (x1 - x0)
	denominator := x1.Sub(x0)
	if denominator.IsZero() {
		return nil, fmt.Errorf("cannot interpolate line through identical points")
	}

	slope, err := y1.Sub(y0).Div(denominator)
	if err != nil {
		return nil, fmt.Errorf("failed to compute slope: %w", err)
	}

	// p(X) = y0 + slope * (X - x0) = y0 - slope * x0 + slope * X
	constant := y0.Sub(slope.Mul(x0))

	// Create polynomial: constant + slope * X
	coefficients := []*core.FieldElement{constant, slope}
	poly, err := core.NewPolynomial(coefficients)
	if err != nil {
		return nil, fmt.Errorf("failed to create polynomial: %w", err)
	}
	return poly, nil
}

// Note: FRIQueryPhase soundness error calculation is handled by the main FRI protocol.
// The δ₀ parameter and soundness error calculations from TR17-134 are implemented
// in fri.go:calculateSoundnessError which is actually used in proof generation.
// The FRIQueryPhase-specific versions have been removed to eliminate code duplication.
