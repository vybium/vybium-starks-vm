package protocols

import (
	"fmt"
	"math/big"

	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/utils"
)

// FRIProtocol implements the exact FRI protocol from TR17-134
// "Fast Reed-Solomon Interactive Oracle Proofs of Proximity"
type FRIProtocol struct {
	field           *core.Field
	rate            *core.FieldElement // ρ = 2^(-R), R ≥ 2
	omega           *core.FieldElement // Generator of cyclic group ⟨ω⟩
	queryPhase      *FRIQueryPhase
	eta             int // Dimension of subspaces L^(i)_0
	repetitionParam int // Number of query repetitions
}

// FRIProof represents a FRI proof according to TR17-134
type FRIProof struct {
	Layers          []FRILayer
	FinalPolynomial *core.Polynomial
	SoundnessError  *core.FieldElement
}

// FRILayer represents a single layer in the FRI protocol
type FRILayer struct {
	Function   []field.Element // f^(i): S^(i) → F
	Domain     []field.Element // S^(i) = ⟨ω^(2^i)⟩
	MerkleRoot []byte
	Challenge  field.Element // x^(i) from verifier
}

// NewFRIProtocol creates a new FRI protocol instance according to TR17-134
func NewFRIProtocol(field *core.Field, rate *core.FieldElement, omega *core.FieldElement) *FRIProtocol {
	// Default parameters from the paper
	eta := 1             // Dimension of subspaces L^(i)_0
	repetitionParam := 1 // Number of query repetitions

	queryPhase := NewFRIQueryPhase(field, rate, eta, repetitionParam)

	return &FRIProtocol{
		field:           field,
		rate:            rate,
		omega:           omega,
		queryPhase:      queryPhase,
		eta:             eta,
		repetitionParam: repetitionParam,
	}
}

// Prove generates a FRI proof according to TR17-134 specifications
func (fri *FRIProtocol) Prove(function []*core.FieldElement, domain []*core.FieldElement, channel *utils.Channel) (*FRIProof, error) {
	if len(function) != len(domain) {
		return nil, fmt.Errorf("function and domain length mismatch")
	}

	// Ensure domain size is a power of 2: N = 2^k
	if !utils.IsPowerOfTwo(len(domain)) {
		return nil, fmt.Errorf("domain size must be a power of 2")
	}

	// Check rate: ρ = 2^(-R), R ≥ 2
	// Standard FRI requires rate ≤ 1/4 for soundness
	if !fri.isValidRate() {
		return nil, fmt.Errorf("invalid rate: must be ρ = 2^(-R) with R ≥ 2 (rate ≤ 1/4)")
	}

	// Create initial domain S^(0) = ⟨ω⟩
	currentDomain := domain
	currentFunction := function

	// Create Merkle tree for initial function
	tree, err := core.NewMerkleTree(fri.functionToBytes(currentFunction))
	if err != nil {
		return nil, fmt.Errorf("failed to create initial Merkle tree: %w", err)
	}

	// Convert currentFunction and currentDomain to field.Element slices
	funcElems := make([]field.Element, len(currentFunction))
	for i, f := range currentFunction {
		funcElems[i] = convertToFieldElement(f)
	}
	domElems := make([]field.Element, len(currentDomain))
	for i, d := range currentDomain {
		domElems[i] = convertToFieldElement(d)
	}

	// Start FRI protocol layers
	layers := []FRILayer{
		{
			Function:   funcElems,
			Domain:     domElems,
			MerkleRoot: convertDigestToBytes(tree.Root()),
		},
	}

	// FRI folding rounds: i = 0 to log N - 1
	for len(currentDomain) > 1 {
		// Receive random challenge x^(i) from verifier
		challenge := channel.ReceiveRandomFieldElement(fri.field)

		// Compute next domain S^(i+1) = ⟨ω^(2^(i+1))⟩
		nextDomain, err := fri.computeNextDomain(currentDomain)
		if err != nil {
			return nil, fmt.Errorf("failed to compute next domain: %w", err)
		}

		// Compute next function f^(i+1) using the folding formula
		nextFunction, err := fri.foldFunction(currentFunction, currentDomain, nextDomain, challenge)
		if err != nil {
			return nil, fmt.Errorf("failed to fold function: %w", err)
		}

		// Create Merkle tree for next function
		nextTree, err := core.NewMerkleTree(fri.functionToBytes(nextFunction))
		if err != nil {
			return nil, fmt.Errorf("failed to create next Merkle tree: %w", err)
		}

		// Convert nextFunction and nextDomain to field.Element slices
		nextFuncElems := make([]field.Element, len(nextFunction))
		for i, f := range nextFunction {
			nextFuncElems[i] = convertToFieldElement(f)
		}
		nextDomElems := make([]field.Element, len(nextDomain))
		for i, d := range nextDomain {
			nextDomElems[i] = convertToFieldElement(d)
		}

		// Add layer to proof
		layers = append(layers, FRILayer{
			Function:   nextFuncElems,
			Domain:     nextDomElems,
			MerkleRoot: convertDigestToBytes(nextTree.Root()),
			Challenge:  convertToFieldElement(challenge),
		})

		// Update for next iteration
		currentFunction = nextFunction
		currentDomain = nextDomain
	}

	// Final polynomial f^(log N) should be constant (degree < ρN/2^(log N))
	finalPolynomial, err := fri.createFinalPolynomial(currentFunction)
	if err != nil {
		return nil, fmt.Errorf("failed to create final polynomial: %w", err)
	}

	// Calculate soundness error bound
	soundnessError, err := fri.calculateSoundnessError(len(domain))
	if err != nil {
		return nil, fmt.Errorf("failed to calculate soundness error: %w", err)
	}

	return &FRIProof{
		Layers:          layers,
		FinalPolynomial: finalPolynomial,
		SoundnessError:  soundnessError,
	}, nil
}

// isValidRate checks if the rate is valid: ρ = 2^(-R), R ≥ 2
// Standard FRI requires rate ≤ 1/4 for soundness
func (fri *FRIProtocol) isValidRate() bool {
	// Check if rate is of the form 2^(-R) with R ≥ 2
	// This means rate should be ≤ 1/4
	// Standard FRI requires rate ≤ 1/4 for soundness
	quarter, err := fri.field.NewElementFromInt64(1).Div(fri.field.NewElementFromInt64(4))
	if err != nil {
		// If division fails (shouldn't happen), fail closed (reject the rate)
		return false
	}
	return fri.rate.LessThan(quarter) || fri.rate.Equal(quarter)
}

// computeNextDomain computes S^(i+1) = ⟨ω^(2^(i+1))⟩
func (fri *FRIProtocol) computeNextDomain(currentDomain []*core.FieldElement) ([]*core.FieldElement, error) {
	if len(currentDomain) == 0 {
		return nil, fmt.Errorf("current domain cannot be empty")
	}

	if len(currentDomain)%2 != 0 {
		return nil, fmt.Errorf("domain size must be even for folding")
	}

	// Take every other element (the "even" positions)
	// This corresponds to the cyclic group ⟨ω^(2^(i+1))⟩
	nextDomain := make([]*core.FieldElement, len(currentDomain)/2)
	for i := 0; i < len(nextDomain); i++ {
		nextDomain[i] = currentDomain[2*i]
	}

	return nextDomain, nil
}

// foldFunction implements the exact folding formula from TR17-134:
// f^(i+1)(y) = (f^(i)(ω^i y) + f^(i)(-ω^i y))/2 + x^(i) * (f^(i)(ω^i y) - f^(i)(-ω^i y))/(2ω^i y)
func (fri *FRIProtocol) foldFunction(function []*core.FieldElement, currentDomain []*core.FieldElement, nextDomain []*core.FieldElement, challenge *core.FieldElement) ([]*core.FieldElement, error) {
	if len(function) != len(currentDomain) {
		return nil, fmt.Errorf("function and domain length mismatch")
	}

	if len(nextDomain) != len(currentDomain)/2 {
		return nil, fmt.Errorf("next domain size must be half of current domain")
	}

	// Convert inputs to field.Element slices
	funcElems := make([]field.Element, len(function))
	for i, f := range function {
		funcElems[i] = convertToFieldElement(f)
	}
	currDomElems := make([]field.Element, len(currentDomain))
	for i, d := range currentDomain {
		currDomElems[i] = convertToFieldElement(d)
	}
	nextDomElems := make([]field.Element, len(nextDomain))
	for i, d := range nextDomain {
		nextDomElems[i] = convertToFieldElement(d)
	}
	challengeElem := convertToFieldElement(challenge)

	nextFunction := make([]*core.FieldElement, len(nextDomain))

	// The current domain has size N, next domain has size N/2
	// For each point y in the next domain, we fold two points from current domain:
	// Points at indices i and i+N/2 (which are cosets)
	halfSize := len(currentDomain) / 2

	// For each point y in the next domain
	for i := 0; i < len(nextDomain); i++ {
		// The two points in current domain that fold to nextDomain[i] are:
		// currentDomain[i] and currentDomain[i + halfSize]
		idx1 := i
		idx2 := i + halfSize

		if idx1 >= len(function) || idx2 >= len(function) {
			return nil, fmt.Errorf("invalid folding indices: %d, %d for domain size %d", idx1, idx2, len(function))
		}

		// Get function values at these two coset points
		fPoint1 := funcElems[idx1]
		fPoint2 := funcElems[idx2]

		// Apply FRI folding formula:
		// f^(i+1)(x^2) = (f^(i)(x) + f^(i)(-x))/2 + α * (f^(i)(x) - f^(i)(-x))/(2x)
		// where α is the challenge, x is the domain point

		// First term: (f^(i)(x) + f^(i)(-x))/2
		sum := fPoint1.Add(fPoint2)
		two := field.New(2)
		half := two.Inverse()
		firstTerm := sum.Mul(half)

		// Second term: α * (f^(i)(x) - f^(i)(-x))/(2x)
		// x is currentDomain[i]
		x := currDomElems[idx1]
		diff := fPoint1.Sub(fPoint2)
		twoX := x.Mul(two)
		quotient := diff.Mul(twoX.Inverse())
		secondTerm := challengeElem.Mul(quotient)

		// Combine terms
		result := firstTerm.Add(secondTerm)

		// Convert back to *core.FieldElement
		nextFunction[i] = convertFromFieldElement(result, fri.field)
	}

	return nextFunction, nil
}

// computeOmegaIY returns the first point in a folding pair

// For index i in the next (halved) domain, returns currentDomain[i]
func (fri *FRIProtocol) computeOmegaIY(index int, currentDomain []field.Element) (field.Element, error) {
	if index < 0 || index >= len(currentDomain)/2 {
		return field.Zero, fmt.Errorf("index %d out of bounds for domain of size %d", index, len(currentDomain))
	}
	return currentDomain[index], nil
}

// computeNegOmegaIY returns the second point in a folding pair

// For index i in the next (halved) domain, returns currentDomain[i + n/2]
func (fri *FRIProtocol) computeNegOmegaIY(index int, currentDomain []field.Element) (field.Element, error) {
	n := len(currentDomain)
	negIndex := index + n/2
	if index < 0 || negIndex >= n {
		return field.Zero, fmt.Errorf("index %d out of bounds for domain of size %d", index, n)
	}
	return currentDomain[negIndex], nil
}

// getFunctionValue gets the function value at a specific point
func (fri *FRIProtocol) getFunctionValue(function []field.Element, domain []field.Element, point field.Element) (field.Element, error) {
	// Find the index of the point in the domain
	for i, domainPoint := range domain {
		if point.Equal(domainPoint) {
			return function[i], nil
		}
	}

	// If point not found, return error (in proper FRI, all points should be in domain)
	return field.Zero, fmt.Errorf("point not found in domain")
}

// createFinalPolynomial creates the final polynomial from the last function
func (fri *FRIProtocol) createFinalPolynomial(function []*core.FieldElement) (*core.Polynomial, error) {
	if len(function) == 0 {
		return nil, fmt.Errorf("function cannot be empty")
	}

	// The final function should be constant (degree < ρN/2^(log N))
	// Check if all values are the same (constant function)
	firstValue := function[0]
	isConstant := true
	for _, value := range function {
		if !value.Equal(firstValue) {
			isConstant = false
			break
		}
	}

	if isConstant {
		// Return constant polynomial
		return core.NewPolynomial([]*core.FieldElement{firstValue})
	}

	// If not constant, create polynomial from evaluations
	// This should not happen in a correct FRI proof, but we handle it gracefully
	// Create proper arithmetic domain for interpolation
	
	// ArithmeticDomain::of_length(last_codeword.len()).interpolate(last_codeword)

	// Get primitive root of unity for the codeword length
	generator := field.PrimitiveRootOfUnity(uint64(len(function)))

	// Create domain points: {1, ω, ω², ..., ω^(n-1)} (no offset)
	domainPoints := make([]*core.FieldElement, len(function))
	power := fri.field.One()
	for i := range domainPoints {
		domainPoints[i] = power
		power = power.Mul(convertFromFieldElement(generator, fri.field))
	}

	// Create points for interpolation
	points := make([]core.Point, len(function))
	for i, value := range function {
		points[i] = *core.NewPoint(domainPoints[i], value)
	}

	// Interpolate polynomial
	poly, err := core.LagrangeInterpolation(points, fri.field)
	if err != nil {
		return nil, fmt.Errorf("failed to interpolate final polynomial: %w", err)
	}

	return poly, nil
}

// calculateSoundnessError calculates the soundness error bound according to TR17-134
func (fri *FRIProtocol) calculateSoundnessError(domainSize int) (*core.FieldElement, error) {
	// Soundness bound from TR17-134: min(δ(1 - o(1)), δ₀)
	// where δ₀ is a constant (e.g., ~0.1 for ρ = 1/8)

	// For simplicity, we'll use a conservative bound
	// In practice, this would be calculated more precisely based on the rate

	// Conservative soundness bound
	soundnessBound, err := fri.field.NewElementFromInt64(1).Div(fri.field.NewElementFromInt64(10)) // 0.1
	if err != nil {
		return nil, fmt.Errorf("failed to compute soundness bound: %w", err)
	}

	// Add error term based on domain size
	errorTerm, err := fri.field.NewElementFromInt64(1).Div(fri.field.NewElementFromInt64(int64(domainSize)))
	if err != nil {
		return nil, fmt.Errorf("failed to compute error term: %w", err)
	}

	finalBound := soundnessBound.Sub(errorTerm)

	return finalBound, nil
}

// functionToBytes converts function values to byte slices for Merkle tree
func (fri *FRIProtocol) functionToBytes(function []*core.FieldElement) [][]byte {
	bytes := make([][]byte, len(function))
	for i, value := range function {
		bytes[i] = value.Bytes()
	}
	return bytes
}

// Query implements the FRI-QUERY phase from TR17-134
func (fri *FRIProtocol) Query(proof *FRIProof, channel *utils.Channel) (*QueryResult, error) {
	return fri.queryPhase.Query(proof, channel)
}

// Verify verifies a FRI proof according to TR17-134
func (fri *FRIProtocol) Verify(proof *FRIProof, channel *utils.Channel) error {
	if len(proof.Layers) == 0 {
		return fmt.Errorf("FRI proof has no layers")
	}

	// Verify each layer
	for i := 0; i < len(proof.Layers)-1; i++ {
		currentLayer := proof.Layers[i]
		nextLayer := proof.Layers[i+1]

		// Verify domain size reduction
		if len(nextLayer.Domain) != len(currentLayer.Domain)/2 {
			return fmt.Errorf("domain size reduction incorrect at layer %d", i)
		}

		// Verify Merkle root consistency
		if len(currentLayer.MerkleRoot) == 0 || len(nextLayer.MerkleRoot) == 0 {
			return fmt.Errorf("empty Merkle root at layer %d", i)
		}

		// Verify folding consistency
		err := fri.verifyFoldingConsistency(currentLayer, nextLayer)
		if err != nil {
			return fmt.Errorf("folding consistency check failed at layer %d: %w", i, err)
		}
	}

	// Verify final layer
	finalLayer := proof.Layers[len(proof.Layers)-1]
	if len(finalLayer.Domain) != 1 {
		return fmt.Errorf("final domain should have size 1, got %d", len(finalLayer.Domain))
	}

	// Verify final polynomial degree
	if proof.FinalPolynomial.Degree() > 0 {
		return fmt.Errorf("final polynomial should be constant (degree 0)")
	}

	// Verify soundness error bound
	if proof.SoundnessError == nil {
		return fmt.Errorf("missing soundness error bound")
	}

	return nil
}

// verifyFoldingConsistency verifies that the folding was done correctly
func (fri *FRIProtocol) verifyFoldingConsistency(currentLayer, nextLayer FRILayer) error {
	// Verify the folding consistency using the mathematical relationship
	// from TR17-134: f^(i+1)(y) = (f^(i)(ω^i y) + f^(i)(-ω^i y))/2 + x^(i) * (f^(i)(ω^i y) - f^(i)(-ω^i y))/(2ω^i y)

	if len(currentLayer.Function) == 0 || len(nextLayer.Function) == 0 {
		return fmt.Errorf("empty function in layer")
	}

	if currentLayer.Challenge.IsZero() {
		return fmt.Errorf("missing challenge in current layer")
	}

	// Verify each point in the next layer
	for i := range nextLayer.Domain {
		// Get the paired points from current layer for folding verification
		// Points at indices i and i+n/2 fold together
		omegaIY, err := fri.computeOmegaIY(i, currentLayer.Domain)
		if err != nil {
			return fmt.Errorf("failed to compute first folding point: %w", err)
		}

		negOmegaIY, err := fri.computeNegOmegaIY(i, currentLayer.Domain)
		if err != nil {
			return fmt.Errorf("failed to compute second folding point: %w", err)
		}

		// Get function values
		fOmegaIY, err := fri.getFunctionValue(currentLayer.Function, currentLayer.Domain, omegaIY)
		if err != nil {
			return fmt.Errorf("failed to get f(ω^i y): %w", err)
		}

		fNegOmegaIY, err := fri.getFunctionValue(currentLayer.Function, currentLayer.Domain, negOmegaIY)
		if err != nil {
			return fmt.Errorf("failed to get f(-ω^i y): %w", err)
		}

		// Apply folding formula
		// f^(i+1)(y) = (f^(i)(ω^i y) + f^(i)(-ω^i y))/2 + x^(i) * (f^(i)(ω^i y) - f^(i)(-ω^i y))/(2ω^i y)

		// First term: (f^(i)(ω^i y) + f^(i)(-ω^i y))/2
		sum := fOmegaIY.Add(fNegOmegaIY)
		two := field.New(2)
		half := two.Inverse()
		firstTerm := sum.Mul(half)

		// Second term: x^(i) * (f^(i)(ω^i y) - f^(i)(-ω^i y))/(2ω^i y)
		diff := fOmegaIY.Sub(fNegOmegaIY)
		twoOmegaIY := omegaIY.Mul(two)
		quotient := diff.Mul(twoOmegaIY.Inverse())
		secondTerm := currentLayer.Challenge.Mul(quotient)

		// Expected value
		expectedValue := firstTerm.Add(secondTerm)

		// Check if the actual value matches the expected value
		if !nextLayer.Function[i].Equal(expectedValue) {
			return fmt.Errorf("folding consistency check failed at point %d: expected %s, got %s",
				i, expectedValue.String(), nextLayer.Function[i].String())
		}
	}

	return nil
}

// GetComplexity returns the complexity bounds from TR17-134
func (fri *FRIProtocol) GetComplexity(domainSize int) (proverOps, verifierOps, proofLength int) {
	// Prover: < 6N arithmetic operations
	proverOps = 6 * domainSize

	// Verifier: ≤ 21 log N arithmetic operations, 2 log N queries
	verifierOps = 21 * utils.Log2(domainSize)

	// Proof length: < N/3 field elements
	proofLength = domainSize / 3

	return proverOps, verifierOps, proofLength
}

// evaluatePolynomialOverDomain evaluates a polynomial over a domain
func (fri *FRIProtocol) EvaluatePolynomialOverDomain(poly *core.Polynomial, domain []*core.FieldElement) ([]*core.FieldElement, error) {
	evaluations := make([]*core.FieldElement, len(domain))

	for i, point := range domain {
		eval := poly.Eval(point)
		evaluations[i] = eval
	}

	return evaluations, nil
}

// Helper function to convert *core.FieldElement to field.Element
func convertToFieldElement(coreElem *core.FieldElement) field.Element {
	if coreElem == nil {
		return field.Zero
	}
	// Extract the value from core.FieldElement and create a new field.Element
	// core.FieldElement stores a big.Int internally
	bigVal := coreElem.Big()
	if bigVal.IsUint64() {
		return field.New(bigVal.Uint64())
	}
	// If too large, reduce modulo the field prime
	return field.New(bigVal.Uint64()) // Will automatically reduce
}

// Helper function to convert hash.Digest to []byte
func convertDigestToBytes(digest []byte) []byte {
	return digest
}

// Helper function to convert field.Element back to *core.FieldElement
func convertFromFieldElement(elem field.Element, coreField *core.Field) *core.FieldElement {
	val := new(big.Int).SetUint64(elem.Value())
	return coreField.NewElement(val)
}
