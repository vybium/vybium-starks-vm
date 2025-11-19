// Package protocols provides optimized FRI protocol implementation
package protocols

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
)

// OptimizedFRIProtocol implements the FRI protocol with performance optimizations
type OptimizedFRIProtocol struct {
	*FRIProtocol // Embed base FRI protocol
	numWorkers   int
}

// NewOptimizedFRIProtocol creates a new optimized FRI protocol
func NewOptimizedFRIProtocol(
	field *core.Field,
	rate *core.FieldElement,
	omega *core.FieldElement,
) *OptimizedFRIProtocol {
	baseFRI := NewFRIProtocol(field, rate, omega)

	return &OptimizedFRIProtocol{
		FRIProtocol: baseFRI,
		numWorkers:  runtime.NumCPU(),
	}
}

// SetNumWorkers sets the number of parallel workers (default: NumCPU)
func (ofri *OptimizedFRIProtocol) SetNumWorkers(n int) {
	if n > 0 {
		ofri.numWorkers = n
	}
}

// ParallelFoldFunction performs FRI folding with parallelization and batch inversion
// This is the core optimization matching Triton VM's split_and_fold
func (ofri *OptimizedFRIProtocol) ParallelFoldFunction(
	function []*core.FieldElement,
	domain []*core.FieldElement,
	challenge *core.FieldElement,
) ([]*core.FieldElement, error) {
	n := len(function)
	if n%2 != 0 {
		return nil, fmt.Errorf("function length must be even, got %d", n)
	}

	if len(domain) != n {
		return nil, fmt.Errorf("domain length must equal function length")
	}

	// Batch invert domain points for efficiency (Montgomery's trick)
	domainInverses, err := ofri.field.BatchInversion(domain[:n/2])
	if err != nil {
		return nil, fmt.Errorf("batch inversion failed: %w", err)
	}

	// Parallel processing using goroutines
	chunkSize := (n/2 + ofri.numWorkers - 1) / ofri.numWorkers
	result := make([]*core.FieldElement, n/2)

	var wg sync.WaitGroup
	errChan := make(chan error, ofri.numWorkers)

	for w := 0; w < ofri.numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			start := workerID * chunkSize
			if start >= n/2 {
				return
			}
			end := min(start+chunkSize, n/2)

			// Precompute constants for this worker
			one := ofri.field.One()
			two := ofri.field.NewElementFromInt64(2)
			twoInv, err := two.Inv()
			if err != nil {
				errChan <- fmt.Errorf("worker %d: failed to compute 2^(-1): %w", workerID, err)
				return
			}

			// Optimized folding formula from TR17-134
			// result[i] = (f[i] + f[n/2+i])/2 + challenge * (f[i] - f[n/2+i])/(2*domain[i])
			//
			// Rewritten as:
			// scaled_offset_inv = challenge * domain[i]^(-1)
			// left_coeff = 1 + scaled_offset_inv
			// right_coeff = 1 - scaled_offset_inv
			// result[i] = (left_coeff * f[i] + right_coeff * f[n/2+i]) / 2

			for i := start; i < end; i++ {
				// Compute scaled_offset_inv = challenge * domain_inverses[i]
				scaledOffsetInv := challenge.Mul(domainInverses[i])

				// Compute left coefficient: (1 + scaled_offset_inv)
				leftCoeff := one.Add(scaledOffsetInv)

				// Compute right coefficient: (1 - scaled_offset_inv)
				rightCoeff := one.Sub(scaledOffsetInv)

				// Compute weighted sum
				leftSummand := leftCoeff.Mul(function[i])
				rightSummand := rightCoeff.Mul(function[n/2+i])

				// Divide by 2
				result[i] = leftSummand.Add(rightSummand).Mul(twoInv)
			}
		}(w)
	}

	wg.Wait()
	close(errChan)

	// Check for errors
	if err := <-errChan; err != nil {
		return nil, err
	}

	return result, nil
}

// OptimizedCommit performs FRI commitment with parallel Merkle tree construction
func (ofri *OptimizedFRIProtocol) OptimizedCommit(
	codeword []*core.FieldElement,
) ([]FRILayer, error) {
	layers := make([]FRILayer, 0)
	currentFunction := codeword
	currentDomain := ofri.generateDomain(len(codeword))

	// First layer
	merkleRoot, err := ofri.parallelMerkleCommitment(currentFunction)
	if err != nil {
		return nil, fmt.Errorf("failed to commit first layer: %w", err)
	}

	// Convert to field.Element slices
	domainElems := make([]field.Element, len(currentDomain))
	for i, d := range currentDomain {
		domainElems[i] = convertToFieldElement(d)
	}
	funcElems := make([]field.Element, len(currentFunction))
	for i, f := range currentFunction {
		funcElems[i] = convertToFieldElement(f)
	}

	layers = append(layers, FRILayer{
		Domain:     domainElems,
		Function:   funcElems,
		MerkleRoot: merkleRoot,
		Challenge:  field.Zero, // No challenge for first layer
	})

	// Folding rounds - continue until domain is small enough (e.g., size 2)
	finalDegree := 1
	for len(currentFunction) > finalDegree*2 {
		// Sample challenge (in real implementation, use Fiat-Shamir)
		challenge := ofri.field.NewElementFromInt64(int64(len(layers) + 1))

		// Parallel fold with batch inversion
		nextFunction, err := ofri.ParallelFoldFunction(currentFunction, currentDomain, challenge)
		if err != nil {
			return nil, fmt.Errorf("folding round %d failed: %w", len(layers), err)
		}

		nextDomain := currentDomain[:len(currentDomain)/2]

		// Parallel Merkle commitment
		nextMerkleRoot, err := ofri.parallelMerkleCommitment(nextFunction)
		if err != nil {
			return nil, fmt.Errorf("failed to commit layer %d: %w", len(layers), err)
		}

		// Convert to field.Element slices
		nextDomainElems := make([]field.Element, len(nextDomain))
		for i, d := range nextDomain {
			nextDomainElems[i] = convertToFieldElement(d)
		}
		nextFuncElems := make([]field.Element, len(nextFunction))
		for i, f := range nextFunction {
			nextFuncElems[i] = convertToFieldElement(f)
		}
		challengeElem := convertToFieldElement(challenge)

		layers = append(layers, FRILayer{
			Domain:     nextDomainElems,
			Function:   nextFuncElems,
			MerkleRoot: nextMerkleRoot,
			Challenge:  challengeElem,
		})

		currentFunction = nextFunction
		currentDomain = nextDomain
	}

	return layers, nil
}

// parallelMerkleCommitment creates a Merkle tree commitment with parallel hashing
func (ofri *OptimizedFRIProtocol) parallelMerkleCommitment(
	codeword []*core.FieldElement,
) ([]byte, error) {
	n := len(codeword)

	// Convert field elements to bytes for Merkle tree
	leaves := make([][]byte, n)

	// Parallel conversion
	chunkSize := (n + ofri.numWorkers - 1) / ofri.numWorkers
	var wg sync.WaitGroup

	for w := 0; w < ofri.numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			start := workerID * chunkSize
			if start >= n {
				return
			}
			end := min(start+chunkSize, n)

			for i := start; i < end; i++ {
				leaves[i] = codeword[i].Bytes()
			}
		}(w)
	}

	wg.Wait()

	// Create Merkle tree (this uses parallel construction internally)
	tree, err := core.NewMerkleTree(leaves)
	if err != nil {
		return nil, fmt.Errorf("failed to create Merkle tree: %w", err)
	}

	return tree.Root(), nil
}

// generateDomain generates the evaluation domain
func (ofri *OptimizedFRIProtocol) generateDomain(size int) []*core.FieldElement {
	domain := make([]*core.FieldElement, size)
	domain[0] = ofri.field.One()

	for i := 1; i < size; i++ {
		domain[i] = domain[i-1].Mul(ofri.omega)
	}

	return domain
}

// OptimizedQuery performs FRI query phase with parallel authentication path generation
func (ofri *OptimizedFRIProtocol) OptimizedQuery(
	layers []FRILayer,
	queryIndices []int,
) ([]FRIQueryResponse, error) {
	responses := make([]FRIQueryResponse, len(queryIndices))

	// Parallel query processing
	chunkSize := (len(queryIndices) + ofri.numWorkers - 1) / ofri.numWorkers
	var wg sync.WaitGroup
	errChan := make(chan error, ofri.numWorkers)

	for w := 0; w < ofri.numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			start := workerID * chunkSize
			if start >= len(queryIndices) {
				return
			}
			end := min(start+chunkSize, len(queryIndices))

			for i := start; i < end; i++ {
				queryIdx := queryIndices[i]

				// Generate response for this query
				response, err := ofri.generateQueryResponse(layers, queryIdx)
				if err != nil {
					errChan <- fmt.Errorf("query %d failed: %w", queryIdx, err)
					return
				}

				responses[i] = response
			}
		}(w)
	}

	wg.Wait()
	close(errChan)

	if err := <-errChan; err != nil {
		return nil, err
	}

	return responses, nil
}

// generateQueryResponse generates a single query response
func (ofri *OptimizedFRIProtocol) generateQueryResponse(
	layers []FRILayer,
	queryIndex int,
) (FRIQueryResponse, error) {
	values := make([]*core.FieldElement, len(layers))
	authPaths := make([][][]byte, len(layers))

	currentIdx := queryIndex
	for i, layer := range layers {
		if currentIdx >= len(layer.Function) {
			return FRIQueryResponse{}, fmt.Errorf("query index %d out of bounds for layer %d", currentIdx, i)
		}

		values[i] = convertFromFieldElement(layer.Function[currentIdx], ofri.field)

		// Generate authentication path (simplified - in production use actual Merkle path)
		authPaths[i] = [][]byte{layer.MerkleRoot}

		// Next layer index is half
		currentIdx = currentIdx / 2
	}

	return FRIQueryResponse{
		QueryIndex:          queryIndex,
		Values:              values,
		AuthenticationPaths: authPaths,
	}, nil
}

// FRIQueryResponse represents a response to a FRI query
type FRIQueryResponse struct {
	QueryIndex          int
	Values              []*core.FieldElement
	AuthenticationPaths [][][]byte
}

// OptimizedVerify performs FRI verification with parallel query checking
func (ofri *OptimizedFRIProtocol) OptimizedVerify(
	layers []FRILayer,
	responses []FRIQueryResponse,
) (bool, error) {
	// Parallel verification of query responses
	results := make([]bool, len(responses))
	chunkSize := (len(responses) + ofri.numWorkers - 1) / ofri.numWorkers

	var wg sync.WaitGroup
	errChan := make(chan error, ofri.numWorkers)

	for w := 0; w < ofri.numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			start := workerID * chunkSize
			if start >= len(responses) {
				return
			}
			end := min(start+chunkSize, len(responses))

			for i := start; i < end; i++ {
				valid, err := ofri.verifyQueryResponse(layers, responses[i])
				if err != nil {
					errChan <- fmt.Errorf("verification of query %d failed: %w", i, err)
					return
				}
				results[i] = valid
			}
		}(w)
	}

	wg.Wait()
	close(errChan)

	if err := <-errChan; err != nil {
		return false, err
	}

	// All queries must pass
	for _, valid := range results {
		if !valid {
			return false, nil
		}
	}

	return true, nil
}

// verifyQueryResponse verifies a single query response
func (ofri *OptimizedFRIProtocol) verifyQueryResponse(
	layers []FRILayer,
	response FRIQueryResponse,
) (bool, error) {
	// Verify folding consistency across layers
	currentIdx := response.QueryIndex

	for i := 0; i < len(layers)-1; i++ {
		currentLayer := layers[i]
		_ = layers[i+1] // nextLayer not used but keep for clarity

		if currentLayer.Challenge.IsZero() {
			continue
		}

		// Verify the folding formula
		n := len(currentLayer.Function)

		// Get domain points
		if currentIdx >= n/2 {
			return false, fmt.Errorf("invalid index for layer %d", i)
		}

		domainPoint := currentLayer.Domain[currentIdx]
		domainPointInv := domainPoint.Inverse()

		// Compute expected next value using folding formula
		one := ofri.field.One()
		two := ofri.field.NewElementFromInt64(2)
		twoInv, _ := two.Inv()

		scaledOffsetInv := currentLayer.Challenge.Mul(domainPointInv)
		oneElem := convertToFieldElement(one)
		leftCoeff := oneElem.Add(scaledOffsetInv)
		rightCoeff := oneElem.Sub(scaledOffsetInv)

		leftValue := convertToFieldElement(response.Values[i])
		rightValue := currentLayer.Function[(currentIdx+n/2)%n]

		twoInvElem := convertToFieldElement(twoInv)
		expected := leftCoeff.Mul(leftValue).Add(rightCoeff.Mul(rightValue)).Mul(twoInvElem)

		// Check if next layer value matches
		nextIdx := currentIdx / 2
		nextValue := convertToFieldElement(response.Values[i+1])
		if !expected.Equal(nextValue) {
			return false, nil
		}

		currentIdx = nextIdx
	}

	return true, nil
}

// CalculateSecurityLevel computes the concrete security level in bits
// Based on FRI soundness analysis from STARK literature
func (ofri *OptimizedFRIProtocol) CalculateSecurityLevel(expansionFactor int, numQueries int) int {
	// Security level = log2(1 / soundness_error)
	// soundness_error ≈ max(ρ^k, proximity_gap)
	// where ρ = rate, k = num_queries

	rate := 1.0 / float64(expansionFactor)

	// Query error: probability that all k queries accept a far codeword
	queryError := powFloat(rate, numQueries)

	// Proximity error: inherent in the protocol
	proximityError := rate + (1.0 - rate)

	// Take the maximum (worst case)
	soundnessError := maxFloat(queryError, proximityError)

	// Security level in bits
	securityBits := -logBase2(soundnessError)

	return int(securityBits)
}

// Helper functions
func powFloat(base float64, exp int) float64 {
	result := 1.0
	for i := 0; i < exp; i++ {
		result *= base
	}
	return result
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func logBase2(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// log2(x) = ln(x) / ln(2)
	return log(x) / log(2.0)
}

func log(x float64) float64 {
	// Simple natural log approximation using Taylor series
	// For production, use math.Log
	if x <= 0 {
		return -1e9
	}
	if x == 1.0 {
		return 0
	}

	// Use change of variables: x = (1+y)/(1-y)
	// Then ln(x) = 2 * (y + y^3/3 + y^5/5 + ...)
	y := (x - 1) / (x + 1)
	y2 := y * y
	result := y
	term := y

	for i := 1; i < 20; i++ {
		term *= y2
		result += term / float64(2*i+1)
	}

	return 2 * result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
