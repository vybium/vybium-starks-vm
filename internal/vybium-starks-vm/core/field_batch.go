// Package core provides batch operations for field arithmetic
package core

import (
	"fmt"
	"math/big"
	"sync"
)

// BatchInversion performs batch inversion using Montgomery's trick
// This is approximately 3x faster than individual inversions for large batches
//
// Algorithm:
// 1. Compute accumulative products: acc[i] = elements[0] * ... * elements[i]
// 2. Invert the final accumulator: acc[n-1]^(-1)
// 3. Back-substitute to compute individual inverses
//
// Mathematical correctness:
// For elements a, b, c: (abc)^(-1) * (ab) = c^(-1)
func (f *Field) BatchInversion(elements []*FieldElement) ([]*FieldElement, error) {
	n := len(elements)
	if n == 0 {
		return []*FieldElement{}, nil
	}

	// Handle single element case
	if n == 1 {
		inv, err := elements[0].Inv()
		if err != nil {
			return nil, err
		}
		return []*FieldElement{inv}, nil
	}

	// Check for zero elements (cannot be inverted)
	for i, elem := range elements {
		if elem.IsZero() {
			return nil, fmt.Errorf("cannot invert zero element at index %d", i)
		}
	}

	// Phase 1: Accumulate products
	// acc[i] = elements[0] * elements[1] * ... * elements[i]
	acc := make([]*FieldElement, n)
	acc[0] = elements[0]
	for i := 1; i < n; i++ {
		acc[i] = acc[i-1].Mul(elements[i])
	}

	// Phase 2: Invert the final accumulator
	accInv, err := acc[n-1].Inv()
	if err != nil {
		return nil, fmt.Errorf("failed to invert accumulator: %w", err)
	}

	// Phase 3: Back-substitute to compute individual inverses
	// elements[i]^(-1) = acc[i-1] * acc[i]^(-1)
	results := make([]*FieldElement, n)
	for i := n - 1; i > 0; i-- {
		results[i] = accInv.Mul(acc[i-1])
		accInv = accInv.Mul(elements[i])
	}
	results[0] = accInv

	return results, nil
}

// ParallelBatchInversion performs batch inversion with parallelization for very large batches
// Uses batch inversion on chunks, then combines results
// Optimal for batches larger than 1000 elements
func (f *Field) ParallelBatchInversion(elements []*FieldElement, numWorkers int) ([]*FieldElement, error) {
	n := len(elements)
	if n == 0 {
		return []*FieldElement{}, nil
	}

	// For small batches, use regular batch inversion
	if n < 1000 || numWorkers <= 1 {
		return f.BatchInversion(elements)
	}

	// Split into chunks
	chunkSize := (n + numWorkers - 1) / numWorkers
	results := make([]*FieldElement, n)

	var wg sync.WaitGroup
	errChan := make(chan error, numWorkers)

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			start := workerID * chunkSize
			if start >= n {
				return
			}
			end := min(start+chunkSize, n)

			// Batch invert this chunk
			chunk := elements[start:end]
			inverted, err := f.BatchInversion(chunk)
			if err != nil {
				errChan <- fmt.Errorf("worker %d failed: %w", workerID, err)
				return
			}

			// Copy results
			copy(results[start:end], inverted)
		}(w)
	}

	wg.Wait()
	close(errChan)

	// Check for errors
	if err := <-errChan; err != nil {
		return nil, err
	}

	return results, nil
}

// BatchMultiplication performs batch multiplication of pairs
// More cache-friendly than individual multiplications
func (f *Field) BatchMultiplication(a, b []*FieldElement) ([]*FieldElement, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("batch multiplication requires equal-length arrays")
	}

	n := len(a)
	results := make([]*FieldElement, n)

	for i := 0; i < n; i++ {
		results[i] = a[i].Mul(b[i])
	}

	return results, nil
}

// ParallelBatchMultiplication performs batch multiplication with parallelization
func (f *Field) ParallelBatchMultiplication(a, b []*FieldElement, numWorkers int) ([]*FieldElement, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("batch multiplication requires equal-length arrays")
	}

	n := len(a)
	if n < 1000 || numWorkers <= 1 {
		return f.BatchMultiplication(a, b)
	}

	results := make([]*FieldElement, n)
	chunkSize := (n + numWorkers - 1) / numWorkers

	var wg sync.WaitGroup

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			start := workerID * chunkSize
			if start >= n {
				return
			}
			end := min(start+chunkSize, n)

			for i := start; i < end; i++ {
				results[i] = a[i].Mul(b[i])
			}
		}(w)
	}

	wg.Wait()
	return results, nil
}

// BatchAddition performs batch addition of pairs
func (f *Field) BatchAddition(a, b []*FieldElement) ([]*FieldElement, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("batch addition requires equal-length arrays")
	}

	n := len(a)
	results := make([]*FieldElement, n)

	for i := 0; i < n; i++ {
		results[i] = a[i].Add(b[i])
	}

	return results, nil
}

// BatchSubtraction performs batch subtraction of pairs
func (f *Field) BatchSubtraction(a, b []*FieldElement) ([]*FieldElement, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("batch subtraction requires equal-length arrays")
	}

	n := len(a)
	results := make([]*FieldElement, n)

	for i := 0; i < n; i++ {
		results[i] = a[i].Sub(b[i])
	}

	return results, nil
}

// BatchExponentiation performs batch exponentiation with the same exponent
// Useful for computing powers in polynomial evaluation
func (f *Field) BatchExponentiation(bases []*FieldElement, exponent *big.Int) []*FieldElement {
	n := len(bases)
	results := make([]*FieldElement, n)

	for i := 0; i < n; i++ {
		results[i] = bases[i].Exp(exponent)
	}

	return results
}

// ParallelBatchExponentiation performs batch exponentiation with parallelization
func (f *Field) ParallelBatchExponentiation(bases []*FieldElement, exponent *big.Int, numWorkers int) []*FieldElement {
	n := len(bases)
	if n < 100 || numWorkers <= 1 {
		return f.BatchExponentiation(bases, exponent)
	}

	results := make([]*FieldElement, n)
	chunkSize := (n + numWorkers - 1) / numWorkers

	var wg sync.WaitGroup

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			start := workerID * chunkSize
			if start >= n {
				return
			}
			end := min(start+chunkSize, n)

			for i := start; i < end; i++ {
				results[i] = bases[i].Exp(exponent)
			}
		}(w)
	}

	wg.Wait()
	return results
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
