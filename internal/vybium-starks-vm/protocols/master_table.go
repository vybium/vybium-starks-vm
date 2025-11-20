package protocols

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/hash"
	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/merkle"
	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/polynomial"
)

// MasterTable combines all execution tables and manages trace operations
//
// Following Triton VM's MasterMainTable, this:
// - Holds all table data from the AET
// - Manages trace randomizers for zero-knowledge
// - Performs low-degree extension
// - Builds Merkle commitments
type MasterTable struct {
	traceData      interface{} // Actual trace data (e.g., *vm.AET)
	domains        *ProverDomains
	numRandomizers int
	randomnessSeed []byte

	// Trace columns (before extension)
	traceColumns [][]field.Element

	// Extended columns (after LDE on FRI domain)
	extendedColumns [][]field.Element

	// Merkle tree of extended trace
	merkleTree *merkle.MerkleTree
}

// NewMasterTable creates a new master table from trace data
func NewMasterTable(
	traceData interface{},
	domains *ProverDomains,
	numRandomizers int,
	randomnessSeed []byte,
) (*MasterTable, error) {
	if traceData == nil {
		return nil, fmt.Errorf("trace data cannot be nil")
	}
	if domains == nil {
		return nil, fmt.Errorf("domains cannot be nil")
	}

	mt := &MasterTable{
		traceData:      traceData,
		domains:        domains,
		numRandomizers: numRandomizers,
		randomnessSeed: randomnessSeed,
	}

	// Extract trace columns from AET
	if err := mt.extractTraceColumns(); err != nil {
		return nil, fmt.Errorf("failed to extract trace columns: %w", err)
	}

	// Add trace randomizers for zero-knowledge
	if err := mt.addTraceRandomizers(); err != nil {
		return nil, fmt.Errorf("failed to add trace randomizers: %w", err)
	}

	return mt, nil
}

// extractTraceColumns extracts all columns from the AET into a uniform format
func (mt *MasterTable) extractTraceColumns() error {
	// Cast traceData to ExecutionTrace interface
	trace, ok := mt.traceData.(ExecutionTrace)
	if !ok {
		return fmt.Errorf("trace data does not implement ExecutionTrace interface")
	}

	// Get padded height from execution trace
	paddedHeight := trace.GetPaddedHeight()
	// Note: trace domain length may be larger than padded height if number of
	// randomizers exceeds padded height. This is expected behavior per triton-vm.
	// The key relationship is: randomized_trace.Length = 2 * trace.Length

	if paddedHeight > mt.domains.Trace.Length {
		return fmt.Errorf("AET padded height %d exceeds trace domain length %d",
			paddedHeight, mt.domains.Trace.Length)
	}

	// Get trace columns via the interface (avoids import cycle)
	traceCols, err := trace.GetTraceColumns()
	if err != nil {
		return fmt.Errorf("failed to get trace columns: %w", err)
	}

	// Verify column lengths match padded height
	for i, col := range traceCols {
		if len(col) != paddedHeight {
			return fmt.Errorf("trace column %d has length %d, expected %d",
				i, len(col), paddedHeight)
		}
	}

	// Use the trace columns from the execution trace
	mt.traceColumns = traceCols

	return nil
}

// addTraceRandomizers appends random values to each column for zero-knowledge
func (mt *MasterTable) addTraceRandomizers() error {
	// Following Triton VM: add numRandomizers random elements to each column
	// This ensures zero-knowledge by hiding the actual trace values

	numCols := len(mt.traceColumns)

	// Create deterministic RNG from seed
	rng := newDeterministicRNG(mt.randomnessSeed)

	// RAM-frugal optimization: allocate padding size upfront to avoid reallocation
	// This matches triton-vm's approach of reserving exact capacity
	for col := 0; col < numCols; col++ {
		currentLen := len(mt.traceColumns[col])
		targetLen := mt.domains.RandomizedTrace.Length
		paddingNeeded := targetLen - currentLen - mt.numRandomizers

		// Pre-allocate exact capacity needed (trace + randomizers + padding)
		// This avoids multiple reallocations during append operations
		if cap(mt.traceColumns[col]) < targetLen {
			newCol := make([]field.Element, currentLen, targetLen)
			copy(newCol, mt.traceColumns[col])
			mt.traceColumns[col] = newCol
		}

		// Generate random elements for this column (smaller immediate allocations)
		for i := 0; i < mt.numRandomizers; i++ {
			// Use column index as additional entropy
			randomizer := mt.generateRandomElement(rng, col, i)
			mt.traceColumns[col] = append(mt.traceColumns[col], randomizer)
		}

		// Pad to randomized trace domain length (must be power of 2)
		// Use last element for padding (in-place modification)
		if paddingNeeded > 0 {
			lastElem := mt.traceColumns[col][len(mt.traceColumns[col])-1]
			for i := 0; i < paddingNeeded; i++ {
				mt.traceColumns[col] = append(mt.traceColumns[col], lastElem)
			}
		}
	}

	return nil
}

// generateRandomElement generates a deterministic random field element
func (mt *MasterTable) generateRandomElement(rng *deterministicRNG, col, idx int) field.Element {
	// Mix in column and index for uniqueness
	entropy := make([]byte, 16)
	binary.LittleEndian.PutUint64(entropy[0:8], uint64(col))
	binary.LittleEndian.PutUint64(entropy[8:16], uint64(idx))

	combined := append(rng.next(), entropy...)
	hash := sha256Hash(combined)

	// Convert first 8 bytes to uint64
	var val uint64
	for i := 0; i < 8 && i < len(hash); i++ {
		val |= uint64(hash[i]) << (i * 8)
	}
	return field.New(val)
}

// LowDegreeExtend performs low-degree extension on all columns
//
// Following Triton VM's algorithm:
// 1. Interpolate each column to get polynomial
// 2. Evaluate polynomial on FRI domain (larger than trace domain)
// 3. This creates the "codeword" for FRI protocol
func (mt *MasterTable) LowDegreeExtend(domains *ProverDomains) error {
	numCols := len(mt.traceColumns)
	friLen := domains.FRI.Length

	mt.extendedColumns = make([][]field.Element, numCols)

	// Use parallel processing for better performance
	var wg sync.WaitGroup
	errors := make(chan error, numCols)

	for col := 0; col < numCols; col++ {
		wg.Add(1)
		go func(colIdx int) {
			defer wg.Done()

			// Interpolate column to get polynomial
			poly, err := mt.interpolateColumn(colIdx, domains)
			if err != nil {
				errors <- fmt.Errorf("failed to interpolate column %d: %w", colIdx, err)
				return
			}

			// Evaluate on FRI domain (low-degree extension)
			extended, err := domains.FRI.Evaluate(poly)
			if err != nil {
				errors <- fmt.Errorf("failed to extend column %d: %w", colIdx, err)
				return
			}

			if len(extended) != friLen {
				errors <- fmt.Errorf("column %d: expected %d values, got %d", colIdx, friLen, len(extended))
				return
			}

			mt.extendedColumns[colIdx] = extended
		}(col)
	}

	wg.Wait()
	close(errors)

	// Check for any errors
	if err := <-errors; err != nil {
		return err
	}

	return nil
}

// interpolateColumn interpolates a column to get its polynomial representation
func (mt *MasterTable) interpolateColumn(colIdx int, domains *ProverDomains) (*polynomial.Polynomial, error) {
	column := mt.traceColumns[colIdx]

	// Get evaluation points from randomized trace domain
	// (column has trace length + randomizers = randomized trace length)
	domainPoints := domains.RandomizedTrace.Elements()

	if len(column) != len(domainPoints) {
		return nil, fmt.Errorf("column length %d doesn't match domain length %d",
			len(column), len(domainPoints))
	}

	// Lagrange interpolation - create points array
	points := make([][2]field.Element, len(domainPoints))
	for i := range domainPoints {
		points[i] = [2]field.Element{domainPoints[i], column[i]}
	}

	poly := polynomial.Interpolate(points)
	return poly, nil
}

// BuildMerkleTree creates a Merkle commitment to the extended trace
//
// Following Triton VM: hash each row (across all columns) to create leaves
func (mt *MasterTable) BuildMerkleTree() (*merkle.MerkleTree, error) {
	if len(mt.extendedColumns) == 0 {
		return nil, fmt.Errorf("must call LowDegreeExtend before BuildMerkleTree")
	}

	numRows := len(mt.extendedColumns[0])
	numCols := len(mt.extendedColumns)

	// Hash each row to create Merkle leaves
	leaves := make([][]byte, numRows)

	// Use parallel processing
	var wg sync.WaitGroup
	errors := make(chan error, numRows)

	// Process rows in batches for efficiency
	// Optimize: reuse rowValues buffer to avoid per-row allocations
	batchSize := 1000
	for startRow := 0; startRow < numRows; startRow += batchSize {
		endRow := startRow + batchSize
		if endRow > numRows {
			endRow = numRows
		}

		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()

			// Reuse buffer across rows in this batch to reduce allocations
			rowValues := make([]field.Element, numCols)

			for row := start; row < end; row++ {
				// Collect all values in this row (reusing buffer)
				for col := 0; col < numCols; col++ {
					rowValues[col] = mt.extendedColumns[col][row]
				}

				// Hash the row using Tip5 (direct slice access, no extra allocation)
				rowHash, err := mt.hashRow(rowValues)
				if err != nil {
					errors <- fmt.Errorf("failed to hash row %d: %w", row, err)
					return
				}

				leaves[row] = rowHash
			}
		}(startRow, endRow)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	if err := <-errors; err != nil {
		return nil, err
	}

	// Convert leaves to hash.Digest format
	digestLeaves := make([]hash.Digest, len(leaves))
	for i, leaf := range leaves {
		// Each leaf is []byte, hash.Digest is [DIGEST_LENGTH]field.Element
		// Convert bytes to field elements
		for j := 0; j < len(digestLeaves[i]) && j*8 < len(leaf); j++ {
			// Take 8 bytes and convert to field element
			var val uint64
			for k := 0; k < 8 && j*8+k < len(leaf); k++ {
				val |= uint64(leaf[j*8+k]) << (k * 8)
			}
			digestLeaves[i][j] = field.New(val)
		}
	}

	// Build Merkle tree from leaves
	tree, err := merkle.New(digestLeaves)
	if err != nil {
		return nil, fmt.Errorf("failed to create Merkle tree: %w", err)
	}

	mt.merkleTree = tree
	return tree, nil
}

// hashRow hashes a row of field elements using Tip5
func (mt *MasterTable) hashRow(rowValues []field.Element) ([]byte, error) {
	// Use variable-length Tip5 hash
	digest := hash.HashVarlen(rowValues)
	// Convert hash.Digest to []byte
	// Each field element is 8 bytes
	result := make([]byte, len(digest)*8)
	for i, elem := range digest {
		// Convert field element to bytes (little-endian)
		val := elem.Value()
		for j := 0; j < 8; j++ {
			result[i*8+j] = byte(val >> (j * 8))
		}
	}
	return result, nil
}

// ComputeQuotients computes the constraint quotient polynomials
//
// Following the STARK protocol:
// 1. Create AIR constraints for the tables
// 2. Evaluate composition polynomial over trace
// 3. Divide by vanishing polynomial
// 4. Return quotient polynomials
func (mt *MasterTable) ComputeQuotients(
	domains *ProverDomains,
	challenges []field.Element,
) ([]*polynomial.Polynomial, error) {
	// Create AIR constraints for processor table
	// In a full implementation, we'd have constraints for all 9 tables
	air := CreateProcessorConstraints()

	// Use trace columns (with randomizers) for quotient computation
	// Following triton-vm: quotients are computed from the trace table before extension
	// The trace table includes randomizers for zero-knowledge, and is interpolated
	// over the randomized trace domain. Extension to FRI domain happens later.
	traceTable := mt.traceColumns

	// Compute quotient polynomials
	quotients, err := ComputeQuotientPolynomials(
		air,
		traceTable,
		domains,
		challenges,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to compute quotients: %w", err)
	}

	return quotients, nil
}

// EvaluateAtPoint evaluates all trace columns at a given point
func (mt *MasterTable) EvaluateAtPoint(point field.Element) ([]field.Element, error) {
	if len(mt.extendedColumns) == 0 {
		return nil, fmt.Errorf("must call LowDegreeExtend before EvaluateAtPoint")
	}

	numCols := len(mt.traceColumns)
	values := make([]field.Element, numCols)

	// For each column, interpolate and evaluate at the point
	var wg sync.WaitGroup
	errors := make(chan error, numCols)

	for col := 0; col < numCols; col++ {
		wg.Add(1)
		go func(colIdx int) {
			defer wg.Done()

			// Interpolate column
			poly, err := mt.interpolateColumn(colIdx, mt.domains)
			if err != nil {
				errors <- fmt.Errorf("failed to interpolate column %d: %w", colIdx, err)
				return
			}

			// Evaluate at point
			values[colIdx] = poly.Evaluate(point)
		}(col)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	if err := <-errors; err != nil {
		return nil, err
	}

	return values, nil
}

// getTotalColumns returns the total number of columns across all tables (reserved for future use)
// nolint:unused
func (mt *MasterTable) getTotalColumns() int {
	// Count columns from each table in the AET
	// This Production implementation.
	total := 0

	// Processor table: 13 base columns + 16 stack columns = 29
	total += 29

	// OpStack table: 5 columns
	total += 5

	// RAM table: 6 columns
	total += 6

	// JumpStack table: 5 columns
	total += 5

	// Program table: variable, estimate 10
	total += 10

	// Hash table: 16 state columns
	total += 16

	// U32 table: 10 columns
	total += 10

	// Cascade table: 4 columns
	total += 4

	// Lookup table: 4 columns
	total += 4

	return total
}

// deterministicRNG is a simple deterministic random number generator
type deterministicRNG struct {
	state []byte
	index int
}

// newDeterministicRNG creates a new deterministic RNG from a seed
func newDeterministicRNG(seed []byte) *deterministicRNG {
	// Use crypto hash to expand seed
	state := sha256Hash(seed)
	return &deterministicRNG{
		state: state[:],
		index: 0,
	}
}

// next returns the next random bytes
func (rng *deterministicRNG) next() []byte {
	// Hash current state to get next random bytes
	result := sha256Hash(append(rng.state, byte(rng.index)))
	rng.index++

	// Periodically rehash state to maintain unpredictability
	if rng.index%100 == 0 {
		rng.state = sha256Hash(rng.state)
		rng.index = 0
	}

	return result[:]
}

// sha256Hash is a helper to compute SHA256 hash
func sha256Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// GetExtendedColumn returns an extended column by index (for testing)
func (mt *MasterTable) GetExtendedColumn(colIdx int) ([]field.Element, error) {
	if colIdx < 0 || colIdx >= len(mt.extendedColumns) {
		return nil, fmt.Errorf("column index %d out of range [0, %d)", colIdx, len(mt.extendedColumns))
	}
	return mt.extendedColumns[colIdx], nil
}

// NumColumns returns the total number of columns
func (mt *MasterTable) NumColumns() int {
	return len(mt.traceColumns)
}

// NumExtendedRows returns the number of rows in the extended table
func (mt *MasterTable) NumExtendedRows() int {
	if len(mt.extendedColumns) == 0 {
		return 0
	}
	return len(mt.extendedColumns[0])
}
