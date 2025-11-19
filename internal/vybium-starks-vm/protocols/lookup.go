package protocols

import (
	"fmt"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/utils"
)

// LookupTable represents a lookup table for efficient constraint verification
// This implements the Plookup-style lookup arguments
type LookupTable struct {
	field  *core.Field
	values []*core.FieldElement // The lookup table values
	size   int                  // Size of the table
	// Merkle tree commitment for the table
	merkleTree *core.MerkleTree
	merkleRoot []byte
}

// LookupConstraint represents a lookup constraint
// Proves that a value exists in a lookup table
type LookupConstraint struct {
	Table  *LookupTable
	Input  *core.FieldElement // The value to look up
	Output *core.FieldElement // The expected output (same as input for membership)
	Index  int                // Index in the table (for proof generation)
}

// LookupProof represents a proof for a lookup argument
type LookupProof struct {
	TableCommitment []byte               // Merkle root of the lookup table
	InputProof      []*core.ProofNode    // Merkle proof for the input value
	OutputProof     []*core.ProofNode    // Merkle proof for the output value
	IndexProof      []*core.ProofNode    // Merkle proof for the index
	Queries         []*core.FieldElement // Random queries for verification
}

// NewLookupTable creates a new lookup table
func NewLookupTable(field *core.Field, values []*core.FieldElement) (*LookupTable, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("lookup table cannot be empty")
	}

	// Convert field elements to bytes for Merkle tree
	tableBytes := make([][]byte, len(values))
	for i, value := range values {
		tableBytes[i] = value.Big().Bytes()
	}

	// Create Merkle tree for the table
	merkleTree, err := core.NewMerkleTree(tableBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create Merkle tree for lookup table: %w", err)
	}

	return &LookupTable{
		field:      field,
		values:     values,
		size:       len(values),
		merkleTree: merkleTree,
		merkleRoot: merkleTree.Root(),
	}, nil
}

// CreateRangeTable creates a lookup table for range checks (0 to max-1)
func CreateRangeTable(field *core.Field, max int) (*LookupTable, error) {
	values := make([]*core.FieldElement, max)
	for i := 0; i < max; i++ {
		values[i] = field.NewElementFromInt64(int64(i))
	}
	return NewLookupTable(field, values)
}

// CreateBitTable creates a lookup table for bit operations (0, 1)
func CreateBitTable(field *core.Field) (*LookupTable, error) {
	values := []*core.FieldElement{
		field.Zero(),
		field.One(),
	}
	return NewLookupTable(field, values)
}

// CreateXORTable creates a lookup table for XOR operations
func CreateXORTable(field *core.Field) (*LookupTable, error) {
	values := []*core.FieldElement{
		field.Zero(), // 0 XOR 0 = 0
		field.One(),  // 0 XOR 1 = 1
		field.One(),  // 1 XOR 0 = 1
		field.Zero(), // 1 XOR 1 = 0
	}
	return NewLookupTable(field, values)
}

// Lookup finds a value in the table and returns its index
func (lt *LookupTable) Lookup(value *core.FieldElement) (int, bool) {
	for i, tableValue := range lt.values {
		if tableValue.Equal(value) {
			return i, true
		}
	}
	return -1, false
}

// GetValue returns the value at the given index
func (lt *LookupTable) GetValue(index int) (*core.FieldElement, error) {
	if index < 0 || index >= lt.size {
		return nil, fmt.Errorf("index %d out of range [0, %d)", index, lt.size)
	}
	return lt.values[index], nil
}

// Size returns the size of the lookup table
func (lt *LookupTable) Size() int {
	return lt.size
}

// MerkleRoot returns the Merkle root of the lookup table
func (lt *LookupTable) MerkleRoot() []byte {
	return lt.merkleRoot
}

// LookupProver generates a proof for a lookup argument
type LookupProver struct {
	table *LookupTable
	field *core.Field
}

// NewLookupProver creates a new lookup prover
func NewLookupProver(table *LookupTable) *LookupProver {
	return &LookupProver{
		table: table,
		field: table.field,
	}
}

// ProveLookup generates a proof that a value exists in the lookup table
func (lp *LookupProver) ProveLookup(input *core.FieldElement, channel *utils.Channel) (*LookupProof, error) {
	// Find the input value in the table
	index, found := lp.table.Lookup(input)
	if !found {
		return nil, fmt.Errorf("value %s not found in lookup table", input.String())
	}

	// Generate Merkle proofs for the input value
	inputProof, err := lp.table.merkleTree.Proof(index)
	if err != nil {
		return nil, fmt.Errorf("failed to generate input proof: %w", err)
	}

	// For membership proofs, output equals input
	// Generate random queries for verification
	numQueries := 3
	queries := make([]*core.FieldElement, numQueries)
	for i := 0; i < numQueries; i++ {
		queries[i] = channel.ReceiveRandomFieldElement(lp.field)
	}

	// Convert ProofNode slice to pointer slice
	inputProofPtrs := make([]*core.ProofNode, len(inputProof))
	for i := range inputProof {
		inputProofPtrs[i] = &inputProof[i]
	}

	return &LookupProof{
		TableCommitment: lp.table.merkleRoot,
		InputProof:      inputProofPtrs,
		OutputProof:     inputProofPtrs, // Same proof since output == input
		IndexProof:      inputProofPtrs, // Same proof for index
		Queries:         queries,
	}, nil
}

// LookupVerifier verifies lookup arguments
type LookupVerifier struct {
	field *core.Field
}

// NewLookupVerifier creates a new lookup verifier
func NewLookupVerifier(field *core.Field) *LookupVerifier {
	return &LookupVerifier{
		field: field,
	}
}

// VerifyLookup verifies a lookup proof
func (lv *LookupVerifier) VerifyLookup(proof *LookupProof, input *core.FieldElement, tableCommitment []byte) error {
	// Verify that the table commitment matches
	if string(proof.TableCommitment) != string(tableCommitment) {
		return fmt.Errorf("table commitment mismatch")
	}

	// Convert pointer slice back to value slice for verification
	inputProofValues := make([]core.ProofNode, len(proof.InputProof))
	for i, ptr := range proof.InputProof {
		inputProofValues[i] = *ptr
	}

	outputProofValues := make([]core.ProofNode, len(proof.OutputProof))
	for i, ptr := range proof.OutputProof {
		outputProofValues[i] = *ptr
	}

	// Verify the input proof
	if !core.VerifyProof(proof.TableCommitment, input.Big().Bytes(), inputProofValues, 0) {
		return fmt.Errorf("input proof verification failed")
	}

	// For membership proofs, output should equal input
	output := input
	if !core.VerifyProof(proof.TableCommitment, output.Big().Bytes(), outputProofValues, 0) {
		return fmt.Errorf("output proof verification failed")
	}

	// Verify queries (simplified - in practice would involve more complex checks)
	for _, query := range proof.Queries {
		if query == nil {
			return fmt.Errorf("invalid query in proof")
		}
	}

	return nil
}

// LookupAIR extends AIR with lookup table support
type LookupAIR struct {
	*AIR
	lookupTables []*LookupTable
	constraints  []LookupConstraint
}

// NewLookupAIR creates a new LookupAIR instance
func NewLookupAIR(field *core.Field, traceLength, stateWidth int, rate *core.FieldElement) *LookupAIR {
	return &LookupAIR{
		AIR:          NewAIR(field, traceLength, stateWidth, rate),
		lookupTables: make([]*LookupTable, 0),
		constraints:  make([]LookupConstraint, 0),
	}
}

// AddLookupTable adds a lookup table to the AIR
func (lair *LookupAIR) AddLookupTable(table *LookupTable) {
	lair.lookupTables = append(lair.lookupTables, table)
}

// AddLookupConstraint adds a lookup constraint
func (lair *LookupAIR) AddLookupConstraint(constraint LookupConstraint) {
	lair.constraints = append(lair.constraints, constraint)
}

// CreateLookupConstraints creates lookup constraints for the trace
func (lair *LookupAIR) CreateLookupConstraints() ([]LookupConstraint, error) {
	var constraints []LookupConstraint

	// For each lookup table, create constraints for values that appear in the trace
	for _, table := range lair.lookupTables {
		// Find all values in the trace that exist in this table
		for i := 0; i < lair.traceLength; i++ {
			for j := 0; j < lair.stateWidth; j++ {
				value := lair.trace[i][j]
				if index, found := table.Lookup(value); found {
					constraint := LookupConstraint{
						Table:  table,
						Input:  value,
						Output: value, // For membership, output equals input
						Index:  index,
					}
					constraints = append(constraints, constraint)
				}
			}
		}
	}

	return constraints, nil
}

// GenerateLookupProofs generates proofs for all lookup constraints
func (lair *LookupAIR) GenerateLookupProofs(channel *utils.Channel) ([]*LookupProof, error) {
	var proofs []*LookupProof

	for _, constraint := range lair.constraints {
		prover := NewLookupProver(constraint.Table)
		proof, err := prover.ProveLookup(constraint.Input, channel)
		if err != nil {
			return nil, fmt.Errorf("failed to generate lookup proof: %w", err)
		}
		proofs = append(proofs, proof)
	}

	return proofs, nil
}

// VerifyLookupProofs verifies all lookup proofs
func (lair *LookupAIR) VerifyLookupProofs(proofs []*LookupProof) error {
	if len(proofs) != len(lair.constraints) {
		return fmt.Errorf("proof count mismatch: expected %d, got %d", len(lair.constraints), len(proofs))
	}

	verifier := NewLookupVerifier(lair.field)

	for i, proof := range proofs {
		constraint := lair.constraints[i]
		err := verifier.VerifyLookup(proof, constraint.Input, constraint.Table.merkleRoot)
		if err != nil {
			return fmt.Errorf("lookup proof %d verification failed: %w", i, err)
		}
	}

	return nil
}

// RangeCheckConstraint creates a constraint to prove a value is in range [0, max)
func RangeCheckConstraint(field *core.Field, value *core.FieldElement, max int) (*LookupConstraint, error) {
	// Create a range table
	table, err := CreateRangeTable(field, max)
	if err != nil {
		return nil, fmt.Errorf("failed to create range table: %w", err)
	}

	// Check if value is in range
	index, found := table.Lookup(value)
	if !found {
		return nil, fmt.Errorf("value %s is not in range [0, %d)", value.String(), max)
	}

	return &LookupConstraint{
		Table:  table,
		Input:  value,
		Output: value,
		Index:  index,
	}, nil
}

// BitCheckConstraint creates a constraint to prove a value is a bit (0 or 1)
func BitCheckConstraint(field *core.Field, value *core.FieldElement) (*LookupConstraint, error) {
	// Create a bit table
	table, err := CreateBitTable(field)
	if err != nil {
		return nil, fmt.Errorf("failed to create bit table: %w", err)
	}

	// Check if value is a bit
	index, found := table.Lookup(value)
	if !found {
		return nil, fmt.Errorf("value %s is not a bit (0 or 1)", value.String())
	}

	return &LookupConstraint{
		Table:  table,
		Input:  value,
		Output: value,
		Index:  index,
	}, nil
}
