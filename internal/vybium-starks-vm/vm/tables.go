// Package vm provides the Vybium STARKs VM virtual machine implementation
package vm

import (
	"fmt"

	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/protocols"
)

// TableID uniquely identifies each table in the multi-table architecture
type TableID int

const (
	// ProcessorTable records the main execution trace
	ProcessorTable TableID = iota

	// OperationalStackTable tracks stack operations
	OperationalStackTable

	// RAMTable ensures memory consistency
	RAMTable

	// JumpStackTable handles control flow
	JumpStackTable

	// HashTable records cryptographic operations (Poseidon)
	HashTable

	// U32Table handles 32-bit operations
	U32Table

	// ProgramTable provides program attestation
	ProgramTable

	// CascadeTable optimizes lookup arguments
	CascadeTable

	// LookupTable stores precomputed values
	LookupTable

	// ProgramHashTable computes program digest (TIP-0006)
	ProgramHashTable
)

// String returns the name of the table
func (id TableID) String() string {
	switch id {
	case ProcessorTable:
		return "Processor"
	case OperationalStackTable:
		return "OperationalStack"
	case RAMTable:
		return "RAM"
	case JumpStackTable:
		return "JumpStack"
	case HashTable:
		return "Hash"
	case U32Table:
		return "U32"
	case ProgramTable:
		return "Program"
	case CascadeTable:
		return "Cascade"
	case LookupTable:
		return "Lookup"
	case ProgramHashTable:
		return "ProgramHash"
	default:
		return "Unknown"
	}
}

// ExecutionTable is the interface that all tables must implement
type ExecutionTable interface {
	// GetID returns the table's unique identifier
	GetID() TableID

	// GetHeight returns the current height (number of rows) before padding
	GetHeight() int

	// GetPaddedHeight returns the height after padding to power of 2
	GetPaddedHeight() int

	// GetMainColumns returns the main columns (BField elements)
	GetMainColumns() [][]field.Element

	// GetAuxiliaryColumns returns the auxiliary columns (XField elements for arguments)
	GetAuxiliaryColumns() [][]field.Element

	// Pad extends the table to the target height with padding rows
	Pad(targetHeight int) error

	// CreateInitialConstraints generates constraints for the first row
	CreateInitialConstraints() ([]protocols.AIRConstraint, error)

	// CreateConsistencyConstraints generates constraints within each row
	CreateConsistencyConstraints() ([]protocols.AIRConstraint, error)

	// CreateTransitionConstraints generates constraints between consecutive rows
	CreateTransitionConstraints() ([]protocols.AIRConstraint, error)

	// CreateTerminalConstraints generates constraints for the last row
	CreateTerminalConstraints() ([]protocols.AIRConstraint, error)
}

// TableLinkage describes how tables are connected
type TableLinkage struct {
	FromTable TableID
	ToTable   TableID
	LinkType  LinkageType
	Challenge field.Element // Verifier challenge for this linkage
}

// LinkageType defines the type of cross-table argument
type LinkageType int

const (
	// PermutationArgument proves one table is a permutation of another
	PermutationArgument LinkageType = iota

	// EvaluationArgument links table to public input/output
	EvaluationArgument

	// LookupArgument proves values in one table appear in another
	LookupArgument

	// ContiguityArgument proves memory pointer regions are contiguous
	ContiguityArgument
)

// String returns the name of the linkage type
func (lt LinkageType) String() string {
	switch lt {
	case PermutationArgument:
		return "Permutation"
	case EvaluationArgument:
		return "Evaluation"
	case LookupArgument:
		return "Lookup"
	case ContiguityArgument:
		return "Contiguity"
	default:
		return "Unknown"
	}
}

// AlgebraicExecutionTrace holds all 10 tables and their linkages
type AlgebraicExecutionTrace struct {
	// Core tables
	Processor        ExecutionTable
	OperationalStack ExecutionTable
	RAM              ExecutionTable
	JumpStack        ExecutionTable
	Hash             ExecutionTable
	U32              ExecutionTable
	Program          ExecutionTable
	ProgramHash      ExecutionTable // TIP-0006: Program digest computation
	Cascade          ExecutionTable
	Lookup           ExecutionTable

	// Table linkages
	Linkages []TableLinkage

	// Metadata
	PaddedHeight int
	Field        *core.Field
}

// NewAlgebraicExecutionTrace creates a new AET
func NewAlgebraicExecutionTrace(field *core.Field) *AlgebraicExecutionTrace {
	return &AlgebraicExecutionTrace{
		Linkages: make([]TableLinkage, 0),
		Field:    field,
	}
}

// GetTable retrieves a specific table by ID
func (aet *AlgebraicExecutionTrace) GetTable(id TableID) (ExecutionTable, error) {
	switch id {
	case ProcessorTable:
		if aet.Processor == nil {
			return nil, fmt.Errorf("processor table not initialized")
		}
		return aet.Processor, nil
	case OperationalStackTable:
		if aet.OperationalStack == nil {
			return nil, fmt.Errorf("operational stack table not initialized")
		}
		return aet.OperationalStack, nil
	case RAMTable:
		if aet.RAM == nil {
			return nil, fmt.Errorf("RAM table not initialized")
		}
		return aet.RAM, nil
	case JumpStackTable:
		if aet.JumpStack == nil {
			return nil, fmt.Errorf("jump stack table not initialized")
		}
		return aet.JumpStack, nil
	case HashTable:
		if aet.Hash == nil {
			return nil, fmt.Errorf("hash table not initialized")
		}
		return aet.Hash, nil
	case U32Table:
		if aet.U32 == nil {
			return nil, fmt.Errorf("U32 table not initialized")
		}
		return aet.U32, nil
	case ProgramTable:
		if aet.Program == nil {
			return nil, fmt.Errorf("program table not initialized")
		}
		return aet.Program, nil
	case CascadeTable:
		if aet.Cascade == nil {
			return nil, fmt.Errorf("cascade table not initialized")
		}
		return aet.Cascade, nil
	case LookupTable:
		if aet.Lookup == nil {
			return nil, fmt.Errorf("lookup table not initialized")
		}
		return aet.Lookup, nil
	case ProgramHashTable:
		if aet.ProgramHash == nil {
			return nil, fmt.Errorf("program hash table not initialized")
		}
		return aet.ProgramHash, nil
	default:
		return nil, fmt.Errorf("invalid table ID: %d", id)
	}
}

// GetAllTables returns all non-nil tables
func (aet *AlgebraicExecutionTrace) GetAllTables() []ExecutionTable {
	tables := make([]ExecutionTable, 0, 10)

	if aet.Processor != nil {
		tables = append(tables, aet.Processor)
	}
	if aet.OperationalStack != nil {
		tables = append(tables, aet.OperationalStack)
	}
	if aet.RAM != nil {
		tables = append(tables, aet.RAM)
	}
	if aet.JumpStack != nil {
		tables = append(tables, aet.JumpStack)
	}
	if aet.Hash != nil {
		tables = append(tables, aet.Hash)
	}
	if aet.U32 != nil {
		tables = append(tables, aet.U32)
	}
	if aet.Program != nil {
		tables = append(tables, aet.Program)
	}
	if aet.ProgramHash != nil {
		tables = append(tables, aet.ProgramHash)
	}
	if aet.Cascade != nil {
		tables = append(tables, aet.Cascade)
	}
	if aet.Lookup != nil {
		tables = append(tables, aet.Lookup)
	}

	return tables
}

// ComputePaddedHeight determines the padded height for all tables
// Must be a power of 2 and at least as large as the tallest table
func (aet *AlgebraicExecutionTrace) ComputePaddedHeight() int {
	maxHeight := 0

	for _, table := range aet.GetAllTables() {
		if height := table.GetHeight(); height > maxHeight {
			maxHeight = height
		}
	}

	// Round up to next power of 2
	paddedHeight := 1
	for paddedHeight < maxHeight {
		paddedHeight <<= 1
	}

	aet.PaddedHeight = paddedHeight
	return paddedHeight
}

// PadAllTables pads all tables to the computed padded height
func (aet *AlgebraicExecutionTrace) PadAllTables() error {
	if aet.PaddedHeight == 0 {
		aet.ComputePaddedHeight()
	}

	for _, table := range aet.GetAllTables() {
		if err := table.Pad(aet.PaddedHeight); err != nil {
			return fmt.Errorf("failed to pad %s table: %w", table.GetID(), err)
		}
	}

	return nil
}

// AddLinkage adds a cross-table linkage
func (aet *AlgebraicExecutionTrace) AddLinkage(linkage TableLinkage) {
	aet.Linkages = append(aet.Linkages, linkage)
}

// GetLinkages returns all linkages of a specific type
func (aet *AlgebraicExecutionTrace) GetLinkages(linkType LinkageType) []TableLinkage {
	result := make([]TableLinkage, 0)

	for _, linkage := range aet.Linkages {
		if linkage.LinkType == linkType {
			result = append(result, linkage)
		}
	}

	return result
}

// Validate checks that the AET is well-formed
func (aet *AlgebraicExecutionTrace) Validate() error {
	// Check that at least Processor table exists
	if aet.Processor == nil {
		return fmt.Errorf("processor table is required")
	}

	// Check that all tables have compatible heights after padding
	if aet.PaddedHeight == 0 {
		aet.ComputePaddedHeight()
	}

	for _, table := range aet.GetAllTables() {
		if table.GetPaddedHeight() != aet.PaddedHeight {
			return fmt.Errorf("%s table has incorrect padded height: got %d, expected %d",
				table.GetID(), table.GetPaddedHeight(), aet.PaddedHeight)
		}
	}

	// Check that all linkages reference valid tables
	for i, linkage := range aet.Linkages {
		if _, err := aet.GetTable(linkage.FromTable); err != nil {
			return fmt.Errorf("linkage %d: invalid from table: %w", i, err)
		}
		if _, err := aet.GetTable(linkage.ToTable); err != nil {
			return fmt.Errorf("linkage %d: invalid to table: %w", i, err)
		}
	}

	return nil
}

// CreateStandardLinkages creates the standard linkages between tables
// Based on Triton VM's architecture (see specification/src/arithmetization.md)
func (aet *AlgebraicExecutionTrace) CreateStandardLinkages(challenges []field.Element) error {
	if len(challenges) < 10 {
		return fmt.Errorf("need at least 10 challenges for standard linkages")
	}

	// Permutation: Processor <-> Program (instruction lookup)
	aet.AddLinkage(TableLinkage{
		FromTable: ProcessorTable,
		ToTable:   ProgramTable,
		LinkType:  PermutationArgument,
		Challenge: challenges[0],
	})

	// Permutation: Processor <-> OperationalStack (stack consistency)
	aet.AddLinkage(TableLinkage{
		FromTable: ProcessorTable,
		ToTable:   OperationalStackTable,
		LinkType:  PermutationArgument,
		Challenge: challenges[1],
	})

	// Permutation: Processor <-> RAM (memory consistency)
	aet.AddLinkage(TableLinkage{
		FromTable: ProcessorTable,
		ToTable:   RAMTable,
		LinkType:  PermutationArgument,
		Challenge: challenges[2],
	})

	// Permutation: Processor <-> JumpStack (control flow)
	aet.AddLinkage(TableLinkage{
		FromTable: ProcessorTable,
		ToTable:   JumpStackTable,
		LinkType:  PermutationArgument,
		Challenge: challenges[3],
	})

	// Evaluation: Processor -> Hash (hash operations)
	aet.AddLinkage(TableLinkage{
		FromTable: ProcessorTable,
		ToTable:   HashTable,
		LinkType:  EvaluationArgument,
		Challenge: challenges[4],
	})

	// Lookup: Processor -> U32 (bitwise operations)
	aet.AddLinkage(TableLinkage{
		FromTable: ProcessorTable,
		ToTable:   U32Table,
		LinkType:  LookupArgument,
		Challenge: challenges[5],
	})

	// Lookup: U32 -> Cascade (lookup optimization)
	aet.AddLinkage(TableLinkage{
		FromTable: U32Table,
		ToTable:   CascadeTable,
		LinkType:  LookupArgument,
		Challenge: challenges[6],
	})

	// Lookup: Cascade -> Lookup (final lookup)
	aet.AddLinkage(TableLinkage{
		FromTable: CascadeTable,
		ToTable:   LookupTable,
		LinkType:  LookupArgument,
		Challenge: challenges[7],
	})

	// Contiguity: RAM memory regions
	aet.AddLinkage(TableLinkage{
		FromTable: RAMTable,
		ToTable:   RAMTable,
		LinkType:  ContiguityArgument,
		Challenge: challenges[8],
	})

	// Evaluation: Public I/O
	aet.AddLinkage(TableLinkage{
		FromTable: ProcessorTable,
		ToTable:   ProcessorTable, // Self-reference for public I/O
		LinkType:  EvaluationArgument,
		Challenge: challenges[9],
	})

	return nil
}

// GetTableStatistics returns statistics about the AET
func (aet *AlgebraicExecutionTrace) GetTableStatistics() map[TableID]TableStats {
	stats := make(map[TableID]TableStats)

	for _, table := range aet.GetAllTables() {
		mainCols := table.GetMainColumns()
		auxCols := table.GetAuxiliaryColumns()

		stats[table.GetID()] = TableStats{
			Height:           table.GetHeight(),
			PaddedHeight:     table.GetPaddedHeight(),
			MainColumns:      len(mainCols),
			AuxiliaryColumns: len(auxCols),
		}
	}

	return stats
}

// TableStats holds statistics for a single table
type TableStats struct {
	Height           int
	PaddedHeight     int
	MainColumns      int
	AuxiliaryColumns int
}
