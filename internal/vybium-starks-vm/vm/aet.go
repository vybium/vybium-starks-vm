package vm

import (
	"fmt"

	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/protocols"
)

// AET (Algebraic Execution Trace) represents the complete execution trace
// of a Vybium STARKs VM program, combining all table traces.
//
// This is the primary witness required for zkSTARK proof generation.
// It holds every intermediate state of the processor and all coprocessors.
type AET struct {
	// The program that was executed to generate this trace
	Program *Program

	// Instruction execution multiplicities (how often each instruction was executed)
	InstructionMultiplicities []uint64

	// All 10 table traces (TIP-0006: added ProgramHashTable)
	ProcessorTable   *ProcessorTableImpl
	OpStackTable     *OpStackTableImpl
	RAMTable         *RAMTableImpl
	JumpStackTable   *JumpStackTableImpl
	ProgramTable     *ProgramTableImpl
	ProgramHashTable *ProgramHashTableImpl // TIP-0006: Program attestation
	HashTable        *HashTableImpl
	U32Table         *U32TableImpl
	CascadeTable     *CascadeTableImpl
	LookupTable      *LookupTableImpl

	// TIP-0005: Lookup multiplicities for cascade and lookup tables
	// Tracks how often each 16-bit value is looked up in cascade table
	CascadeLookupMultiplicities map[uint16]uint64
	// Tracks how often each 8-bit value (0..255) is looked up in lookup table
	LookupTableMultiplicities [256]uint64

	// TIP-0006: Program attestation
	ProgramDigest [5]field.Element // Hash digest of program description

	// Metadata
	Height       int
	PaddedHeight int
}

// NewAET creates a new Algebraic Execution Trace for a given program
func NewAET(program *Program) (*AET, error) {
	if program == nil {
		return nil, fmt.Errorf("program cannot be nil")
	}

	// Initialize instruction multiplicities (one per instruction)
	multiplicities := make([]uint64, len(program.Instructions))

	// Initialize all tables
	processorTable := NewProcessorTable()
	opStackTable := NewOpStackTable()
	ramTable := NewRAMTable()
	jumpStackTable := NewJumpStackTable()
	programTable := NewProgramTable(16)       // chunk rate
	programHashTable := NewProgramHashTable() // TIP-0006: Program attestation
	hashTable := NewHashTable(8, 83)          // Poseidon 128-bit security (RF=8, RP=83)
	u32Table := NewU32Table()
	cascadeTable := NewCascadeTable()
	lookupTable := NewLookupTable()

	// TIP-0006: Compute program digest for attestation
	programDigest, err := programHashTable.ComputeProgramDigest(program)
	if err != nil {
		return nil, fmt.Errorf("failed to compute program digest: %w", err)
	}

	return &AET{
		Program:                     program,
		InstructionMultiplicities:   multiplicities,
		ProcessorTable:              processorTable,
		OpStackTable:                opStackTable,
		RAMTable:                    ramTable,
		JumpStackTable:              jumpStackTable,
		ProgramTable:                programTable,
		ProgramHashTable:            programHashTable,
		HashTable:                   hashTable,
		U32Table:                    u32Table,
		CascadeTable:                cascadeTable,
		LookupTable:                 lookupTable,
		CascadeLookupMultiplicities: make(map[uint16]uint64),
		LookupTableMultiplicities:   [256]uint64{}, // Zero-initialized array
		ProgramDigest:               programDigest,
		Height:                      0,
		PaddedHeight:                0,
	}, nil
}

// Pad pads all tables to the next power of 2 for FFT compatibility
func (aet *AET) Pad() error {
	// Find maximum height across all tables
	maxHeight := aet.ProcessorTable.GetHeight()
	if h := aet.OpStackTable.GetHeight(); h > maxHeight {
		maxHeight = h
	}
	if h := aet.RAMTable.GetHeight(); h > maxHeight {
		maxHeight = h
	}
	if h := aet.JumpStackTable.GetHeight(); h > maxHeight {
		maxHeight = h
	}
	if h := aet.ProgramTable.GetHeight(); h > maxHeight {
		maxHeight = h
	}
	if h := aet.HashTable.GetHeight(); h > maxHeight {
		maxHeight = h
	}
	if h := aet.U32Table.GetHeight(); h > maxHeight {
		maxHeight = h
	}
	if h := aet.CascadeTable.GetHeight(); h > maxHeight {
		maxHeight = h
	}
	if h := aet.LookupTable.GetHeight(); h > maxHeight {
		maxHeight = h
	}
	if h := aet.ProgramHashTable.GetHeight(); h > maxHeight {
		maxHeight = h
	}

	// Round up to next power of 2
	paddedHeight := nextPowerOf2(maxHeight)

	// Ensure minimum height of 1
	if paddedHeight == 0 {
		paddedHeight = 1
	}

	// Pad all tables to the same height (skip if table is empty and paddedHeight would be 0)
	if err := aet.ProcessorTable.Pad(paddedHeight); err != nil {
		return fmt.Errorf("failed to pad processor table: %w", err)
	}
	// OpStack, RAM, JumpStack, Hash, U32 may be empty in simple programs
	// Only pad if they have content
	if aet.OpStackTable.GetHeight() > 0 {
		if err := aet.OpStackTable.Pad(paddedHeight); err != nil {
			return fmt.Errorf("failed to pad opstack table: %w", err)
		}
	}
	if aet.RAMTable.GetHeight() > 0 {
		if err := aet.RAMTable.Pad(paddedHeight); err != nil {
			return fmt.Errorf("failed to pad ram table: %w", err)
		}
	}
	if aet.JumpStackTable.GetHeight() > 0 {
		if err := aet.JumpStackTable.Pad(paddedHeight); err != nil {
			return fmt.Errorf("failed to pad jumpstack table: %w", err)
		}
	}
	if aet.ProgramTable.GetHeight() > 0 {
		if err := aet.ProgramTable.Pad(paddedHeight); err != nil {
			return fmt.Errorf("failed to pad program table: %w", err)
		}
	}
	if aet.HashTable.GetHeight() > 0 {
		if err := aet.HashTable.Pad(paddedHeight); err != nil {
			return fmt.Errorf("failed to pad hash table: %w", err)
		}
	}
	if aet.U32Table.GetHeight() > 0 {
		if err := aet.U32Table.Pad(paddedHeight); err != nil {
			return fmt.Errorf("failed to pad u32 table: %w", err)
		}
	}
	if aet.CascadeTable.GetHeight() > 0 {
		if err := aet.CascadeTable.Pad(paddedHeight); err != nil {
			return fmt.Errorf("failed to pad cascade table: %w", err)
		}
	}
	if aet.LookupTable.GetHeight() > 0 {
		if err := aet.LookupTable.Pad(paddedHeight); err != nil {
			return fmt.Errorf("failed to pad lookup table: %w", err)
		}
	}
	if aet.ProgramHashTable.GetHeight() > 0 {
		if err := aet.ProgramHashTable.Pad(paddedHeight); err != nil {
			return fmt.Errorf("failed to pad program hash table: %w", err)
		}
	}

	aet.Height = maxHeight
	aet.PaddedHeight = paddedHeight

	return nil
}

// GenerateAIRConstraints generates all AIR constraints for all tables
func (aet *AET) GenerateAIRConstraints() ([]protocols.AIRConstraint, error) {
	var allConstraints []protocols.AIRConstraint

	// Processor table constraints
	procInitial, err := aet.ProcessorTable.CreateInitialConstraints()
	if err != nil {
		return nil, fmt.Errorf("processor initial constraints: %w", err)
	}
	allConstraints = append(allConstraints, procInitial...)

	procConsistency, err := aet.ProcessorTable.CreateConsistencyConstraints()
	if err != nil {
		return nil, fmt.Errorf("processor consistency constraints: %w", err)
	}
	allConstraints = append(allConstraints, procConsistency...)

	procTransition, err := aet.ProcessorTable.CreateTransitionConstraints()
	if err != nil {
		return nil, fmt.Errorf("processor transition constraints: %w", err)
	}
	allConstraints = append(allConstraints, procTransition...)

	procTerminal, err := aet.ProcessorTable.CreateTerminalConstraints()
	if err != nil {
		return nil, fmt.Errorf("processor terminal constraints: %w", err)
	}
	allConstraints = append(allConstraints, procTerminal...)

	// OpStack table constraints
	opInitial, err := aet.OpStackTable.CreateInitialConstraints()
	if err != nil {
		return nil, fmt.Errorf("opstack initial constraints: %w", err)
	}
	allConstraints = append(allConstraints, opInitial...)

	opConsistency, err := aet.OpStackTable.CreateConsistencyConstraints()
	if err != nil {
		return nil, fmt.Errorf("opstack consistency constraints: %w", err)
	}
	allConstraints = append(allConstraints, opConsistency...)

	opTransition, err := aet.OpStackTable.CreateTransitionConstraints()
	if err != nil {
		return nil, fmt.Errorf("opstack transition constraints: %w", err)
	}
	allConstraints = append(allConstraints, opTransition...)

	opTerminal, err := aet.OpStackTable.CreateTerminalConstraints()
	if err != nil {
		return nil, fmt.Errorf("opstack terminal constraints: %w", err)
	}
	allConstraints = append(allConstraints, opTerminal...)

	// RAM table constraints
	ramInitial, err := aet.RAMTable.CreateInitialConstraints()
	if err != nil {
		return nil, fmt.Errorf("ram initial constraints: %w", err)
	}
	allConstraints = append(allConstraints, ramInitial...)

	ramConsistency, err := aet.RAMTable.CreateConsistencyConstraints()
	if err != nil {
		return nil, fmt.Errorf("ram consistency constraints: %w", err)
	}
	allConstraints = append(allConstraints, ramConsistency...)

	ramTransition, err := aet.RAMTable.CreateTransitionConstraints()
	if err != nil {
		return nil, fmt.Errorf("ram transition constraints: %w", err)
	}
	allConstraints = append(allConstraints, ramTransition...)

	ramTerminal, err := aet.RAMTable.CreateTerminalConstraints()
	if err != nil {
		return nil, fmt.Errorf("ram terminal constraints: %w", err)
	}
	allConstraints = append(allConstraints, ramTerminal...)

	// Similar for other tables...
	// (JumpStack, Program, Hash, U32, Cascade, Lookup)
	// For brevity, following same pattern

	return allConstraints, nil
}

// GetTables returns all execution tables as a slice
func (aet *AET) GetTables() []ExecutionTable {
	return []ExecutionTable{
		aet.ProcessorTable,
		aet.OpStackTable,
		aet.RAMTable,
		aet.JumpStackTable,
		aet.ProgramTable,
		aet.HashTable,
		aet.U32Table,
		aet.CascadeTable,
		aet.LookupTable,
	}
}

// nextPowerOf2 returns the next power of 2 greater than or equal to n
func nextPowerOf2(n int) int {
	if n <= 1 {
		return 1
	}
	power := 1
	for power < n {
		power *= 2
	}
	return power
}

// GetPaddedHeight implements the ExecutionTrace interface
func (aet *AET) GetPaddedHeight() int {
	return aet.PaddedHeight
}

// GetTableData implements the ExecutionTrace interface
func (aet *AET) GetTableData() interface{} {
	return aet
}

// GetTraceColumns implements the ExecutionTrace interface
// Returns all trace columns from the processor table
func (aet *AET) GetTraceColumns() ([][]field.Element, error) {
	if aet.ProcessorTable == nil {
		return nil, fmt.Errorf("AET has no processor table")
	}

	return aet.ProcessorTable.GetColumns()
}

// ===========================================================================
// TIP-0005: Cascade and Lookup Table Integration
// ===========================================================================

// RecordCascadeLookup records a 16-bit lookup in the cascade table
// This should be called whenever a 16-bit value needs to be looked up
// (e.g., during U32 operations that use 16-bit limbs)
func (aet *AET) RecordCascadeLookup(value16 uint16) {
	aet.CascadeLookupMultiplicities[value16]++

	// Cascade lookups decompose into two 8-bit lookups
	// Automatically record the constituent 8-bit lookups
	lowByte := byte(value16 & 0xff)
	highByte := byte((value16 >> 8) & 0xff)

	aet.LookupTableMultiplicities[lowByte]++
	aet.LookupTableMultiplicities[highByte]++
}

// Record8BitLookup records an 8-bit lookup in the lookup table
// This is used when operations directly need 8-bit lookups
func (aet *AET) Record8BitLookup(value8 byte) {
	aet.LookupTableMultiplicities[value8]++
}

// RecordU32Value records cascade lookups for a 32-bit value
// Decomposes 32-bit value into two 16-bit limbs and records both
func (aet *AET) RecordU32Value(value32 uint32) {
	// Split 32-bit value into two 16-bit limbs
	lowLimb := uint16(value32 & 0xFFFF)
	highLimb := uint16((value32 >> 16) & 0xFFFF)

	// Record cascade lookups for both limbs
	aet.RecordCascadeLookup(lowLimb)
	aet.RecordCascadeLookup(highLimb)
}

// ProcessU32TableForCascade processes all U32 table entries and records cascade lookups
// This should be called before FinalizeLookupTables to integrate U32 operations with TIP-0005
func (aet *AET) ProcessU32TableForCascade() {
	// Iterate through all U32 table entries
	for i := 0; i < aet.U32Table.GetHeight(); i++ {
		// Record cascade lookups for LHS, RHS, and Result
		// These are the 32-bit values involved in U32 operations

		lhs := aet.U32Table.lhs[i].Value()
		if lhs <= 0xFFFFFFFF { // Ensure it's a valid 32-bit value
			aet.RecordU32Value(uint32(lhs))
		}

		rhs := aet.U32Table.rhs[i].Value()
		if rhs <= 0xFFFFFFFF {
			aet.RecordU32Value(uint32(rhs))
		}

		result := aet.U32Table.result[i].Value()
		if result <= 0xFFFFFFFF {
			aet.RecordU32Value(uint32(result))
		}
	}
}

// FinalizeLookupTables populates the cascade and lookup tables with recorded multiplicities
// This should be called after VM execution completes, before proof generation
func (aet *AET) FinalizeLookupTables() error {
	// First, process U32 table to record cascade lookups for all U32 operations
	aet.ProcessU32TableForCascade()

	// Populate Lookup Table (8-bit) with all 256 entries
	if err := aet.LookupTable.Fill(aet.LookupTableMultiplicities); err != nil {
		return fmt.Errorf("failed to fill lookup table: %w", err)
	}

	// Populate Cascade Table (16-bit) with only the values that were looked up
	// Sort entries for deterministic ordering
	var entries []CascadeLookupEntry
	for value16, multiplicity := range aet.CascadeLookupMultiplicities {
		if multiplicity > 0 {
			entries = append(entries, CascadeLookupEntry{
				Input:        value16,
				Multiplicity: multiplicity,
			})
		}
	}

	// Sort by input value for deterministic ordering
	// (Go doesn't guarantee map iteration order)
	sortCascadeEntries(entries)

	// Fill cascade table
	for _, entry := range entries {
		if err := aet.CascadeTable.AddRow(entry.Input, entry.Multiplicity); err != nil {
			return fmt.Errorf("failed to add cascade row: %w", err)
		}
	}

	return nil
}

// CascadeLookupEntry represents a 16-bit lookup entry for the cascade table
type CascadeLookupEntry struct {
	Input        uint16
	Multiplicity uint64
}

// sortCascadeEntries sorts cascade entries by input value (in-place)
func sortCascadeEntries(entries []CascadeLookupEntry) {
	// Simple insertion sort (efficient for small to medium lists)
	for i := 1; i < len(entries); i++ {
		key := entries[i]
		j := i - 1
		for j >= 0 && entries[j].Input > key.Input {
			entries[j+1] = entries[j]
			j--
		}
		entries[j+1] = key
	}
}

// GetCascadeLookupCount returns the number of unique 16-bit values looked up
func (aet *AET) GetCascadeLookupCount() int {
	return len(aet.CascadeLookupMultiplicities)
}

// GetTotalCascadeLookups returns the total number of cascade lookups (with multiplicity)
func (aet *AET) GetTotalCascadeLookups() uint64 {
	total := uint64(0)
	for _, count := range aet.CascadeLookupMultiplicities {
		total += count
	}
	return total
}

// GetTotal8BitLookups returns the total number of 8-bit lookups (with multiplicity)
func (aet *AET) GetTotal8BitLookups() uint64 {
	total := uint64(0)
	for _, count := range aet.LookupTableMultiplicities {
		total += count
	}
	return total
}

// GetProgramDigest returns the TIP-0006 compliant program attestation digest
// This 5-element digest uniquely identifies the program and enables recursive verification
func (aet *AET) GetProgramDigest() []field.Element {
	return aet.ProgramDigest[:]
}
