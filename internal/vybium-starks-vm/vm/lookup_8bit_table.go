// Package vm implements TIP-0005 8-bit Lookup Table
package vm

import (
	"fmt"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
)

// Lookup8BitTable implements the 8-bit lookup table for TIP-0005 Tip5 hash
//
// The lookup table computes L(x) = (x+1)^3 - 1 for x in {0, 1, ..., 255}
// This is used as part of the split-and-lookup S-box in Tip5 hash function
//
// Main Columns (4):
//   - LookIn: Input value (0..255)
//   - LookOut: Output value L(x)
//   - LookupMultiplicity: Number of times this row is queried
//   - IsPadding: 1 if padding row, 0 otherwise
//
// Auxiliary Columns (2):
//   - CascadeLogDerivative: Running log derivative for cascade table lookups
//   - PublicEvaluation: Running evaluation for public I/O
type Lookup8BitTable struct {
	field *core.Field

	// Main columns (BField elements)
	lookIn             []*core.FieldElement // Input values 0..255
	lookOut            []*core.FieldElement // Output values L(x) = (x+1)^3 - 1
	lookupMultiplicity []*core.FieldElement // Multiplicity of lookups
	isPadding          []*core.FieldElement // Padding indicator

	// Auxiliary columns (XField elements)
	cascadeLogDerivative []*core.FieldElement // Running log derivative (cascade)
	publicEvaluation     []*core.FieldElement // Running evaluation (public I/O)

	height       int
	paddedHeight int
}

// NewLookup8BitTable creates a new 8-bit Lookup Table
func NewLookup8BitTable(field *core.Field) *Lookup8BitTable {
	return &Lookup8BitTable{
		field:                field,
		lookIn:               make([]*core.FieldElement, 0),
		lookOut:              make([]*core.FieldElement, 0),
		lookupMultiplicity:   make([]*core.FieldElement, 0),
		isPadding:            make([]*core.FieldElement, 0),
		cascadeLogDerivative: make([]*core.FieldElement, 0),
		publicEvaluation:     make([]*core.FieldElement, 0),
		height:               0,
		paddedHeight:         0,
	}
}

// GetID returns the table's identifier
func (lt *Lookup8BitTable) GetID() TableID {
	return LookupTable
}

// GetHeight returns the current table height
func (lt *Lookup8BitTable) GetHeight() int {
	return lt.height
}

// GetPaddedHeight returns the padded table height
func (lt *Lookup8BitTable) GetPaddedHeight() int {
	if lt.paddedHeight > 0 {
		return lt.paddedHeight
	}
	return lt.height
}

// GetMainColumns returns main columns
func (lt *Lookup8BitTable) GetMainColumns() [][]*core.FieldElement {
	return [][]*core.FieldElement{
		lt.lookIn,
		lt.lookOut,
		lt.lookupMultiplicity,
		lt.isPadding,
	}
}

// GetAuxiliaryColumns returns auxiliary columns
func (lt *Lookup8BitTable) GetAuxiliaryColumns() [][]*core.FieldElement {
	return [][]*core.FieldElement{
		lt.cascadeLogDerivative,
		lt.publicEvaluation,
	}
}

// ComputeLookup8Bit computes the 8-bit lookup function: L(x) = (x+1)^3 - 1
// This is the S-box component used in Tip5 hash function (TIP-0005)
//
// The function maps F_{2^8+1} → F_{2^8+1} where elements are represented
// as field elements in the larger prime field.
func ComputeLookup8Bit(field *core.Field, x byte) *core.FieldElement {
	// Convert byte to field element
	xElem := field.NewElementFromInt64(int64(x))

	// Compute (x + 1)
	xPlusOne := xElem.Add(field.One())

	// Compute (x + 1)^3
	xPlusOneCubed := xPlusOne.Mul(xPlusOne).Mul(xPlusOne)

	// Compute (x + 1)^3 - 1
	result := xPlusOneCubed.Sub(field.One())

	return result
}

// GenerateLookupTable generates all 256 entries of the 8-bit lookup table
// Returns a slice of 256 field elements representing L(0), L(1), ..., L(255)
func GenerateLookupTable(field *core.Field) [256]*core.FieldElement {
	var table [256]*core.FieldElement
	for i := 0; i < 256; i++ {
		table[i] = ComputeLookup8Bit(field, byte(i))
	}
	return table
}

// Fill populates the lookup table with all 256 possible input-output pairs
// Multiplicities are provided from the AET (Algebraic Execution Trace)
func (lt *Lookup8BitTable) Fill(multiplicities [256]uint64) error {
	// Table always has exactly 256 rows (one for each 8-bit value)
	const tableSize = 256

	lt.lookIn = make([]*core.FieldElement, tableSize)
	lt.lookOut = make([]*core.FieldElement, tableSize)
	lt.lookupMultiplicity = make([]*core.FieldElement, tableSize)
	lt.isPadding = make([]*core.FieldElement, tableSize)

	// Generate all 256 lookup pairs
	lookupTable := GenerateLookupTable(lt.field)

	for i := 0; i < tableSize; i++ {
		lt.lookIn[i] = lt.field.NewElementFromInt64(int64(i))
		lt.lookOut[i] = lookupTable[i]
		lt.lookupMultiplicity[i] = lt.field.NewElementFromUint64(multiplicities[i])
		lt.isPadding[i] = lt.field.Zero() // No padding rows in lookup table
	}

	lt.height = tableSize
	return nil
}

// Pad extends the table to the target height with padding rows
func (lt *Lookup8BitTable) Pad(targetHeight int) error {
	if targetHeight < lt.height {
		return fmt.Errorf("target height %d is less than current height %d", targetHeight, lt.height)
	}

	if lt.height == 0 {
		return fmt.Errorf("cannot pad empty table")
	}

	// The lookup table has exactly 256 entries, but we may need to pad beyond that
	// for power-of-2 requirements in the proof system
	lastIdx := lt.height - 1
	paddingRows := targetHeight - lt.height

	for i := 0; i < paddingRows; i++ {
		// Pad with last row values, mark as padding
		lt.lookIn = append(lt.lookIn, lt.lookIn[lastIdx])
		lt.lookOut = append(lt.lookOut, lt.lookOut[lastIdx])
		lt.lookupMultiplicity = append(lt.lookupMultiplicity, lt.field.Zero())
		lt.isPadding = append(lt.isPadding, lt.field.One()) // Mark as padding

		// Pad auxiliary columns if they exist
		if len(lt.cascadeLogDerivative) > 0 {
			lt.cascadeLogDerivative = append(lt.cascadeLogDerivative, lt.cascadeLogDerivative[lastIdx])
		}
		if len(lt.publicEvaluation) > 0 {
			lt.publicEvaluation = append(lt.publicEvaluation, lt.publicEvaluation[lastIdx])
		}
	}

	lt.paddedHeight = targetHeight
	return nil
}

// ExtendWithChallenges populates auxiliary columns using Fiat-Shamir challenges
// This implements the log-derivative accumulation for the lookup argument
func (lt *Lookup8BitTable) ExtendWithChallenges(challenges *FiatShamirChallenges) error {
	if lt.height == 0 {
		return fmt.Errorf("cannot extend empty table")
	}

	rows := lt.GetPaddedHeight()
	lt.cascadeLogDerivative = make([]*core.FieldElement, rows)
	lt.publicEvaluation = make([]*core.FieldElement, rows)

	// Initial values for running accumulators
	cascadeLogDeriv := lt.field.Zero()
	publicEval := lt.field.Zero()

	for i := 0; i < rows; i++ {
		// Skip padding rows for accumulation
		if lt.isPadding[i].IsZero() {
			// Compute compressed row for cascade lookup
			// compressed_row = look_in * input_weight + look_out * output_weight
			compressedRow := lt.lookIn[i].Mul(challenges.LookupInputWeight).
				Add(lt.lookOut[i].Mul(challenges.LookupOutputWeight))

			// Update cascade log derivative
			// log_deriv += multiplicity / (indeterminate - compressed_row)
			denominator := challenges.CascadeIndeterminate.Sub(compressedRow)
			if denominator.IsZero() {
				return fmt.Errorf("division by zero in log derivative at row %d", i)
			}

			denominatorInv, err := denominator.Inv()
			if err != nil {
				return fmt.Errorf("failed to invert denominator at row %d: %w", i, err)
			}

			update := lt.lookupMultiplicity[i].Mul(denominatorInv)
			cascadeLogDeriv = cascadeLogDeriv.Add(update)

			// Update public evaluation
			// eval = eval * indeterminate + look_out
			publicEval = publicEval.Mul(challenges.PublicIndeterminate).
				Add(lt.lookOut[i])
		}

		lt.cascadeLogDerivative[i] = cascadeLogDeriv
		lt.publicEvaluation[i] = publicEval
	}

	return nil
}

// FiatShamirChallenges contains the challenges needed for TIP-0005 lookups
type FiatShamirChallenges struct {
	// Challenges for cascade table
	CascadeIndeterminate *core.FieldElement
	LookupInputWeight    *core.FieldElement
	LookupOutputWeight   *core.FieldElement

	// Challenge for public I/O evaluation
	PublicIndeterminate *core.FieldElement
}

// Verify checks that the lookup table is correctly constructed
func (lt *Lookup8BitTable) Verify() error {
	if lt.height != 256 {
		return fmt.Errorf("lookup table must have exactly 256 rows, got %d", lt.height)
	}

	// Verify all input-output pairs match the lookup function
	for i := 0; i < 256; i++ {
		expectedOut := ComputeLookup8Bit(lt.field, byte(i))
		if !lt.lookOut[i].Equal(expectedOut) {
			return fmt.Errorf("incorrect lookup at index %d: expected %s, got %s",
				i, expectedOut.String(), lt.lookOut[i].String())
		}
	}

	return nil
}

// Lookup16Bit performs a 16-bit lookup by composing two 8-bit lookups
// Input: 16-bit value (0..65535)
// Output: Corresponding output from composed L(hi)||L(lo) where L is the 8-bit lookup
func Lookup16Bit(field *core.Field, toLookUp uint16) *core.FieldElement {
	// Split into high and low bytes
	toLookUpLo := byte(toLookUp & 0xff)
	toLookUpHi := byte((toLookUp >> 8) & 0xff)

	// Lookup each byte
	lookedUpLo := ComputeLookup8Bit(field, toLookUpLo)
	lookedUpHi := ComputeLookup8Bit(field, toLookUpHi)

	// Combine: result = 256 * hi + lo
	shift := field.NewElementFromInt64(256)
	result := lookedUpHi.Mul(shift).Add(lookedUpLo)

	return result
}
