// Package vm provides the Vybium STARKs VM instruction set architecture
package vm

import (
	"fmt"

	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
)

// Instruction represents a Vybium STARKs VM instruction
// Vybium STARKs VM follows Triton VM's architecture with Poseidon-optimized hash operations
type Instruction uint32

// Vybium STARKs VM Instruction Set Architecture (ISA)
// Based on Triton VM's 47-instruction ISA with optimizations for Poseidon
const (
	// ========== Stack Manipulation (7 instructions) ==========

	// Pop removes n elements from the stack
	Pop Instruction = 3

	// Push pushes a value onto the stack
	Push Instruction = 1

	// Divine non-deterministically pushes n elements (prover-supplied)
	Divine Instruction = 9

	// Pick copies the element at stack[i] to the top
	Pick Instruction = 17

	// Place moves the top element to stack[i]
	Place Instruction = 25

	// Dup duplicates the element at stack[i] to the top
	Dup Instruction = 33

	// Swap swaps the top element with stack[i]
	Swap Instruction = 41

	// ========== Control Flow (7 instructions) ==========

	// Halt terminates program execution
	Halt Instruction = 0

	// Nop does nothing (no operation)
	Nop Instruction = 8

	// Skiz skips next instruction if top of stack is zero
	Skiz Instruction = 2

	// Call calls a function at the given address
	Call Instruction = 49

	// Return returns from a function call
	Return Instruction = 16

	// Recurse calls the current function recursively
	Recurse Instruction = 24

	// RecurseOrReturn recurses if JSP > 0, otherwise returns
	RecurseOrReturn Instruction = 32

	// Assert asserts that the top of stack is 1, halts if not
	Assert Instruction = 10

	// ========== Memory Access (2 instructions) ==========

	// ReadMem reads n words from RAM at address on top of stack
	ReadMem Instruction = 57

	// WriteMem writes n words to RAM at address on top of stack
	WriteMem Instruction = 11

	// ========== Hashing (6 instructions) ==========
	// Optimized for Poseidon instead of Tip5

	// Hash computes Poseidon hash of stack[0..10]
	Hash Instruction = 18

	// AssertVector asserts stack[0..5] equals stack[5..10]
	AssertVector Instruction = 26

	// SpongeInit initializes Poseidon sponge state
	SpongeInit Instruction = 40

	// SpongeAbsorb absorbs 10 elements from stack into sponge
	SpongeAbsorb Instruction = 34

	// SpongeAbsorbMem absorbs n elements from RAM into sponge
	SpongeAbsorbMem Instruction = 48

	// SpongeSqueeze squeezes 10 elements from sponge onto stack
	SpongeSqueeze Instruction = 56

	// ========== Base Field Arithmetic (5 instructions) ==========

	// Add adds top two stack elements
	Add Instruction = 42

	// AddI adds immediate value to top of stack
	AddI Instruction = 65

	// Mul multiplies top two stack elements
	Mul Instruction = 50

	// Invert inverts top of stack (multiplicative inverse)
	Invert Instruction = 64

	// Eq checks equality of top two stack elements (1 if equal, 0 otherwise)
	Eq Instruction = 58

	// ========== Bitwise Arithmetic (8 instructions) ==========
	// These use U32 coprocessor for efficient 32-bit operations

	// Split splits top element into high and low 32-bit parts
	Split Instruction = 4

	// Lt checks if second element < top element (unsigned 32-bit)
	Lt Instruction = 6

	// And performs bitwise AND on top two stack elements
	And Instruction = 14

	// Xor performs bitwise XOR on top two stack elements
	Xor Instruction = 22

	// Log2Floor computes floor(log2(top))
	Log2Floor Instruction = 12

	// Pow raises second element to power of top element
	Pow Instruction = 30

	// DivMod computes quotient and remainder of division
	DivMod Instruction = 20

	// PopCount counts the number of 1 bits in top element
	PopCount Instruction = 28

	// ========== Extension Field Arithmetic (4 instructions) ==========

	// XxAdd adds two extension field elements (3 elements each)
	XxAdd Instruction = 66

	// XxMul multiplies two extension field elements
	XxMul Instruction = 74

	// XInvert inverts an extension field element
	XInvert Instruction = 72

	// XbMul multiplies extension field element by base field element
	XbMul Instruction = 82

	// ========== I/O Operations (2 instructions) ==========

	// ReadIo reads n elements from standard input
	ReadIo Instruction = 73

	// WriteIo writes n elements to standard output
	WriteIo Instruction = 19

	// ========== Advanced Operations (4 instructions) ==========

	// MerkleStep verifies one Merkle tree step (uses Poseidon!)
	MerkleStep Instruction = 36

	// MerkleStepMem verifies Merkle step with data from RAM
	MerkleStepMem Instruction = 44

	// XxDotStep computes one step of extension field dot product
	XxDotStep Instruction = 80

	// XbDotStep computes one step of base-extension dot product
	XbDotStep Instruction = 88

	// ========== Permutation Checks (3 instructions - TIP-0007) ==========

	// PushPerm pushes top 5 stack elements into permutation accumulator
	// Computes inner product p = Σ(st_i · a_i) with Fiat-Shamir weights
	// Multiplies (α - p) into permrp: permrp' = permrp · (α - p)
	PushPerm Instruction = 90

	// PopPerm pops from permutation accumulator
	// Computes inner product p = Σ(st_i · a_i) with Fiat-Shamir weights
	// Divides (α - p) out of permrp: permrp' = permrp / (α - p)
	PopPerm Instruction = 91

	// AssertPerm asserts that permutation accumulator equals 1
	// Verifies that pushed and popped elements are equal up to permutation
	AssertPerm Instruction = 92
)

// InstructionCount is the total number of instructions in Vybium STARKs VM ISA
const InstructionCount = 50

// InstructionInfo provides metadata about an instruction
type InstructionInfo struct {
	Opcode      Instruction
	Name        string
	Description string
	Size        int  // Number of words (1 or 2)
	StackEffect int  // Net effect on stack depth (positive = push, negative = pop)
	HasArg      bool // Whether instruction takes an argument
}

// AllInstructions returns information about all Vybium STARKs VM instructions
var AllInstructions = map[Instruction]InstructionInfo{
	// Stack Manipulation
	Pop:    {Pop, "pop", "Remove n elements from stack", 2, -1, true},
	Push:   {Push, "push", "Push value onto stack", 2, 1, true},
	Divine: {Divine, "divine", "Non-deterministically push n elements", 2, 1, true},
	Pick:   {Pick, "pick", "Copy stack[i] to top", 2, 1, true},
	Place:  {Place, "place", "Move top to stack[i]", 2, -1, true},
	Dup:    {Dup, "dup", "Duplicate stack[i] to top", 2, 1, true},
	Swap:   {Swap, "swap", "Swap top with stack[i]", 2, 0, true},

	// Control Flow
	Halt:            {Halt, "halt", "Terminate execution", 1, 0, false},
	Nop:             {Nop, "nop", "No operation", 1, 0, false},
	Skiz:            {Skiz, "skiz", "Skip if zero", 1, -1, false},
	Call:            {Call, "call", "Call function", 2, 0, true},
	Return:          {Return, "return", "Return from function", 1, 0, false},
	Recurse:         {Recurse, "recurse", "Recurse into current function", 1, 0, false},
	RecurseOrReturn: {RecurseOrReturn, "recurse_or_return", "Recurse or return based on JSP", 1, 0, false},
	Assert:          {Assert, "assert", "Assert top is 1", 1, -1, false},

	// Memory Access
	ReadMem:  {ReadMem, "read_mem", "Read n words from RAM", 2, 1, true},
	WriteMem: {WriteMem, "write_mem", "Write n words to RAM", 2, -2, true},

	// Hashing (Poseidon-optimized)
	Hash:            {Hash, "hash", "Poseidon hash of stack[0..10]", 1, -5, false},
	AssertVector:    {AssertVector, "assert_vector", "Assert vector equality", 1, -10, false},
	SpongeInit:      {SpongeInit, "sponge_init", "Initialize Poseidon sponge", 1, 0, false},
	SpongeAbsorb:    {SpongeAbsorb, "sponge_absorb", "Absorb into sponge", 1, -10, false},
	SpongeAbsorbMem: {SpongeAbsorbMem, "sponge_absorb_mem", "Absorb from RAM", 1, 0, false},
	SpongeSqueeze:   {SpongeSqueeze, "sponge_squeeze", "Squeeze from sponge", 1, 10, false},

	// Base Field Arithmetic
	Add:    {Add, "add", "Add top two elements", 1, -1, false},
	AddI:   {AddI, "addi", "Add immediate", 2, 0, true},
	Mul:    {Mul, "mul", "Multiply top two elements", 1, -1, false},
	Invert: {Invert, "invert", "Multiplicative inverse", 1, 0, false},
	Eq:     {Eq, "eq", "Check equality", 1, -1, false},

	// Bitwise Arithmetic (U32 coprocessor)
	Split:     {Split, "split", "Split into high/low 32-bit", 1, 1, false},
	Lt:        {Lt, "lt", "Less than (unsigned)", 1, -1, false},
	And:       {And, "and", "Bitwise AND", 1, -1, false},
	Xor:       {Xor, "xor", "Bitwise XOR", 1, -1, false},
	Log2Floor: {Log2Floor, "log_2_floor", "Floor of log2", 1, 0, false},
	Pow:       {Pow, "pow", "Exponentiation", 1, -1, false},
	DivMod:    {DivMod, "div_mod", "Division with remainder", 1, 0, false},
	PopCount:  {PopCount, "pop_count", "Count 1 bits", 1, 0, false},

	// Extension Field Arithmetic
	XxAdd:   {XxAdd, "xx_add", "Extension field addition", 1, -3, false},
	XxMul:   {XxMul, "xx_mul", "Extension field multiplication", 1, -3, false},
	XInvert: {XInvert, "x_invert", "Extension field inverse", 1, 0, false},
	XbMul:   {XbMul, "xb_mul", "Base × Extension multiplication", 1, -1, false},

	// I/O
	ReadIo:  {ReadIo, "read_io", "Read from standard input", 2, 1, true},
	WriteIo: {WriteIo, "write_io", "Write to standard output", 2, -1, true},

	// Advanced Operations
	MerkleStep:    {MerkleStep, "merkle_step", "Merkle tree step (Poseidon)", 1, -1, false},
	MerkleStepMem: {MerkleStepMem, "merkle_step_mem", "Merkle step from RAM", 1, 0, false},
	XxDotStep:     {XxDotStep, "xx_dot_step", "Extension dot product step", 1, -2, false},
	XbDotStep:     {XbDotStep, "xb_dot_step", "Base-extension dot step", 1, -1, false},

	// Permutation Checks (TIP-0007)
	PushPerm:   {PushPerm, "push_perm", "Push to permutation accumulator", 1, -5, false},
	PopPerm:    {PopPerm, "pop_perm", "Pop from permutation accumulator", 1, -5, false},
	AssertPerm: {AssertPerm, "assert_perm", "Assert permutation equality", 1, 0, false},
}

// String returns the name of the instruction
func (i Instruction) String() string {
	if info, ok := AllInstructions[i]; ok {
		return info.Name
	}
	return fmt.Sprintf("unknown(%d)", i)
}

// Info returns metadata about the instruction
func (i Instruction) Info() (InstructionInfo, error) {
	info, ok := AllInstructions[i]
	if !ok {
		return InstructionInfo{}, fmt.Errorf("unknown instruction: %d", i)
	}
	return info, nil
}

// Size returns the number of words the instruction occupies
func (i Instruction) Size() int {
	info, err := i.Info()
	if err != nil {
		return 1 // Default to 1 word
	}
	return info.Size
}

// StackEffect returns the net effect on stack depth
// Positive = elements pushed, Negative = elements popped
func (i Instruction) StackEffect() int {
	info, err := i.Info()
	if err != nil {
		return 0
	}
	return info.StackEffect
}

// HasArgument returns whether the instruction takes an argument
func (i Instruction) HasArgument() bool {
	info, err := i.Info()
	if err != nil {
		return false
	}
	return info.HasArg
}

// InstructionBit represents bit positions in the opcode for AIR constraints
type InstructionBit uint8

const (
	IB0 InstructionBit = 0
	IB1 InstructionBit = 1
	IB2 InstructionBit = 2
	IB3 InstructionBit = 3
	IB4 InstructionBit = 4
	IB5 InstructionBit = 5
	IB6 InstructionBit = 6
)

// GetInstructionBit extracts a specific bit from the opcode
// Used in AIR constraints for instruction decoding
func (i Instruction) GetInstructionBit(bit InstructionBit) uint32 {
	return (uint32(i) >> uint(bit)) & 1
}

// EncodedInstruction represents a fully-encoded instruction with its argument
type EncodedInstruction struct {
	Instruction Instruction
	Argument    *field.Element // nil if no argument
}

// NewEncodedInstruction creates a new encoded instruction
func NewEncodedInstruction(inst Instruction, arg *field.Element) (*EncodedInstruction, error) {
	info, err := inst.Info()
	if err != nil {
		return nil, err
	}

	if info.HasArg && arg == nil {
		return nil, fmt.Errorf("instruction %s requires an argument", inst.String())
	}

	if !info.HasArg && arg != nil {
		return nil, fmt.Errorf("instruction %s does not take an argument", inst.String())
	}

	return &EncodedInstruction{
		Instruction: inst,
		Argument:    arg,
	}, nil
}

// Words returns the instruction as field elements for program memory
func (ei *EncodedInstruction) Words() []field.Element {
	info, err := ei.Instruction.Info()
	if err != nil {
		// Should not happen if properly constructed
		return []field.Element{field.New(uint64(ei.Instruction))}
	}

	if info.Size == 1 {
		return []field.Element{
			field.New(uint64(ei.Instruction)),
		}
	}

	// Size == 2: instruction + argument
	if ei.Argument == nil {
		return []field.Element{
			field.New(uint64(ei.Instruction)),
			field.Zero,
		}
	}
	return []field.Element{
		field.New(uint64(ei.Instruction)),
		*ei.Argument,
	}
}

// DecodeInstruction decodes an instruction from field elements
func DecodeInstruction(words []field.Element, offset int) (*EncodedInstruction, error) {
	if offset >= len(words) {
		return nil, fmt.Errorf("offset %d out of bounds", offset)
	}

	// Extract opcode
	opcodeValue := words[offset].Value()
	opcode := Instruction(opcodeValue)

	// Check if valid instruction
	info, err := opcode.Info()
	if err != nil {
		return nil, fmt.Errorf("unknown opcode: %d", opcode)
	}

	// Extract argument if needed
	var arg *field.Element
	if info.HasArg {
		if offset+1 >= len(words) {
			return nil, fmt.Errorf("instruction %s requires argument but none found", opcode.String())
		}
		arg = &words[offset+1]
	}

	return NewEncodedInstruction(opcode, arg)
}

// Program represents a Vybium STARKs VM program
type Program struct {
	Instructions []*EncodedInstruction
	Length       int // Total words
}

// NewProgram creates a new program
func NewProgram() *Program {
	return &Program{
		Instructions: make([]*EncodedInstruction, 0),
		Length:       0,
	}
}

// AddInstruction adds an instruction to the program
func (p *Program) AddInstruction(inst *EncodedInstruction) {
	p.Instructions = append(p.Instructions, inst)
	p.Length += inst.Instruction.Size()
}

// ToWords converts the program to field elements for execution
func (p *Program) ToWords() []field.Element {
	words := make([]field.Element, 0, p.Length)
	for _, inst := range p.Instructions {
		words = append(words, inst.Words()...)
	}
	return words
}

// ValidateProgram validates a program for correctness
func ValidateProgram(program *Program) error {
	if len(program.Instructions) == 0 {
		return fmt.Errorf("empty program")
	}

	// Check that program ends with Halt
	lastInst := program.Instructions[len(program.Instructions)-1]
	if lastInst.Instruction != Halt {
		return fmt.Errorf("program must end with Halt instruction")
	}

	// Additional validation could include:
	// - Jump target validation
	// - Stack depth analysis
	// - Call/Return matching

	return nil
}
