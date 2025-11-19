// Package vm provides instruction execution handlers for Vybium STARKs VM
package vm

import (
	"fmt"
	"math/big"

	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/hash"
)

// ============================================================================
// Stack Manipulation Instructions
// ============================================================================

// execPop removes n elements from the stack
func (vm *VMState) execPop(inst *EncodedInstruction) error {
	// Get number of words to pop (from argument)
	n := int(inst.Argument.Value())

	if n < 1 || n > 5 {
		return fmt.Errorf("invalid pop count: %d (must be 1-5)", n)
	}

	if vm.StackPointer < n {
		return fmt.Errorf("stack underflow: cannot pop %d elements from stack of size %d", n, vm.StackPointer)
	}

	// Pop n elements
	for i := 0; i < n; i++ {
		if _, err := vm.StackPop(); err != nil {
			return err
		}
	}

	return vm.IncrementIP()
}

// execPush pushes a value onto the stack
func (vm *VMState) execPush(inst *EncodedInstruction) error {
	if err := vm.StackPush(*inst.Argument); err != nil {
		return err
	}
	return vm.IncrementIP()
}

// execDivine non-deterministically pushes n elements (prover-supplied)
func (vm *VMState) execDivine(inst *EncodedInstruction) error {
	n := int(inst.Argument.Value())

	if n < 1 || n > 5 {
		return fmt.Errorf("invalid divine count: %d (must be 1-5)", n)
	}

	// Read n elements from secret input
	for i := 0; i < n; i++ {
		if vm.SecretPointer >= len(vm.SecretInput) {
			return fmt.Errorf("secret input exhausted")
		}

		value := vm.SecretInput[vm.SecretPointer]
		vm.SecretPointer++

		if err := vm.StackPush(value); err != nil {
			return err
		}
	}

	return vm.IncrementIP()
}

// execPick copies stack[i] to top
func (vm *VMState) execPick(inst *EncodedInstruction) error {
	index := int(inst.Argument.Value())

	if index < 0 || index >= 16 {
		return fmt.Errorf("invalid pick index: %d (must be 0-15)", index)
	}

	value, err := vm.StackPeek(index)
	if err != nil {
		return err
	}

	if err := vm.StackPush(value); err != nil {
		return err
	}

	return vm.IncrementIP()
}

// execPlace moves top to stack[i]
func (vm *VMState) execPlace(inst *EncodedInstruction) error {
	index := int(inst.Argument.Value())

	if index < 0 || index >= 16 {
		return fmt.Errorf("invalid place index: %d (must be 0-15)", index)
	}

	value, err := vm.StackPop()
	if err != nil {
		return err
	}

	// Shift stack down to make room at index
	for i := vm.StackPointer; i > index; i-- {
		vm.Stack[i] = vm.Stack[i-1]
	}

	vm.Stack[index] = value
	vm.StackPointer++

	return vm.IncrementIP()
}

// execDup duplicates stack[i] to top
func (vm *VMState) execDup(inst *EncodedInstruction) error {
	index := int(inst.Argument.Value())

	if index < 0 || index >= 16 {
		return fmt.Errorf("invalid dup index: %d (must be 0-15)", index)
	}

	value, err := vm.StackPeek(index)
	if err != nil {
		return err
	}

	if err := vm.StackPush(value); err != nil {
		return err
	}

	return vm.IncrementIP()
}

// execSwap swaps top with stack[i]
func (vm *VMState) execSwap(inst *EncodedInstruction) error {
	index := int(inst.Argument.Value())

	if index < 0 || index >= 16 {
		return fmt.Errorf("invalid swap index: %d (must be 0-15)", index)
	}

	if index >= vm.StackPointer {
		return fmt.Errorf("swap index out of bounds")
	}

	// Swap st0 with st[index]
	st0 := vm.Stack[vm.StackPointer-1]
	sti := vm.Stack[vm.StackPointer-1-index]

	vm.Stack[vm.StackPointer-1] = sti
	vm.Stack[vm.StackPointer-1-index] = st0

	return vm.IncrementIP()
}

// ============================================================================
// Control Flow Instructions
// ============================================================================

// execHalt terminates execution
func (vm *VMState) execHalt() error {
	vm.Halting = true
	// Don't increment IP - we're done
	return nil
}

// execNop does nothing
func (vm *VMState) execNop() error {
	return vm.IncrementIP()
}

// execSkiz skips next instruction if top of stack is zero
func (vm *VMState) execSkiz() error {
	st0, err := vm.StackPop()
	if err != nil {
		return err
	}

	// Increment IP past skiz
	if err := vm.IncrementIP(); err != nil {
		return err
	}

	// If st0 is zero, skip next instruction
	if st0.IsZero() {
		inst, err := vm.CurrentInstruction()
		if err != nil {
			return err
		}
		vm.InstructionPointer += inst.Instruction.Size()
	}

	return nil
}

// execCall calls a function
func (vm *VMState) execCall(inst *EncodedInstruction) error {
	// Get target address
	target := int(inst.Argument.Value())

	// Push return address onto jump stack
	returnAddr := vm.InstructionPointer + inst.Instruction.Size()

	vm.JumpStack = append(vm.JumpStack, VMJumpStackEntry{
		Origin:      returnAddr,
		Destination: target,
	})

	// Jump to target
	vm.InstructionPointer = target

	return nil
}

// execReturn returns from a function call
func (vm *VMState) execReturn() error {
	if len(vm.JumpStack) == 0 {
		return fmt.Errorf("jump stack underflow: cannot return without call")
	}

	// Pop return address from jump stack
	entry := vm.JumpStack[len(vm.JumpStack)-1]
	vm.JumpStack = vm.JumpStack[:len(vm.JumpStack)-1]

	// Jump to return address
	vm.InstructionPointer = entry.Origin

	return nil
}

// execRecurse calls current function recursively
func (vm *VMState) execRecurse() error {
	if len(vm.JumpStack) == 0 {
		return fmt.Errorf("recurse requires at least one call on jump stack")
	}

	// Get current function's entry point
	entry := vm.JumpStack[len(vm.JumpStack)-1]
	target := entry.Destination

	// Push new return address
	returnAddr := vm.InstructionPointer + 1
	vm.JumpStack = append(vm.JumpStack, VMJumpStackEntry{
		Origin:      returnAddr,
		Destination: target,
	})

	// Jump to function entry
	vm.InstructionPointer = target

	return nil
}

// execRecurseOrReturn recurses if JSP > 0, otherwise returns
func (vm *VMState) execRecurseOrReturn() error {
	if len(vm.JumpStack) > 1 {
		// Recurse
		return vm.execRecurse()
	} else if len(vm.JumpStack) == 1 {
		// Return
		return vm.execReturn()
	} else {
		return fmt.Errorf("recurse_or_return requires at least one call")
	}
}

// execAssert asserts that top of stack is 1
func (vm *VMState) execAssert() error {
	st0, err := vm.StackPop()
	if err != nil {
		return err
	}

	if !st0.Equal(field.One) {
		return fmt.Errorf("assertion failed: expected 1, got %s", st0.String())
	}

	return vm.IncrementIP()
}

// ============================================================================
// Memory Access Instructions
// ============================================================================

// execReadMem reads n words from RAM
func (vm *VMState) execReadMem(inst *EncodedInstruction) error {
	n := int(inst.Argument.Value())

	if n < 1 || n > 5 {
		return fmt.Errorf("invalid read_mem count: %d (must be 1-5)", n)
	}

	// Get address from stack
	addrElement, err := vm.StackPop()
	if err != nil {
		return err
	}

	addr := int64(addrElement.Value())

	// Read n words from RAM and push onto stack
	for i := 0; i < n; i++ {
		value := vm.RAMRead(field.New(uint64(addr + int64(i))))
		if err := vm.StackPush(value); err != nil {
			return err
		}
	}

	return vm.IncrementIP()
}

// execWriteMem writes n words to RAM
// Stack layout: [..., value_n-1, ..., value_0, address]
// So we pop values first (in reverse order), then address
func (vm *VMState) execWriteMem(inst *EncodedInstruction) error {
	n := int(inst.Argument.Value())

	if n < 1 || n > 5 {
		return fmt.Errorf("invalid write_mem count: %d (must be 1-5)", n)
	}

	// Pop n words from stack (values to write)
	values := make([]field.Element, n)
	for i := n - 1; i >= 0; i-- {
		val, err := vm.StackPop()
		if err != nil {
			return err
		}
		values[i] = val
	}

	// Get address from stack (bottom of the group)
	addrElement, err := vm.StackPop()
	if err != nil {
		return err
	}

	addr := int64(addrElement.Value())

	// Write values to RAM
	for i := 0; i < n; i++ {
		vm.RAMWrite(field.New(uint64(addr+int64(i))), values[i])
	}

	return vm.IncrementIP()
}

// ============================================================================
// Base Field Arithmetic Instructions
// ============================================================================

// execAdd adds top two stack elements
func (vm *VMState) execAdd() error {
	b, err := vm.StackPop()
	if err != nil {
		return err
	}

	a, err := vm.StackPop()
	if err != nil {
		return err
	}

	result := a.Add(b)

	if err := vm.StackPush(result); err != nil {
		return err
	}

	return vm.IncrementIP()
}

// execAddI adds immediate value to top
func (vm *VMState) execAddI(inst *EncodedInstruction) error {
	a, err := vm.StackPop()
	if err != nil {
		return err
	}

	result := a.Add(*inst.Argument)

	if err := vm.StackPush(result); err != nil {
		return err
	}

	return vm.IncrementIP()
}

// execMul multiplies top two stack elements
func (vm *VMState) execMul() error {
	b, err := vm.StackPop()
	if err != nil {
		return err
	}

	a, err := vm.StackPop()
	if err != nil {
		return err
	}

	result := a.Mul(b)

	if err := vm.StackPush(result); err != nil {
		return err
	}

	return vm.IncrementIP()
}

// execInvert computes multiplicative inverse
func (vm *VMState) execInvert() error {
	a, err := vm.StackPop()
	if err != nil {
		return err
	}

	if a.IsZero() {
		return fmt.Errorf("cannot invert zero")
	}

	result := a.Inverse()

	if err := vm.StackPush(result); err != nil {
		return err
	}

	return vm.IncrementIP()
}

// execEq checks equality of top two stack elements
func (vm *VMState) execEq() error {
	b, err := vm.StackPop()
	if err != nil {
		return err
	}

	a, err := vm.StackPop()
	if err != nil {
		return err
	}

	var result field.Element
	if a.Equal(b) {
		result = field.One
	} else {
		result = field.Zero
	}

	if err := vm.StackPush(result); err != nil {
		return err
	}

	return vm.IncrementIP()
}

// ============================================================================
// I/O Instructions
// ============================================================================

// execReadIo reads n elements from public input
func (vm *VMState) execReadIo(inst *EncodedInstruction) error {
	n := int(inst.Argument.Value())

	if n < 1 || n > 5 {
		return fmt.Errorf("invalid read_io count: %d (must be 1-5)", n)
	}

	// Read n elements from public input
	for i := 0; i < n; i++ {
		if vm.InputPointer >= len(vm.PublicInput) {
			return fmt.Errorf("public input exhausted")
		}

		value := vm.PublicInput[vm.InputPointer]
		vm.InputPointer++

		if err := vm.StackPush(value); err != nil {
			return err
		}
	}

	return vm.IncrementIP()
}

// execWriteIo writes n elements to public output
func (vm *VMState) execWriteIo(inst *EncodedInstruction) error {
	n := int(inst.Argument.Value())

	if n < 1 || n > 5 {
		return fmt.Errorf("invalid write_io count: %d (must be 1-5)", n)
	}

	// Pop n elements and write to output
	values := make([]field.Element, n)
	for i := n - 1; i >= 0; i-- {
		value, err := vm.StackPop()
		if err != nil {
			return err
		}
		values[i] = value
	}

	vm.PublicOutput = append(vm.PublicOutput, values...)

	return vm.IncrementIP()
}

// ============================================================================
// Bitwise Instructions (U32 Coprocessor)
// ============================================================================

// execSplit splits top into high and low 32-bit parts
func (vm *VMState) execSplit() error {
	a, err := vm.StackPop()
	if err != nil {
		return err
	}

	// Split into low 32 bits and high bits
	value := big.NewInt(int64(a.Value()))
	mask := big.NewInt((1 << 32) - 1)

	low := new(big.Int).And(value, mask)
	high := new(big.Int).Rsh(value, 32)

	// Push high, then low (so low is on top)
	if err := vm.StackPush(field.New(high.Uint64())); err != nil {
		return err
	}
	if err := vm.StackPush(field.New(low.Uint64())); err != nil {
		return err
	}

	// Record U32 coprocessor call
	vm.CoProcessorCalls = append(vm.CoProcessorCalls, CoProcessorCall{
		Type: U32CoProcessor,
		Data: map[string]interface{}{
			"operation": "split",
			"input":     value,
			"high":      high,
			"low":       low,
		},
	})

	return vm.IncrementIP()
}

// execLt checks if second < top (unsigned 32-bit)
func (vm *VMState) execLt() error {
	b, err := vm.StackPop()
	if err != nil {
		return err
	}

	a, err := vm.StackPop()
	if err != nil {
		return err
	}

	// Compare as unsigned 32-bit integers
	aValue := new(big.Int).And(big.NewInt(int64(a.Value())), big.NewInt((1<<32)-1))
	bValue := new(big.Int).And(big.NewInt(int64(b.Value())), big.NewInt((1<<32)-1))

	var result field.Element
	if aValue.Cmp(bValue) < 0 {
		result = field.One
	} else {
		result = field.Zero
	}

	if err := vm.StackPush(result); err != nil {
		return err
	}

	// Record U32 coprocessor call
	vm.CoProcessorCalls = append(vm.CoProcessorCalls, CoProcessorCall{
		Type: U32CoProcessor,
		Data: map[string]interface{}{
			"operation": "lt",
			"a":         aValue,
			"b":         bValue,
			"result":    result.Equal(field.One),
		},
	})

	return vm.IncrementIP()
}

// execAnd performs bitwise AND
func (vm *VMState) execAnd() error {
	b, err := vm.StackPop()
	if err != nil {
		return err
	}

	a, err := vm.StackPop()
	if err != nil {
		return err
	}

	result := new(big.Int).And(big.NewInt(int64(a.Value())), big.NewInt(int64(b.Value())))

	if err := vm.StackPush(field.New(result.Uint64())); err != nil {
		return err
	}

	// Record U32 coprocessor call
	vm.CoProcessorCalls = append(vm.CoProcessorCalls, CoProcessorCall{
		Type: U32CoProcessor,
		Data: map[string]interface{}{
			"operation": "and",
			"a":         big.NewInt(int64(a.Value())),
			"b":         big.NewInt(int64(b.Value())),
			"result":    result,
		},
	})

	return vm.IncrementIP()
}

// execXor performs bitwise XOR
func (vm *VMState) execXor() error {
	b, err := vm.StackPop()
	if err != nil {
		return err
	}

	a, err := vm.StackPop()
	if err != nil {
		return err
	}

	result := new(big.Int).Xor(big.NewInt(int64(a.Value())), big.NewInt(int64(b.Value())))

	if err := vm.StackPush(field.New(result.Uint64())); err != nil {
		return err
	}

	// Record U32 coprocessor call
	vm.CoProcessorCalls = append(vm.CoProcessorCalls, CoProcessorCall{
		Type: U32CoProcessor,
		Data: map[string]interface{}{
			"operation": "xor",
			"a":         big.NewInt(int64(a.Value())),
			"b":         big.NewInt(int64(b.Value())),
			"result":    result,
		},
	})

	return vm.IncrementIP()
}

// execLog2Floor computes floor(log2(x))
func (vm *VMState) execLog2Floor() error {
	a, err := vm.StackPop()
	if err != nil {
		return err
	}

	if a.IsZero() {
		return fmt.Errorf("log2 of zero is undefined")
	}

	value := big.NewInt(int64(a.Value()))
	log2 := value.BitLen() - 1

	result := field.New(uint64(log2))

	if err := vm.StackPush(result); err != nil {
		return err
	}

	// Record U32 coprocessor call
	vm.CoProcessorCalls = append(vm.CoProcessorCalls, CoProcessorCall{
		Type: U32CoProcessor,
		Data: map[string]interface{}{
			"operation": "log2_floor",
			"input":     value,
			"result":    log2,
		},
	})

	return vm.IncrementIP()
}

// execPow raises second to power of top
func (vm *VMState) execPow() error {
	expElement, err := vm.StackPop() // exp
	if err != nil {
		return err
	}

	base, err := vm.StackPop()
	if err != nil {
		return err
	}

	// Perform modular exponentiation
	exp := expElement.Value()
	result := base.ModPow(exp)

	if err := vm.StackPush(result); err != nil {
		return err
	}

	return vm.IncrementIP()
}

// execDivMod computes quotient and remainder
func (vm *VMState) execDivMod() error {
	divisor, err := vm.StackPop()
	if err != nil {
		return err
	}

	dividend, err := vm.StackPop()
	if err != nil {
		return err
	}

	if divisor.IsZero() {
		return fmt.Errorf("division by zero")
	}

	// Compute quotient and remainder
	q := new(big.Int)
	r := new(big.Int)
	q.DivMod(big.NewInt(int64(dividend.Value())), big.NewInt(int64(divisor.Value())), r)

	// Push quotient, then remainder (so remainder is on top)
	if err := vm.StackPush(field.New(q.Uint64())); err != nil {
		return err
	}
	if err := vm.StackPush(field.New(r.Uint64())); err != nil {
		return err
	}

	return vm.IncrementIP()
}

// execPopCount counts the number of 1 bits
func (vm *VMState) execPopCount() error {
	a, err := vm.StackPop()
	if err != nil {
		return err
	}

	// Count 1 bits in binary representation
	count := 0
	value := new(big.Int).Set(big.NewInt(int64(a.Value())))
	for value.Sign() > 0 {
		if value.Bit(0) == 1 {
			count++
		}
		value.Rsh(value, 1)
	}

	result := field.New(uint64(count))

	if err := vm.StackPush(result); err != nil {
		return err
	}

	// Record U32 coprocessor call
	vm.CoProcessorCalls = append(vm.CoProcessorCalls, CoProcessorCall{
		Type: U32CoProcessor,
		Data: map[string]interface{}{
			"operation": "pop_count",
			"input":     big.NewInt(int64(a.Value())),
			"result":    count,
		},
	})

	return vm.IncrementIP()
}

// ============================================================================
// Hashing Instructions (Poseidon-based)
// ============================================================================

// execHash computes Poseidon hash of stack[0..10]
func (vm *VMState) execHash() error {
	// Pop 10 elements from stack for hashing
	input := make([]field.Element, 10)
	for i := 9; i >= 0; i-- {
		val, err := vm.StackPop()
		if err != nil {
			return fmt.Errorf("hash requires 10 stack elements: %w", err)
		}
		input[i] = val
	}

	// Compute Poseidon hash using vybium-crypto
	result := hash.PoseidonHash(input)

	// Push result (5 elements for Poseidon digest)
	// The hash produces a 5-element digest. For simplicity, we push the single result
	// 5 times. In production, use Tip5 Hash10 for proper 5-element digest
	for i := 0; i < 5; i++ {
		if err := vm.StackPush(result); err != nil {
			return err
		}
	}

	// Record hash coprocessor call
	vm.CoProcessorCalls = append(vm.CoProcessorCalls, CoProcessorCall{
		Type: HashCoProcessor,
		Data: map[string]interface{}{
			"operation": "hash",
			"input":     input,
			"output":    result,
		},
	})

	return vm.IncrementIP()
}

// execAssertVector asserts stack[0..5] equals stack[5..10]
func (vm *VMState) execAssertVector() error {
	// Pop 10 elements (two vectors of 5)
	vector2 := make([]field.Element, 5)
	for i := 4; i >= 0; i-- {
		val, err := vm.StackPop()
		if err != nil {
			return err
		}
		vector2[i] = val
	}

	vector1 := make([]field.Element, 5)
	for i := 4; i >= 0; i-- {
		val, err := vm.StackPop()
		if err != nil {
			return err
		}
		vector1[i] = val
	}

	// Check equality
	for i := 0; i < 5; i++ {
		if !vector1[i].Equal(vector2[i]) {
			return fmt.Errorf("assert_vector failed: vector1[%d] (%s) != vector2[%d] (%s)",
				i, vector1[i].String(), i, vector2[i].String())
		}
	}

	return vm.IncrementIP()
}

// execSpongeInit initializes Poseidon sponge
func (vm *VMState) execSpongeInit() error {
	// Initialize Poseidon sponge state (16 elements)
	vm.Sponge = &PoseidonSponge{
		State: make([]field.Element, 16),
		Rate:  10, // 10 elements absorbed/squeezed at once
	}
	for i := 0; i < 16; i++ {
		vm.Sponge.State[i] = field.Zero
	}

	// Record coprocessor call
	vm.CoProcessorCalls = append(vm.CoProcessorCalls, CoProcessorCall{
		Type: SpongeResetCoProcessor,
		Data: nil,
	})

	return vm.IncrementIP()
}

// execSpongeAbsorb absorbs 10 elements from stack into sponge
func (vm *VMState) execSpongeAbsorb() error {
	if vm.Sponge == nil {
		return fmt.Errorf("sponge not initialized (call sponge_init first)")
	}

	// Pop 10 elements from stack
	input := make([]field.Element, 10)
	for i := 9; i >= 0; i-- {
		val, err := vm.StackPop()
		if err != nil {
			return err
		}
		input[i] = val
	}

	// XOR input into sponge state (rate portion)
	for i := 0; i < 10; i++ {
		vm.Sponge.State[i] = vm.Sponge.State[i].Add(input[i])
	}

	// Apply Poseidon permutation
	if err := vm.applyPoseidonPermutation(); err != nil {
		return fmt.Errorf("sponge permutation failed: %w", err)
	}

	// Record coprocessor call
	vm.CoProcessorCalls = append(vm.CoProcessorCalls, CoProcessorCall{
		Type: HashCoProcessor,
		Data: map[string]interface{}{
			"operation": "sponge_absorb",
			"input":     input,
			"state":     vm.Sponge.State,
		},
	})

	return vm.IncrementIP()
}

// execSpongeAbsorbMem absorbs elements from RAM into sponge
func (vm *VMState) execSpongeAbsorbMem() error {
	if vm.Sponge == nil {
		return fmt.Errorf("sponge not initialized")
	}

	// Pop address from stack
	addrElement, err := vm.StackPop()
	if err != nil {
		return err
	}
	addr := int64(addrElement.Value())

	// Read 10 elements from RAM
	input := make([]field.Element, 10)
	for i := 0; i < 10; i++ {
		input[i] = vm.RAMRead(field.New(uint64(addr + int64(i))))
	}

	// XOR into sponge state
	for i := 0; i < 10; i++ {
		vm.Sponge.State[i] = vm.Sponge.State[i].Add(input[i])
	}

	// Apply Poseidon permutation
	if err := vm.applyPoseidonPermutation(); err != nil {
		return err
	}

	// Record coprocessor call
	vm.CoProcessorCalls = append(vm.CoProcessorCalls, CoProcessorCall{
		Type: HashCoProcessor,
		Data: map[string]interface{}{
			"operation": "sponge_absorb_mem",
			"address":   addr,
			"input":     input,
		},
	})

	return vm.IncrementIP()
}

// execSpongeSqueeze squeezes 10 elements from sponge onto stack
func (vm *VMState) execSpongeSqueeze() error {
	if vm.Sponge == nil {
		return fmt.Errorf("sponge not initialized")
	}

	// Apply Poseidon permutation before squeezing
	if err := vm.applyPoseidonPermutation(); err != nil {
		return err
	}

	// Push first 10 elements of state onto stack
	output := make([]field.Element, 10)
	for i := 0; i < 10; i++ {
		output[i] = vm.Sponge.State[i]
		if err := vm.StackPush(output[i]); err != nil {
			return err
		}
	}

	// Record coprocessor call
	vm.CoProcessorCalls = append(vm.CoProcessorCalls, CoProcessorCall{
		Type: HashCoProcessor,
		Data: map[string]interface{}{
			"operation": "sponge_squeeze",
			"output":    output,
		},
	})

	return vm.IncrementIP()
}

// applyPoseidonPermutation applies one round of Poseidon permutation
func (vm *VMState) applyPoseidonPermutation() error {
	if vm.Sponge == nil {
		return fmt.Errorf("sponge not initialized")
	}

	// Apply Poseidon permutation to the sponge state
	// The sponge uses Tip5 which operates on 16 elements
	// For compatibility, we use Poseidon hash on the rate portion (first 10 elements)
	rateElements := vm.Sponge.State[:10]
	permResult := hash.PoseidonHash(rateElements)

	// Update the first element of the state with the permutation result
	// In a full implementation, this would be a complete state permutation
	vm.Sponge.State[0] = permResult

	return nil
}

// ============================================================================
// Extension Field Instructions
// ============================================================================

// execXxAdd adds two extension field elements (3 elements each)
func (vm *VMState) execXxAdd() error {
	// Pop second extension field element (3 components)
	b2, err := vm.StackPop()
	if err != nil {
		return err
	}
	b1, err := vm.StackPop()
	if err != nil {
		return err
	}
	b0, err := vm.StackPop()
	if err != nil {
		return err
	}

	// Pop first extension field element (3 components)
	a2, err := vm.StackPop()
	if err != nil {
		return err
	}
	a1, err := vm.StackPop()
	if err != nil {
		return err
	}
	a0, err := vm.StackPop()
	if err != nil {
		return err
	}

	// Component-wise addition in extension field
	r0 := a0.Add(b0)
	r1 := a1.Add(b1)
	r2 := a2.Add(b2)

	// Push result
	if err := vm.StackPush(r0); err != nil {
		return err
	}
	if err := vm.StackPush(r1); err != nil {
		return err
	}
	if err := vm.StackPush(r2); err != nil {
		return err
	}

	return vm.IncrementIP()
}

// execXxMul multiplies two extension field elements
func (vm *VMState) execXxMul() error {
	// Pop second extension field element
	b2, err := vm.StackPop()
	if err != nil {
		return err
	}
	b1, err := vm.StackPop()
	if err != nil {
		return err
	}
	b0, err := vm.StackPop()
	if err != nil {
		return err
	}

	// Pop first extension field element
	a2, err := vm.StackPop()
	if err != nil {
		return err
	}
	a1, err := vm.StackPop()
	if err != nil {
		return err
	}
	a0, err := vm.StackPop()
	if err != nil {
		return err
	}

	// Extension field multiplication using irreducible polynomial
	// For F_p[X]/(X^3 - X - 1), the multiplication is:
	// (a0 + a1*X + a2*X^2) * (b0 + b1*X + b2*X^2)
	//
	// Simplified implementation (Karatsuba-style)
	r0 := a0.Mul(b0).Add(a1.Mul(b2)).Add(a2.Mul(b1))
	r1 := a0.Mul(b1).Add(a1.Mul(b0)).Add(a2.Mul(b2))
	r2 := a0.Mul(b2).Add(a1.Mul(b1)).Add(a2.Mul(b0))

	// Push result
	if err := vm.StackPush(r0); err != nil {
		return err
	}
	if err := vm.StackPush(r1); err != nil {
		return err
	}
	if err := vm.StackPush(r2); err != nil {
		return err
	}

	return vm.IncrementIP()
}

// execXInvert inverts an extension field element
func (vm *VMState) execXInvert() error {
	// Pop extension field element
	a2, err := vm.StackPop()
	if err != nil {
		return err
	}
	a1, err := vm.StackPop()
	if err != nil {
		return err
	}
	a0, err := vm.StackPop()
	if err != nil {
		return err
	}

	// Check for zero
	if a0.IsZero() && a1.IsZero() && a2.IsZero() {
		return fmt.Errorf("cannot invert zero in extension field")
	}

	// Compute norm N(a) = a * a_conjugate (simplified)
	// For full implementation, use proper extension field arithmetic
	// Here we use a simplified version
	norm := a0.Mul(a0).Add(a1.Mul(a1)).Add(a2.Mul(a2))

	if norm.IsZero() {
		return fmt.Errorf("extension field element has zero norm")
	}

	normInv := norm.Inverse()

	// Result = conjugate(a) / norm
	r0 := a0.Mul(normInv)
	r1 := a1.Mul(normInv).Neg()
	r2 := a2.Mul(normInv).Neg()

	// Push result
	if err := vm.StackPush(r0); err != nil {
		return err
	}
	if err := vm.StackPush(r1); err != nil {
		return err
	}
	if err := vm.StackPush(r2); err != nil {
		return err
	}

	return vm.IncrementIP()
}

// execXbMul multiplies extension field element by base field element
func (vm *VMState) execXbMul() error {
	// Pop base field scalar
	scalar, err := vm.StackPop()
	if err != nil {
		return err
	}

	// Pop extension field element
	a2, err := vm.StackPop()
	if err != nil {
		return err
	}
	a1, err := vm.StackPop()
	if err != nil {
		return err
	}
	a0, err := vm.StackPop()
	if err != nil {
		return err
	}

	// Scalar multiplication (component-wise)
	r0 := a0.Mul(scalar)
	r1 := a1.Mul(scalar)
	r2 := a2.Mul(scalar)

	// Push result
	if err := vm.StackPush(r0); err != nil {
		return err
	}
	if err := vm.StackPush(r1); err != nil {
		return err
	}
	if err := vm.StackPush(r2); err != nil {
		return err
	}

	return vm.IncrementIP()
}

// ============================================================================
// Merkle Tree Instructions (Poseidon-based)
// ============================================================================

// execMerkleStep verifies one Merkle tree step using Poseidon
func (vm *VMState) execMerkleStep() error {
	// Pop node index, sibling, and current digest from stack
	nodeIndex, err := vm.StackPop()
	if err != nil {
		return err
	}

	// Pop sibling digest (5 elements)
	sibling := make([]field.Element, 5)
	for i := 4; i >= 0; i-- {
		val, err := vm.StackPop()
		if err != nil {
			return err
		}
		sibling[i] = val
	}

	// Pop current digest (5 elements)
	current := make([]field.Element, 5)
	for i := 4; i >= 0; i-- {
		val, err := vm.StackPop()
		if err != nil {
			return err
		}
		current[i] = val
	}

	// Determine if current is left or right child
	nodeIdx := nodeIndex.Value()
	isLeftChild := (nodeIdx & 1) == 0

	// Prepare input for hashing (left || right)
	var hashInput []field.Element
	if isLeftChild {
		hashInput = append(current, sibling...)
	} else {
		hashInput = append(sibling, current...)
	}

	// Compute parent hash using Poseidon
	parent := hash.PoseidonHash(hashInput)

	// Push parent digest onto stack (5 times for 5-element digest)
	for i := 0; i < 5; i++ {
		if err := vm.StackPush(parent); err != nil {
			return err
		}
	}

	// Record coprocessor call
	vm.CoProcessorCalls = append(vm.CoProcessorCalls, CoProcessorCall{
		Type: HashCoProcessor,
		Data: map[string]interface{}{
			"operation": "merkle_step",
			"current":   current,
			"sibling":   sibling,
			"parent":    parent,
		},
	})

	return vm.IncrementIP()
}

// execMerkleStepMem verifies Merkle step with sibling from RAM
func (vm *VMState) execMerkleStepMem() error {
	// Pop address and node index
	addr, err := vm.StackPop()
	if err != nil {
		return err
	}

	nodeIndex, err := vm.StackPop()
	if err != nil {
		return err
	}

	// Read sibling from RAM (5 elements)
	sibling := make([]field.Element, 5)
	for i := 0; i < 5; i++ {
		sibling[i] = vm.RAMRead(field.New(uint64(int64(addr.Value()) + int64(i))))
	}

	// Pop current digest from stack
	current := make([]field.Element, 5)
	for i := 4; i >= 0; i-- {
		val, err := vm.StackPop()
		if err != nil {
			return err
		}
		current[i] = val
	}

	// Same logic as merkle_step
	nodeIdx := nodeIndex.Value()
	isLeftChild := (nodeIdx & 1) == 0

	// Prepare input for hashing (left || right)
	var hashInput []field.Element
	if isLeftChild {
		hashInput = append(current, sibling...)
	} else {
		hashInput = append(sibling, current...)
	}

	// Compute parent hash using Poseidon
	parent := hash.PoseidonHash(hashInput)

	// Push parent
	for i := 0; i < 5; i++ {
		if err := vm.StackPush(parent); err != nil {
			return err
		}
	}

	return vm.IncrementIP()
}

// ============================================================================
// Dot Product Instructions (Extension Field)
// ============================================================================

// execXxDotStep computes one step of extension field dot product
func (vm *VMState) execXxDotStep() error {
	// Pop accumulator (3 elements)
	acc2, err := vm.StackPop()
	if err != nil {
		return err
	}
	acc1, err := vm.StackPop()
	if err != nil {
		return err
	}
	acc0, err := vm.StackPop()
	if err != nil {
		return err
	}

	// Pop second vector element (3 elements)
	b2, err := vm.StackPop()
	if err != nil {
		return err
	}
	b1, err := vm.StackPop()
	if err != nil {
		return err
	}
	b0, err := vm.StackPop()
	if err != nil {
		return err
	}

	// Pop first vector element (3 elements)
	a2, err := vm.StackPop()
	if err != nil {
		return err
	}
	a1, err := vm.StackPop()
	if err != nil {
		return err
	}
	a0, err := vm.StackPop()
	if err != nil {
		return err
	}

	// Compute a * b (extension field multiplication)
	prod0 := a0.Mul(b0).Add(a1.Mul(b2)).Add(a2.Mul(b1))
	prod1 := a0.Mul(b1).Add(a1.Mul(b0)).Add(a2.Mul(b2))
	prod2 := a0.Mul(b2).Add(a1.Mul(b1)).Add(a2.Mul(b0))

	// Add to accumulator
	result0 := acc0.Add(prod0)
	result1 := acc1.Add(prod1)
	result2 := acc2.Add(prod2)

	// Push result
	if err := vm.StackPush(result0); err != nil {
		return err
	}
	if err := vm.StackPush(result1); err != nil {
		return err
	}
	if err := vm.StackPush(result2); err != nil {
		return err
	}

	return vm.IncrementIP()
}

// execXbDotStep computes one step of base-extension dot product
func (vm *VMState) execXbDotStep() error {
	// Pop accumulator (3 elements)
	acc2, err := vm.StackPop()
	if err != nil {
		return err
	}
	acc1, err := vm.StackPop()
	if err != nil {
		return err
	}
	acc0, err := vm.StackPop()
	if err != nil {
		return err
	}

	// Pop base field scalar
	scalar, err := vm.StackPop()
	if err != nil {
		return err
	}

	// Pop extension field element
	a2, err := vm.StackPop()
	if err != nil {
		return err
	}
	a1, err := vm.StackPop()
	if err != nil {
		return err
	}
	a0, err := vm.StackPop()
	if err != nil {
		return err
	}

	// Compute scalar * extension_element
	prod0 := a0.Mul(scalar)
	prod1 := a1.Mul(scalar)
	prod2 := a2.Mul(scalar)

	// Add to accumulator
	result0 := acc0.Add(prod0)
	result1 := acc1.Add(prod1)
	result2 := acc2.Add(prod2)

	// Push result
	if err := vm.StackPush(result0); err != nil {
		return err
	}
	if err := vm.StackPush(result1); err != nil {
		return err
	}
	if err := vm.StackPush(result2); err != nil {
		return err
	}

	return vm.IncrementIP()
}

// ===========================================================================
// TIP-0007: Run-Time Permutation Check Instructions
// ===========================================================================

// execPushPerm pushes top 5 stack elements into permutation accumulator
// Computes inner product p = Σ(st_i · a_i) with Fiat-Shamir weights
// Multiplies (α - p) into running product: permrp' = permrp · (α - p)
func (vm *VMState) execPushPerm() error {
	// Ensure we have at least 5 elements on stack
	if vm.StackPointer < 5 {
		return fmt.Errorf("push_perm requires 5 stack elements, have %d", vm.StackPointer)
	}

	// Get top 5 stack elements (st0..st4) without popping
	stackElements := make([]field.Element, 5)
	for i := 0; i < 5; i++ {
		stackElements[i] = vm.Stack[i]
	}

	// Compute inner product p = Σ(st_i · a_i)
	innerProduct := field.Zero
	for i := 0; i < 5; i++ {
		term := stackElements[i].Mul(vm.PermutationWeights[i])
		innerProduct = innerProduct.Add(term)
	}

	// Compute (α - p)
	alphaMinusP := vm.PermutationAlpha.Sub(innerProduct)

	// Multiply into running product: permrp' = permrp · (α - p)
	vm.PermutationRunningProduct = vm.PermutationRunningProduct.Mul(alphaMinusP)

	// Pop the 5 elements
	for i := 0; i < 5; i++ {
		if _, err := vm.StackPop(); err != nil {
			return fmt.Errorf("failed to pop element %d: %w", i, err)
		}
	}

	return vm.IncrementIP()
}

// execPopPerm pops from permutation accumulator
// Computes inner product p = Σ(st_i · a_i) with Fiat-Shamir weights
// Divides (α - p) out of running product: permrp' = permrp / (α - p)
func (vm *VMState) execPopPerm() error {
	// Ensure we have at least 5 elements on stack
	if vm.StackPointer < 5 {
		return fmt.Errorf("pop_perm requires 5 stack elements, have %d", vm.StackPointer)
	}

	// Get top 5 stack elements (st0..st4) without popping
	stackElements := make([]field.Element, 5)
	for i := 0; i < 5; i++ {
		stackElements[i] = vm.Stack[i]
	}

	// Compute inner product p = Σ(st_i · a_i)
	innerProduct := field.Zero
	for i := 0; i < 5; i++ {
		term := stackElements[i].Mul(vm.PermutationWeights[i])
		innerProduct = innerProduct.Add(term)
	}

	// Compute (α - p)
	alphaMinusP := vm.PermutationAlpha.Sub(innerProduct)

	// Check that (α - p) is non-zero
	if alphaMinusP.IsZero() {
		return fmt.Errorf("pop_perm division by zero: α = p")
	}

	// Divide out of running product: permrp' = permrp / (α - p)
	divisor := alphaMinusP.Inverse()
	vm.PermutationRunningProduct = vm.PermutationRunningProduct.Mul(divisor)

	// Pop the 5 elements
	for i := 0; i < 5; i++ {
		if _, err := vm.StackPop(); err != nil {
			return fmt.Errorf("failed to pop element %d: %w", i, err)
		}
	}

	return vm.IncrementIP()
}

// execAssertPerm asserts that permutation accumulator equals 1
// Verifies that pushed and popped elements are equal up to permutation
func (vm *VMState) execAssertPerm() error {
	// Check that running product is 1
	if !vm.PermutationRunningProduct.Equal(field.One) {
		return fmt.Errorf("assert_perm failed: permutation running product is not 1 (got %s)",
			vm.PermutationRunningProduct.String())
	}

	return vm.IncrementIP()
}
