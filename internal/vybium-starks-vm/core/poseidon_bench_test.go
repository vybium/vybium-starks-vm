package core

import (
	"math/big"
	"testing"
)

// BenchmarkPoseidonHash benchmarks the basic Poseidon hash
func BenchmarkPoseidonHash(b *testing.B) {
	field, err := NewField(big.NewInt(2013265921))
	if err != nil {
		b.Fatal(err)
	}

	hash := NewPoseidonHash(field)
	inputs := make([]*FieldElement, 10)
	for i := 0; i < 10; i++ {
		inputs[i] = field.NewElementFromInt64(int64(i + 1))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hash.Hash(inputs)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEnhancedPoseidonHash benchmarks the enhanced Poseidon hash
func BenchmarkEnhancedPoseidonHash(b *testing.B) {
	field, err := NewField(big.NewInt(2013265921))
	if err != nil {
		b.Fatal(err)
	}

	params := GetDefaultPoseidonParameters(field, 128)
	hash, err := NewEnhancedPoseidonHash(field, params)
	if err != nil {
		b.Fatal(err)
	}

	inputs := make([]*FieldElement, 10)
	for i := 0; i < 10; i++ {
		inputs[i] = field.NewElementFromInt64(int64(i + 1))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hash.Hash(inputs)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEnhancedPoseidonHash_Security256 benchmarks 256-bit security
func BenchmarkEnhancedPoseidonHash_Security256(b *testing.B) {
	field, err := NewField(big.NewInt(2013265921))
	if err != nil {
		b.Fatal(err)
	}

	params := GetDefaultPoseidonParameters(field, 256)
	hash, err := NewEnhancedPoseidonHash(field, params)
	if err != nil {
		b.Fatal(err)
	}

	inputs := make([]*FieldElement, 10)
	for i := 0; i < 10; i++ {
		inputs[i] = field.NewElementFromInt64(int64(i + 1))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hash.Hash(inputs)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPoseidonSponge benchmarks the sponge construction
func BenchmarkPoseidonSponge(b *testing.B) {
	field, err := NewField(big.NewInt(2013265921))
	if err != nil {
		b.Fatal(err)
	}

	params := GetDefaultPoseidonParameters(field, 128)
	sponge, err := NewPoseidonSponge(field, params)
	if err != nil {
		b.Fatal(err)
	}

	inputs := make([]*FieldElement, 10)
	for i := 0; i < 10; i++ {
		inputs[i] = field.NewElementFromInt64(int64(i + 1))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Reset sponge state
		sponge, _ = NewPoseidonSponge(field, params)
		sponge.Absorb(inputs)
		_ = sponge.Squeeze(1)
	}
}

// BenchmarkGrainLFSR benchmarks the Grain LFSR parameter generation
func BenchmarkGrainLFSR(b *testing.B) {
	field, err := NewField(big.NewInt(2013265921))
	if err != nil {
		b.Fatal(err)
	}

	params := GetDefaultPoseidonParameters(field, 128)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lfsr := NewGrainLFSR(params)
		_ = lfsr.NextFieldElement(field)
	}
}

// BenchmarkMDSMatrixGeneration benchmarks MDS matrix generation
func BenchmarkMDSMatrixGeneration(b *testing.B) {
	field, err := NewField(big.NewInt(2013265921))
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := generateMDSMatrix(field, 3)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRoundConstantsGeneration benchmarks round constants generation
func BenchmarkRoundConstantsGeneration(b *testing.B) {
	field, err := NewField(big.NewInt(2013265921))
	if err != nil {
		b.Fatal(err)
	}

	params := GetDefaultPoseidonParameters(field, 128)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := generateRoundConstants(field, params)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEnhancedPoseidonHash_VaryingInputSizes benchmarks different input sizes
func BenchmarkEnhancedPoseidonHash_VaryingInputSizes(b *testing.B) {
	field, err := NewField(big.NewInt(2013265921))
	if err != nil {
		b.Fatal(err)
	}

	params := GetDefaultPoseidonParameters(field, 128)
	hash, err := NewEnhancedPoseidonHash(field, params)
	if err != nil {
		b.Fatal(err)
	}

	sizes := []int{1, 2, 5, 10, 20, 50, 100}

	for _, size := range sizes {
		inputs := make([]*FieldElement, size)
		for i := 0; i < size; i++ {
			inputs[i] = field.NewElementFromInt64(int64(i + 1))
		}

		b.Run(string(rune('0'+size)), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := hash.Hash(inputs)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkEnhancedPoseidonHash_VaryingWidth benchmarks different widths
func BenchmarkEnhancedPoseidonHash_VaryingWidth(b *testing.B) {
	field, err := NewField(big.NewInt(2013265921))
	if err != nil {
		b.Fatal(err)
	}

	widths := []int{3, 4, 5, 6}

	for _, width := range widths {
		params := &PoseidonParameters{
			SecurityLevel: 128,
			FieldSize:     field.Modulus().BitLen(),
			Width:         width,
			Rate:          width - 1,
			RoundsFull:    8,
			RoundsPartial: 83,
			SboxPower:     5,
			FieldModulus:  field.Modulus().String(),
		}

		hash, err := NewEnhancedPoseidonHash(field, params)
		if err != nil {
			b.Fatal(err)
		}

		inputs := make([]*FieldElement, 10)
		for i := 0; i < 10; i++ {
			inputs[i] = field.NewElementFromInt64(int64(i + 1))
		}

		b.Run(string(rune('0'+width)), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := hash.Hash(inputs)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkFullPoseidonRound benchmarks a single full round
func BenchmarkFullPoseidonRound(b *testing.B) {
	field, err := NewField(big.NewInt(2013265921))
	if err != nil {
		b.Fatal(err)
	}

	params := GetDefaultPoseidonParameters(field, 128)
	hash, err := NewEnhancedPoseidonHash(field, params)
	if err != nil {
		b.Fatal(err)
	}

	state := make([]*FieldElement, hash.width)
	for i := 0; i < hash.width; i++ {
		state[i] = field.NewElementFromInt64(int64(i + 1))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = hash.fullRound(state, 0)
	}
}

// BenchmarkPartialPoseidonRound benchmarks a single partial round
func BenchmarkPartialPoseidonRound(b *testing.B) {
	field, err := NewField(big.NewInt(2013265921))
	if err != nil {
		b.Fatal(err)
	}

	params := GetDefaultPoseidonParameters(field, 128)
	hash, err := NewEnhancedPoseidonHash(field, params)
	if err != nil {
		b.Fatal(err)
	}

	state := make([]*FieldElement, hash.width)
	for i := 0; i < hash.width; i++ {
		state[i] = field.NewElementFromInt64(int64(i + 1))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = hash.partialRound(state, 0)
	}
}

// BenchmarkSboxComputation benchmarks the S-box operation
func BenchmarkSboxComputation(b *testing.B) {
	field, err := NewField(big.NewInt(2013265921))
	if err != nil {
		b.Fatal(err)
	}

	params := GetDefaultPoseidonParameters(field, 128)
	hash, err := NewEnhancedPoseidonHash(field, params)
	if err != nil {
		b.Fatal(err)
	}

	x := field.NewElementFromInt64(42)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = hash.sbox(x)
	}
}

// BenchmarkMDSMatrixApplication benchmarks MDS matrix multiplication
func BenchmarkMDSMatrixApplication(b *testing.B) {
	field, err := NewField(big.NewInt(2013265921))
	if err != nil {
		b.Fatal(err)
	}

	params := GetDefaultPoseidonParameters(field, 128)
	hash, err := NewEnhancedPoseidonHash(field, params)
	if err != nil {
		b.Fatal(err)
	}

	state := make([]*FieldElement, hash.width)
	for i := 0; i < hash.width; i++ {
		state[i] = field.NewElementFromInt64(int64(i + 1))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = hash.applyMDSMatrix(state)
	}
}

// BenchmarkPoseidonInitialization benchmarks hash initialization
func BenchmarkPoseidonInitialization(b *testing.B) {
	field, err := NewField(big.NewInt(2013265921))
	if err != nil {
		b.Fatal(err)
	}

	params := GetDefaultPoseidonParameters(field, 128)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := NewEnhancedPoseidonHash(field, params)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPoseidonWithLargeField benchmarks with a larger field
func BenchmarkPoseidonWithLargeField(b *testing.B) {
	// Use a 256-bit prime
	prime := new(big.Int)
	prime.SetString("115792089237316195423570985008687907853269984665640564039457584007908834671663", 10)
	field, err := NewField(prime)
	if err != nil {
		b.Fatal(err)
	}

	params := GetDefaultPoseidonParameters(field, 128)
	hash, err := NewEnhancedPoseidonHash(field, params)
	if err != nil {
		b.Fatal(err)
	}

	inputs := make([]*FieldElement, 10)
	for i := 0; i < 10; i++ {
		inputs[i] = field.NewElementFromInt64(int64(i + 1))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hash.Hash(inputs)
		if err != nil {
			b.Fatal(err)
		}
	}
}
