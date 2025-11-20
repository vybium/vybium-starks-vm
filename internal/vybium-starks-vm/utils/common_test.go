package utils

import "testing"

// TestIsPowerOfTwo tests the IsPowerOfTwo function
func TestIsPowerOfTwo(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected bool
	}{
		{"zero", 0, false},
		{"negative", -1, false},
		{"one", 1, true},
		{"two", 2, true},
		{"three", 3, false},
		{"four", 4, true},
		{"five", 5, false},
		{"eight", 8, true},
		{"fifteen", 15, false},
		{"sixteen", 16, true},
		{"large power", 1024, true},
		{"large non-power", 1023, false},
		{"very large", 1 << 20, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsPowerOfTwo(tt.input)
			if result != tt.expected {
				t.Errorf("IsPowerOfTwo(%d) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

// TestLog2 tests the Log2 function
func TestLog2(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected int
	}{
		{"one", 1, 0},
		{"two", 2, 1},
		{"four", 4, 2},
		{"eight", 8, 3},
		{"sixteen", 16, 4},
		{"1024", 1024, 10},
		{"non-power of 2", 3, -1},
		{"zero", 0, -1},
		{"negative", -1, -1},
		{"large power", 1 << 20, 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Log2(tt.input)
			if result != tt.expected {
				t.Errorf("Log2(%d) = %d, expected %d", tt.input, result, tt.expected)
			}
		})
	}
}

// TestNextPowerOfTwo tests the NextPowerOfTwo function
func TestNextPowerOfTwo(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected int
	}{
		{"zero", 0, 1},
		{"negative", -5, 1},
		{"one", 1, 1},
		{"two", 2, 2},
		{"three", 3, 4},
		{"four", 4, 4},
		{"five", 5, 8},
		{"seven", 7, 8},
		{"eight", 8, 8},
		{"nine", 9, 16},
		{"fifteen", 15, 16},
		{"sixteen", 16, 16},
		{"seventeen", 17, 32},
		{"hundred", 100, 128},
		{"thousand", 1000, 1024},
		{"already power", 1024, 1024},
		{"large", 10000, 16384},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NextPowerOfTwo(tt.input)
			if result != tt.expected {
				t.Errorf("NextPowerOfTwo(%d) = %d, expected %d", tt.input, result, tt.expected)
			}

			// Verify result is a power of 2
			if !IsPowerOfTwo(result) {
				t.Errorf("NextPowerOfTwo(%d) = %d, which is not a power of 2", tt.input, result)
			}

			// Verify result >= input
			if result < tt.input {
				t.Errorf("NextPowerOfTwo(%d) = %d, which is less than input", tt.input, result)
			}
		})
	}
}

// TestLog2Consistency tests that Log2 and NextPowerOfTwo are consistent
func TestLog2Consistency(t *testing.T) {
	for i := 1; i <= 1024; i++ {
		next := NextPowerOfTwo(i)
		log := Log2(next)

		// 2^log should equal next
		expected := 1 << uint(log)
		if expected != next {
			t.Errorf("Inconsistency for i=%d: NextPowerOfTwo=%d, Log2=%d, 2^Log2=%d",
				i, next, log, expected)
		}
	}
}

// TestNextPowerOfTwoIdempotent tests that NextPowerOfTwo is idempotent for powers of 2
func TestNextPowerOfTwoIdempotent(t *testing.T) {
	powers := []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096}

	for _, p := range powers {
		result := NextPowerOfTwo(p)
		if result != p {
			t.Errorf("NextPowerOfTwo(%d) = %d, expected %d (idempotent for powers of 2)", p, result, p)
		}
	}
}

// BenchmarkIsPowerOfTwo benchmarks the IsPowerOfTwo function
func BenchmarkIsPowerOfTwo(b *testing.B) {
	for i := 0; i < b.N; i++ {
		IsPowerOfTwo(1024)
	}
}

// BenchmarkLog2 benchmarks the Log2 function
func BenchmarkLog2(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Log2(1024)
	}
}

// BenchmarkNextPowerOfTwo benchmarks the NextPowerOfTwo function
func BenchmarkNextPowerOfTwo(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NextPowerOfTwo(1000)
	}
}
