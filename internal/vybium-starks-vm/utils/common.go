package utils

// IsPowerOfTwo checks if a number is a power of 2
func IsPowerOfTwo(n int) bool {
	return n > 0 && (n&(n-1)) == 0
}

// Log2 computes the base-2 logarithm of a power of 2
func Log2(n int) int {
	if !IsPowerOfTwo(n) {
		return -1
	}

	result := 0
	for n > 1 {
		n >>= 1
		result++
	}
	return result
}

// NextPowerOfTwo returns the smallest power of 2 >= n
func NextPowerOfTwo(n int) int {
	if n <= 0 {
		return 1
	}
	if IsPowerOfTwo(n) {
		return n
	}

	// Find the position of the highest bit
	power := 1
	for power < n {
		power <<= 1
	}
	return power
}
