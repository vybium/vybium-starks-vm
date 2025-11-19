package core

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Field represents a finite field with modular arithmetic operations
type Field struct {
	modulus *big.Int
}

// FieldElement represents an element in the finite field
type FieldElement struct {
	field *Field
	value *big.Int
}

// NewField creates a new finite field with the given modulus
func NewField(modulus *big.Int) (*Field, error) {
	if modulus.Cmp(big.NewInt(2)) <= 0 {
		return nil, fmt.Errorf("modulus must be greater than 2")
	}
	return &Field{modulus: new(big.Int).Set(modulus)}, nil
}

// NewFieldFromUint64 creates a new finite field with the given modulus
func NewFieldFromUint64(modulus uint64) (*Field, error) {
	return NewField(big.NewInt(int64(modulus)))
}

// Modulus returns the field modulus
func (f *Field) Modulus() *big.Int {
	return new(big.Int).Set(f.modulus)
}

// NewElement creates a new field element from a big.Int
func (f *Field) NewElement(value *big.Int) *FieldElement {
	normalized := new(big.Int).Mod(value, f.modulus)
	return &FieldElement{
		field: f,
		value: normalized,
	}
}

// NewElementFromInt64 creates a new field element from an int64
func (f *Field) NewElementFromInt64(value int64) *FieldElement {
	return f.NewElement(big.NewInt(value))
}

// NewElementFromUint64 creates a new field element from a uint64
func (f *Field) NewElementFromUint64(value uint64) *FieldElement {
	return f.NewElement(new(big.Int).SetUint64(value))
}

// RandomElement generates a random field element
func (f *Field) RandomElement() (*FieldElement, error) {
	value, err := rand.Int(rand.Reader, f.modulus)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random element: %w", err)
	}
	return f.NewElement(value), nil
}

// Zero returns the additive identity
func (f *Field) Zero() *FieldElement {
	return f.NewElement(big.NewInt(0))
}

// One returns the multiplicative identity
func (f *Field) One() *FieldElement {
	return f.NewElement(big.NewInt(1))
}

// Big returns the value as a big.Int
func (fe *FieldElement) Big() *big.Int {
	return new(big.Int).Set(fe.value)
}

// Field returns the field this element belongs to
func (fe *FieldElement) Field() *Field {
	return fe.field
}

// Add performs field addition
func (fe *FieldElement) Add(other *FieldElement) *FieldElement {
	if !fe.field.Equals(other.field) {
		panic("cannot add elements from different fields")
	}
	result := new(big.Int).Add(fe.value, other.value)
	return fe.field.NewElement(result)
}

// Sub performs field subtraction
func (fe *FieldElement) Sub(other *FieldElement) *FieldElement {
	if !fe.field.Equals(other.field) {
		panic("cannot subtract elements from different fields")
	}
	result := new(big.Int).Sub(fe.value, other.value)
	return fe.field.NewElement(result)
}

// Neg returns the additive inverse (negation) of the field element
func (fe *FieldElement) Neg() *FieldElement {
	result := new(big.Int).Neg(fe.value)
	return fe.field.NewElement(result)
}

// Sqrt returns the square root of the field element using Tonelli-Shanks algorithm
func (fe *FieldElement) Sqrt() (*FieldElement, error) {
	if fe.IsZero() {
		return fe.field.Zero(), nil
	}

	// Tonelli-Shanks algorithm for finding square roots in prime fields
	p := fe.field.modulus
	n := fe.value

	// Check if n is a quadratic residue using Euler's criterion
	// n^((p-1)/2) ≡ 1 (mod p) if n is a quadratic residue
	exp := new(big.Int).Sub(p, big.NewInt(1))
	exp.Div(exp, big.NewInt(2))

	legendre := new(big.Int).Exp(n, exp, p)
	if legendre.Cmp(big.NewInt(1)) != 0 {
		return nil, fmt.Errorf("field element is not a quadratic residue")
	}

	// If p ≡ 3 (mod 4), use the simple formula: sqrt(n) = n^((p+1)/4)
	if new(big.Int).Mod(p, big.NewInt(4)).Cmp(big.NewInt(3)) == 0 {
		exp := new(big.Int).Add(p, big.NewInt(1))
		exp.Div(exp, big.NewInt(4))
		result := new(big.Int).Exp(n, exp, p)
		return fe.field.NewElement(result), nil
	}

	// For p ≡ 1 (mod 4), use Tonelli-Shanks algorithm
	// Find Q and S such that p-1 = Q * 2^S
	Q := new(big.Int).Sub(p, big.NewInt(1))
	S := 0
	for Q.Bit(0) == 0 {
		Q.Div(Q, big.NewInt(2))
		S++
	}

	// Find a quadratic non-residue z
	z := big.NewInt(2)
	for {
		exp := new(big.Int).Sub(p, big.NewInt(1))
		exp.Div(exp, big.NewInt(2))
		legendre := new(big.Int).Exp(z, exp, p)
		if legendre.Cmp(big.NewInt(1)) != 0 {
			break
		}
		z.Add(z, big.NewInt(1))
	}

	// Tonelli-Shanks main loop
	c := new(big.Int).Exp(z, Q, p)
	x := new(big.Int).Exp(n, new(big.Int).Add(Q, big.NewInt(1)).Div(new(big.Int).Add(Q, big.NewInt(1)), big.NewInt(2)), p)
	t := new(big.Int).Exp(n, Q, p)
	m := S

	for t.Cmp(big.NewInt(1)) != 0 {
		// Find the least i such that t^(2^i) ≡ 1 (mod p)
		i := 1
		for i < m {
			exp := new(big.Int).Lsh(big.NewInt(1), uint(i))
			if new(big.Int).Exp(t, exp, p).Cmp(big.NewInt(1)) == 0 {
				break
			}
			i++
		}

		// Update variables
		b := new(big.Int).Exp(c, new(big.Int).Lsh(big.NewInt(1), uint(m-i-1)), p)
		x.Mul(x, b).Mod(x, p)
		t.Mul(t, new(big.Int).Exp(b, big.NewInt(2), p)).Mod(t, p)
		c.Exp(b, big.NewInt(2), p)
		m = i
	}

	return fe.field.NewElement(x), nil
}

// Cbrt returns the cube root of the field element
func (fe *FieldElement) Cbrt() (*FieldElement, error) {
	if fe.IsZero() {
		return fe.field.Zero(), nil
	}

	p := fe.field.modulus
	n := fe.value

	// For prime fields, we can use the formula: cbrt(n) = n^((2p-1)/3) if p ≡ 2 (mod 3)
	// or more generally, we can use the extended Euclidean algorithm approach

	// Check if p ≡ 2 (mod 3) - simple case
	if new(big.Int).Mod(p, big.NewInt(3)).Cmp(big.NewInt(2)) == 0 {
		// For p ≡ 2 (mod 3), cbrt(n) = n^((2p-1)/3)
		exp := new(big.Int).Sub(new(big.Int).Mul(p, big.NewInt(2)), big.NewInt(1))
		exp.Div(exp, big.NewInt(3))
		result := new(big.Int).Exp(n, exp, p)
		return fe.field.NewElement(result), nil
	}

	// For general case, use the fact that if gcd(3, p-1) = 1, then cube root exists
	// and can be found using extended Euclidean algorithm
	gcd := new(big.Int).GCD(nil, nil, big.NewInt(3), new(big.Int).Sub(p, big.NewInt(1)))
	if gcd.Cmp(big.NewInt(1)) != 0 {
		return nil, fmt.Errorf("cube root does not exist in this field")
	}

	// Find the modular inverse of 3 mod (p-1)
	three := big.NewInt(3)
	pMinusOne := new(big.Int).Sub(p, big.NewInt(1))
	inv := new(big.Int).ModInverse(three, pMinusOne)
	if inv == nil {
		return nil, fmt.Errorf("failed to find modular inverse")
	}

	// Compute n^inv mod p
	result := new(big.Int).Exp(n, inv, p)
	return fe.field.NewElement(result), nil
}

// LessThan returns true if this field element is less than the other
func (fe *FieldElement) LessThan(other *FieldElement) bool {
	return fe.value.Cmp(other.value) < 0
}

// Mul performs field multiplication
func (fe *FieldElement) Mul(other *FieldElement) *FieldElement {
	if !fe.field.Equals(other.field) {
		panic("cannot multiply elements from different fields")
	}
	result := new(big.Int).Mul(fe.value, other.value)
	return fe.field.NewElement(result)
}

// Div performs field division (multiplication by inverse)
func (fe *FieldElement) Div(other *FieldElement) (*FieldElement, error) {
	if !fe.field.Equals(other.field) {
		return nil, fmt.Errorf("cannot divide elements from different fields")
	}
	inv, err := other.Inv()
	if err != nil {
		return nil, fmt.Errorf("division failed: %w", err)
	}
	return fe.Mul(inv), nil
}

// Inv computes the multiplicative inverse
func (fe *FieldElement) Inv() (*FieldElement, error) {
	if fe.value.Cmp(big.NewInt(0)) == 0 {
		return nil, fmt.Errorf("cannot compute inverse of zero")
	}

	// Use extended Euclidean algorithm
	gcd := new(big.Int)
	x := new(big.Int)
	y := new(big.Int)
	gcd.GCD(x, y, fe.value, fe.field.modulus)

	if gcd.Cmp(big.NewInt(1)) != 0 {
		return nil, fmt.Errorf("inverse does not exist")
	}

	// Ensure positive result
	if x.Sign() < 0 {
		x.Add(x, fe.field.modulus)
	}

	return fe.field.NewElement(x), nil
}

// Exp performs field exponentiation
func (fe *FieldElement) Exp(exponent *big.Int) *FieldElement {
	result := new(big.Int).Exp(fe.value, exponent, fe.field.modulus)
	return fe.field.NewElement(result)
}

// Square computes the square of the field element
func (fe *FieldElement) Square() *FieldElement {
	return fe.Mul(fe)
}

// Equal checks if two field elements are equal
func (fe *FieldElement) Equal(other *FieldElement) bool {
	if !fe.field.Equals(other.field) {
		return false
	}
	return fe.value.Cmp(other.value) == 0
}

// IsZero checks if the element is zero
func (fe *FieldElement) IsZero() bool {
	return fe.value.Cmp(big.NewInt(0)) == 0
}

// IsOne checks if the element is one
func (fe *FieldElement) IsOne() bool {
	return fe.value.Cmp(big.NewInt(1)) == 0
}

// String returns a string representation of the field element
func (fe *FieldElement) String() string {
	return fe.value.String()
}

// Bytes returns the byte representation of the field element
func (fe *FieldElement) Bytes() []byte {
	return fe.value.Bytes()
}

// helper method to check if two fields are equal
func (f *Field) Equals(other *Field) bool {
	return f.modulus.Cmp(other.modulus) == 0
}

// Default field for the zkSTARKs implementation
var (
	// DefaultPrimeField uses the same modulus as the original implementation
	DefaultPrimeField, _ = NewFieldFromUint64(3221225473)
	// DefaultGenerator is a generator of the field
	DefaultGenerator = DefaultPrimeField.NewElementFromInt64(5)
)
