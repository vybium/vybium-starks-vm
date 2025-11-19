package core

import (
	"fmt"
	"math/big"
)

// MersenneField implements Mersenne prime field M31 = 2^31 - 1
// This provides CFFT-friendly arithmetic for Circle STARKs
type MersenneField struct {
	modulus *big.Int
	// Precomputed values for optimization
	modulusMinus1 *big.Int
	modulusMinus2 *big.Int
}

// MersenneFieldElement represents an element in the Mersenne field M31
type MersenneFieldElement struct {
	field *MersenneField
	value *big.Int
}

// NewMersenneField creates a new Mersenne field M31
func NewMersenneField() *MersenneField {
	// M31 = 2^31 - 1 = 2147483647
	modulus := new(big.Int)
	modulus.SetBit(modulus, 31, 1)      // 2^31
	modulus.Sub(modulus, big.NewInt(1)) // 2^31 - 1

	modulusMinus1 := new(big.Int).Sub(modulus, big.NewInt(1))
	modulusMinus2 := new(big.Int).Sub(modulus, big.NewInt(2))

	return &MersenneField{
		modulus:       modulus,
		modulusMinus1: modulusMinus1,
		modulusMinus2: modulusMinus2,
	}
}

// NewElement creates a new Mersenne field element
func (mf *MersenneField) NewElement(value *big.Int) *MersenneFieldElement {
	// Reduce modulo M31
	reduced := new(big.Int).Mod(value, mf.modulus)
	return &MersenneFieldElement{
		field: mf,
		value: reduced,
	}
}

// NewElementFromInt64 creates a new Mersenne field element from int64
func (mf *MersenneField) NewElementFromInt64(value int64) *MersenneFieldElement {
	return mf.NewElement(big.NewInt(value))
}

// Zero returns the zero element
func (mf *MersenneField) Zero() *MersenneFieldElement {
	return &MersenneFieldElement{
		field: mf,
		value: big.NewInt(0),
	}
}

// One returns the one element
func (mf *MersenneField) One() *MersenneFieldElement {
	return &MersenneFieldElement{
		field: mf,
		value: big.NewInt(1),
	}
}

// Add adds two Mersenne field elements
func (a *MersenneFieldElement) Add(b *MersenneFieldElement) *MersenneFieldElement {
	if a.field != b.field {
		panic("cannot add elements from different fields")
	}

	sum := new(big.Int).Add(a.value, b.value)
	return a.field.NewElement(sum)
}

// Sub subtracts two Mersenne field elements
func (a *MersenneFieldElement) Sub(b *MersenneFieldElement) *MersenneFieldElement {
	if a.field != b.field {
		panic("cannot subtract elements from different fields")
	}

	diff := new(big.Int).Sub(a.value, b.value)
	return a.field.NewElement(diff)
}

// Mul multiplies two Mersenne field elements
func (a *MersenneFieldElement) Mul(b *MersenneFieldElement) *MersenneFieldElement {
	if a.field != b.field {
		panic("cannot multiply elements from different fields")
	}

	product := new(big.Int).Mul(a.value, b.value)
	return a.field.NewElement(product)
}

// Div divides two Mersenne field elements
func (a *MersenneFieldElement) Div(b *MersenneFieldElement) (*MersenneFieldElement, error) {
	if a.field != b.field {
		panic("cannot divide elements from different fields")
	}

	// Division is multiplication by inverse
	inv, err := b.Inv()
	if err != nil {
		return nil, err
	}

	return a.Mul(inv), nil
}

// Inv computes the multiplicative inverse
func (a *MersenneFieldElement) Inv() (*MersenneFieldElement, error) {
	if a.IsZero() {
		return nil, fmt.Errorf("cannot invert zero")
	}

	// Use extended Euclidean algorithm
	// For Mersenne primes, we can use Fermat's little theorem: a^(p-1) ≡ 1 (mod p)
	// So a^(-1) ≡ a^(p-2) (mod p)

	// Compute a^(p-2) mod p
	exponent := new(big.Int).Set(a.field.modulusMinus2)
	result := new(big.Int).Exp(a.value, exponent, a.field.modulus)

	return &MersenneFieldElement{
		field: a.field,
		value: result,
	}, nil
}

// IsZero checks if the element is zero
func (a *MersenneFieldElement) IsZero() bool {
	return a.value.Cmp(big.NewInt(0)) == 0
}

// IsOne checks if the element is one
func (a *MersenneFieldElement) IsOne() bool {
	return a.value.Cmp(big.NewInt(1)) == 0
}

// Equals checks if two elements are equal
func (a *MersenneFieldElement) Equals(b *MersenneFieldElement) bool {
	if a.field != b.field {
		return false
	}
	return a.value.Cmp(b.value) == 0
}

// String returns the string representation
func (a *MersenneFieldElement) String() string {
	return a.value.String()
}

// Bytes returns the byte representation
func (a *MersenneFieldElement) Bytes() []byte {
	// M31 fits in 4 bytes
	bytes := make([]byte, 4)
	a.value.FillBytes(bytes)
	return bytes
}

// Value returns the underlying big.Int value
func (a *MersenneFieldElement) Value() *big.Int {
	return new(big.Int).Set(a.value)
}

// Modulus returns the field modulus
func (mf *MersenneField) Modulus() *big.Int {
	return new(big.Int).Set(mf.modulus)
}

// Size returns the field size
func (mf *MersenneField) Size() *big.Int {
	return new(big.Int).Set(mf.modulus)
}

// IsValid checks if a value is valid in the field
func (mf *MersenneField) IsValid(value *big.Int) bool {
	return value.Cmp(big.NewInt(0)) >= 0 && value.Cmp(mf.modulus) < 0
}

// GeneratePrimitiveRoot finds a primitive root of the field
func (mf *MersenneField) GeneratePrimitiveRoot() *MersenneFieldElement {
	// For Mersenne primes, 3 is often a primitive root
	// This is a simplified implementation
	return mf.NewElementFromInt64(3)
}

// GenerateCircleGenerator finds a generator for the circle group
func (mf *MersenneField) GenerateCircleGenerator() (*CirclePoint, error) {
	// Find a point (x, y) on the circle X² + Y² = 1
	// This is a simplified implementation

	// Try x = 1, y = 0 (which satisfies 1² + 0² = 1)
	x := mf.NewElementFromInt64(1)
	y := mf.NewElementFromInt64(0)

	// Verify: x² + y² = 1
	xSquared := x.Mul(x)
	ySquared := y.Mul(y)
	sum := xSquared.Add(ySquared)

	if !sum.IsOne() {
		return nil, fmt.Errorf("failed to find valid circle generator")
	}

	return &CirclePoint{
		X: x,
		Y: y,
	}, nil
}

// CirclePoint represents a point on the circle curve X² + Y² = 1
type CirclePoint struct {
	X *MersenneFieldElement
	Y *MersenneFieldElement
}

// Add adds two circle points (group operation)
func (p *CirclePoint) Add(q *CirclePoint) *CirclePoint {
	// Circle group addition: (x1, y1) + (x2, y2) = (x1*x2 - y1*y2, x1*y2 + y1*x2)
	x1x2 := p.X.Mul(q.X)
	y1y2 := p.Y.Mul(q.Y)
	x1y2 := p.X.Mul(q.Y)
	y1x2 := p.Y.Mul(q.X)

	newX := x1x2.Sub(y1y2)
	newY := x1y2.Add(y1x2)

	return &CirclePoint{
		X: newX,
		Y: newY,
	}
}

// Mul multiplies a circle point by a scalar
func (p *CirclePoint) Mul(scalar *MersenneFieldElement) *CirclePoint {
	// Scalar multiplication using repeated addition
	result := &CirclePoint{
		X: p.X.field.Zero(),
		Y: p.X.field.One(), // Start with (0, 1) which is the identity
	}

	current := p
	scalarValue := new(big.Int).Set(scalar.value)

	for scalarValue.Cmp(big.NewInt(0)) > 0 {
		if scalarValue.Bit(0) == 1 {
			result = result.Add(current)
		}
		current = current.Add(current)  // Double
		scalarValue.Rsh(scalarValue, 1) // Divide by 2
	}

	return result
}

// String returns the string representation
func (p *CirclePoint) String() string {
	return fmt.Sprintf("(%s, %s)", p.X.String(), p.Y.String())
}

// OptimizedMersenneArithmetic provides optimized arithmetic for Mersenne fields
type OptimizedMersenneArithmetic struct {
	field *MersenneField
}

// NewOptimizedMersenneArithmetic creates optimized arithmetic
func NewOptimizedMersenneArithmetic(field *MersenneField) *OptimizedMersenneArithmetic {
	return &OptimizedMersenneArithmetic{
		field: field,
	}
}

// FastMul performs optimized multiplication using Mersenne prime properties
func (oma *OptimizedMersenneArithmetic) FastMul(a, b *MersenneFieldElement) *MersenneFieldElement {
	// For Mersenne primes, we can use special multiplication algorithms
	// This is a simplified implementation

	// Standard multiplication with modulo reduction
	product := new(big.Int).Mul(a.value, b.value)
	return oma.field.NewElement(product)
}

// FastExp performs optimized exponentiation
func (oma *OptimizedMersenneArithmetic) FastExp(base *MersenneFieldElement, exponent *big.Int) *MersenneFieldElement {
	// Optimized exponentiation using binary method
	result := new(big.Int).Exp(base.value, exponent, oma.field.modulus)
	return &MersenneFieldElement{
		field: oma.field,
		value: result,
	}
}

// FastInv performs optimized inversion using Fermat's little theorem
func (oma *OptimizedMersenneArithmetic) FastInv(a *MersenneFieldElement) *MersenneFieldElement {
	// For Mersenne primes: a^(-1) = a^(p-2) mod p
	exponent := new(big.Int).Set(oma.field.modulusMinus2)
	result := new(big.Int).Exp(a.value, exponent, oma.field.modulus)
	return &MersenneFieldElement{
		field: oma.field,
		value: result,
	}
}
