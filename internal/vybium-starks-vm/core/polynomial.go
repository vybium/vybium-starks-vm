package core

import (
	"fmt"
	"math/big"
	"strings"
)

// Polynomial represents a polynomial with coefficients in a finite field
type Polynomial struct {
	coefficients []*FieldElement
	field        *Field
}

// NewPolynomial creates a new polynomial from field elements
func NewPolynomial(coefficients []*FieldElement) (*Polynomial, error) {
	if len(coefficients) == 0 {
		return nil, fmt.Errorf("polynomial must have at least one coefficient")
	}

	// Get the field from the first coefficient
	field := coefficients[0].Field()

	// Validate all coefficients are from the same field
	for i, coeff := range coefficients {
		if !coeff.Field().Equals(field) {
			return nil, fmt.Errorf("coefficient %d is from a different field", i)
		}
	}

	// Remove leading zeros
	trimmed := make([]*FieldElement, 0, len(coefficients))
	for i := len(coefficients) - 1; i >= 0; i-- {
		if !coefficients[i].IsZero() {
			trimmed = coefficients[:i+1]
			break
		}
	}

	if len(trimmed) == 0 {
		trimmed = []*FieldElement{field.Zero()}
	}

	return &Polynomial{
		coefficients: trimmed,
		field:        field,
	}, nil
}

// NewPolynomialFromInt64 creates a polynomial from int64 coefficients
func NewPolynomialFromInt64(field *Field, coefficients []int64) (*Polynomial, error) {
	fieldCoeffs := make([]*FieldElement, len(coefficients))
	for i, coeff := range coefficients {
		fieldCoeffs[i] = field.NewElementFromInt64(coeff)
	}
	return NewPolynomial(fieldCoeffs)
}

// NewPolynomialFromBigInt creates a polynomial from big.Int coefficients
func NewPolynomialFromBigInt(field *Field, coefficients []*big.Int) (*Polynomial, error) {
	fieldCoeffs := make([]*FieldElement, len(coefficients))
	for i, coeff := range coefficients {
		fieldCoeffs[i] = field.NewElement(coeff)
	}
	return NewPolynomial(fieldCoeffs)
}

// Degree returns the degree of the polynomial
func (p *Polynomial) Degree() int {
	return len(p.coefficients) - 1
}

// Field returns the field the polynomial is defined over
func (p *Polynomial) Field() *Field {
	return p.field
}

// Coefficient returns the coefficient of the given degree
func (p *Polynomial) Coefficient(degree int) *FieldElement {
	if degree < 0 || degree >= len(p.coefficients) {
		return p.field.Zero()
	}
	return p.coefficients[degree]
}

// LeadingCoefficient returns the coefficient of the highest degree term
func (p *Polynomial) LeadingCoefficient() *FieldElement {
	return p.coefficients[len(p.coefficients)-1]
}

// Coefficients returns a copy of the polynomial coefficients
func (p *Polynomial) Coefficients() []*FieldElement {
	coeffs := make([]*FieldElement, len(p.coefficients))
	copy(coeffs, p.coefficients)
	return coeffs
}

// Point represents a point for polynomial interpolation
type Point struct {
	X *FieldElement
	Y *FieldElement
}

// NewPoint creates a new point
func NewPoint(x, y *FieldElement) *Point {
	return &Point{X: x, Y: y}
}

// Eval evaluates the polynomial at the given point
func (p *Polynomial) Eval(point *FieldElement) *FieldElement {
	if !point.Field().Equals(p.field) {
		panic("cannot evaluate polynomial at point from different field")
	}

	result := p.field.Zero()
	power := p.field.One()

	for i, coeff := range p.coefficients {
		if i > 0 {
			power = power.Mul(point)
		}
		term := coeff.Mul(power)
		result = result.Add(term)
	}

	return result
}

// Add adds two polynomials
func (p *Polynomial) Add(other *Polynomial) (*Polynomial, error) {
	if !p.field.Equals(other.field) {
		return nil, fmt.Errorf("cannot add polynomials from different fields")
	}

	maxDegree := p.Degree()
	if other.Degree() > maxDegree {
		maxDegree = other.Degree()
	}

	coefficients := make([]*FieldElement, maxDegree+1)

	for i := 0; i <= maxDegree; i++ {
		coeff1 := p.Coefficient(i)
		coeff2 := other.Coefficient(i)
		coefficients[i] = coeff1.Add(coeff2)
	}

	return NewPolynomial(coefficients)
}

// Sub subtracts two polynomials
func (p *Polynomial) Sub(other *Polynomial) (*Polynomial, error) {
	if !p.field.Equals(other.field) {
		return nil, fmt.Errorf("cannot subtract polynomials from different fields")
	}

	maxDegree := p.Degree()
	if other.Degree() > maxDegree {
		maxDegree = other.Degree()
	}

	coefficients := make([]*FieldElement, maxDegree+1)

	for i := 0; i <= maxDegree; i++ {
		coeff1 := p.Coefficient(i)
		coeff2 := other.Coefficient(i)
		coefficients[i] = coeff1.Sub(coeff2)
	}

	return NewPolynomial(coefficients)
}

// Mul multiplies two polynomials
func (p *Polynomial) Mul(other *Polynomial) (*Polynomial, error) {
	if !p.field.Equals(other.field) {
		return nil, fmt.Errorf("cannot multiply polynomials from different fields")
	}

	resultDegree := p.Degree() + other.Degree()
	coefficients := make([]*FieldElement, resultDegree+1)

	// Initialize all coefficients to zero
	for i := range coefficients {
		coefficients[i] = p.field.Zero()
	}

	// Perform multiplication
	for i, coeff1 := range p.coefficients {
		for j, coeff2 := range other.coefficients {
			product := coeff1.Mul(coeff2)
			coefficients[i+j] = coefficients[i+j].Add(product)
		}
	}

	return NewPolynomial(coefficients)
}

// MulScalar multiplies the polynomial by a scalar
func (p *Polynomial) MulScalar(scalar *FieldElement) (*Polynomial, error) {
	if !scalar.Field().Equals(p.field) {
		return nil, fmt.Errorf("cannot multiply by scalar from different field")
	}

	coefficients := make([]*FieldElement, len(p.coefficients))
	for i, coeff := range p.coefficients {
		coefficients[i] = coeff.Mul(scalar)
	}

	return NewPolynomial(coefficients)
}

// Pow raises the polynomial to the given power
func (p *Polynomial) Pow(exponent *big.Int) (*Polynomial, error) {
	if exponent.Sign() < 0 {
		return nil, fmt.Errorf("negative exponents not supported")
	}

	if exponent.Cmp(big.NewInt(0)) == 0 {
		// Return constant polynomial 1
		return NewPolynomial([]*FieldElement{p.field.One()})
	}

	if exponent.Cmp(big.NewInt(1)) == 0 {
		// Return copy of self
		return NewPolynomial(p.coefficients)
	}

	result, err := NewPolynomial([]*FieldElement{p.field.One()})
	if err != nil {
		return nil, err
	}

	base := p
	exp := new(big.Int).Set(exponent)

	for exp.Cmp(big.NewInt(0)) > 0 {
		if exp.Bit(0) == 1 {
			result, err = result.Mul(base)
			if err != nil {
				return nil, err
			}
		}
		base, err = base.Mul(base)
		if err != nil {
			return nil, err
		}
		exp.Rsh(exp, 1)
	}

	return result, nil
}

// Compose composes this polynomial with another polynomial
func (p *Polynomial) Compose(other *Polynomial) (*Polynomial, error) {
	if !p.field.Equals(other.field) {
		return nil, fmt.Errorf("cannot compose polynomials from different fields")
	}

	result, err := NewPolynomial([]*FieldElement{p.field.Zero()})
	if err != nil {
		return nil, err
	}

	power, err := NewPolynomial([]*FieldElement{p.field.One()})
	if err != nil {
		return nil, err
	}

	for i, coeff := range p.coefficients {
		if i > 0 {
			power, err = power.Mul(other)
			if err != nil {
				return nil, err
			}
		}

		term, err := power.MulScalar(coeff)
		if err != nil {
			return nil, err
		}

		result, err = result.Add(term)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// Div divides this polynomial by another polynomial
func (p *Polynomial) Div(other *Polynomial) (*Polynomial, *Polynomial, error) {
	if !p.field.Equals(other.field) {
		return nil, nil, fmt.Errorf("cannot divide polynomials from different fields")
	}

	if other.Degree() > p.Degree() {
		// Return zero polynomial and remainder p
		zero, err := NewPolynomial([]*FieldElement{p.field.Zero()})
		if err != nil {
			return nil, nil, err
		}
		return zero, p, nil
	}

	// Implement polynomial long division
	quotient := make([]*FieldElement, p.Degree()-other.Degree()+1)
	remainder := make([]*FieldElement, len(p.coefficients))
	copy(remainder, p.coefficients)

	leadingOther := other.LeadingCoefficient()

	for i := len(quotient) - 1; i >= 0; i-- {
		if len(remainder) <= other.Degree() {
			break
		}

		leadingRem := remainder[len(remainder)-1]
		var err error
		quotient[i], err = leadingRem.Div(leadingOther)
		if err != nil {
			return nil, nil, fmt.Errorf("division failed: %w", err)
		}

		// Subtract quotient[i] * other * x^i from remainder
		for j := 0; j <= other.Degree(); j++ {
			idx := len(remainder) - other.Degree() + j - 1
			if idx >= 0 && idx < len(remainder) {
				term := quotient[i].Mul(other.Coefficient(j))
				remainder[idx] = remainder[idx].Sub(term)
			}
		}

		// Remove leading zeros
		for len(remainder) > 0 && remainder[len(remainder)-1].IsZero() {
			remainder = remainder[:len(remainder)-1]
		}
	}

	quotientPoly, err := NewPolynomial(quotient)
	if err != nil {
		return nil, nil, err
	}

	remainderPoly, err := NewPolynomial(remainder)
	if err != nil {
		return nil, nil, err
	}

	return quotientPoly, remainderPoly, nil
}

// String returns a string representation of the polynomial
func (p *Polynomial) String() string {
	if p.Degree() == 0 {
		return p.coefficients[0].String()
	}

	var terms []string
	for i := p.Degree(); i >= 0; i-- {
		coeff := p.Coefficient(i)
		if coeff.IsZero() {
			continue
		}

		var term string
		if i == 0 {
			term = coeff.String()
		} else if i == 1 {
			if coeff.IsOne() {
				term = "x"
			} else {
				term = coeff.String() + "x"
			}
		} else {
			if coeff.IsOne() {
				term = fmt.Sprintf("x^%d", i)
			} else {
				term = fmt.Sprintf("%sx^%d", coeff.String(), i)
			}
		}

		terms = append(terms, term)
	}

	if len(terms) == 0 {
		return "0"
	}

	return strings.Join(terms, " + ")
}

// Clone creates a copy of the polynomial
func (p *Polynomial) Clone() *Polynomial {
	coefficients := make([]*FieldElement, len(p.coefficients))
	copy(coefficients, p.coefficients)

	clone, err := NewPolynomial(coefficients)
	if err != nil {
		panic("failed to clone polynomial: " + err.Error())
	}

	return clone
}

// LagrangeInterpolation performs Lagrange interpolation
func LagrangeInterpolation(points []Point, field *Field) (*Polynomial, error) {
	if len(points) == 0 {
		return nil, fmt.Errorf("need at least one point for interpolation")
	}

	// Validate all points are from the same field
	for i, point := range points {
		if !point.X.Field().Equals(field) || !point.Y.Field().Equals(field) {
			return nil, fmt.Errorf("point %d is from a different field", i)
		}
	}

	result, err := NewPolynomial([]*FieldElement{field.Zero()})
	if err != nil {
		return nil, err
	}

	for i, point := range points {
		// Compute Lagrange basis polynomial L_i(x)
		basis, err := NewPolynomial([]*FieldElement{field.One()})
		if err != nil {
			return nil, err
		}

		for j, otherPoint := range points {
			if i == j {
				continue
			}

			// (x - x_j) / (x_i - x_j)
			numerator, err := NewPolynomialFromInt64(field, []int64{0, 1}) // x
			if err != nil {
				return nil, err
			}

			constant, err := NewPolynomial([]*FieldElement{otherPoint.X})
			if err != nil {
				return nil, err
			}

			numerator, err = numerator.Sub(constant)
			if err != nil {
				return nil, err
			}

			denominator := point.X.Sub(otherPoint.X)
			if denominator.IsZero() {
				return nil, fmt.Errorf("duplicate x-coordinates found")
			}

			// Scale numerator by 1/denominator
			invDenominator, err := field.One().Div(denominator)
			if err != nil {
				return nil, err
			}
			numerator, err = numerator.MulScalar(invDenominator)
			if err != nil {
				return nil, err
			}

			basis, err = basis.Mul(numerator)
			if err != nil {
				return nil, err
			}
		}

		// Multiply by y_i and add to result
		term, err := basis.MulScalar(point.Y)
		if err != nil {
			return nil, err
		}

		result, err = result.Add(term)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}
