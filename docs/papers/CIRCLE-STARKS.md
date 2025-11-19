# Circle-STARKs

## Overview

Circle-STARKs are a variant of STARKs that operate over arithmetic circles, enabling efficient FFT operations and recursive proof composition. The arithmetic circle provides a natural structure for polynomial evaluation and interpolation.

## Mathematical Foundation

### Arithmetic Circle

The arithmetic circle is defined over a finite field F as:

```
C = {(x, y) ∈ F^2 : x^2 + y^2 = 1}
```

This forms an algebraic curve with group structure. Points on the circle can be parameterized as:

```
(cos(θ), sin(θ)) = (x, y)
```

where θ is an angle parameter.

### Circle Group Structure

The circle forms an abelian group under point addition:

```
(x_1, y_1) + (x_2, y_2) = (x_1·x_2 - y_1·y_2, x_1·y_2 + y_1·x_2)
```

This corresponds to angle addition: θ_1 + θ_2.

### Circle FFT

The Circle-FFT evaluates polynomials at points on the arithmetic circle. For a polynomial p(X) of degree < n, evaluate at n points on the circle:

```
p(cos(2πk/n), sin(2πk/n))  for k = 0, 1, ..., n-1
```

### Evaluation Domain

The evaluation domain D consists of n points on the circle:

```
D = {(cos(2πk/n), sin(2πk/n)) : k = 0, 1, ..., n-1}
```

These points are equally spaced around the circle.

## Mathematical Formulations

### Polynomial Evaluation on Circle

For polynomial p(X) = Σ_{i=0}^{d-1} a_i · X^i, evaluate at circle point (x, y):

```
p(x, y) = Σ_{i=0}^{d-1} a_i · (x + i·y)^i
```

where we interpret the circle point as a complex-like number x + i·y with i^2 = -1.

### Circle Interpolation

Given evaluations p(x_k, y_k) at circle points, interpolate to recover coefficients:

```
a_i = (1/n) · Σ_{k=0}^{n-1} p(x_k, y_k) · (x_k - i·y_k)^{-i}
```

This uses the inverse FFT over the circle.

### Trace Polynomials

In Circle-STARKs, the execution trace is represented as polynomials evaluated on the circle:

```
T_i(x, y) = trace column i evaluated at (x, y)
```

The trace polynomials satisfy transition constraints:

```
T_i(x', y') = f(T_0(x, y), T_1(x, y), ..., T_{m-1}(x, y))
```

where (x', y') is the next point on the circle.

### Transition Constraints

For a state transition from (x, y) to (x', y'):

```
T_{i+1}(x', y') = TRANSITION(T_i(x, y), ...)
```

The transition function is encoded as a polynomial constraint:

```
P(x, y, x', y', T_0, ..., T_{m-1}) = 0
```

### Quotient Polynomial

The quotient polynomial Q(x, y) encodes constraint violations:

```
Q(x, y) = P(x, y, x', y', T_0, ..., T_{m-1}) / Z(x, y)
```

where Z(x, y) is the zerofier polynomial that vanishes on the constraint domain.

### Circle-STARK Proof Structure

1. **Trace Commitment**: Merkle root of trace evaluations on circle
2. **Constraint Polynomials**: Polynomials encoding transition and boundary constraints
3. **Quotient Polynomial**: Q(x, y) = constraint violations / zerofier
4. **FRI Proof**: Low-degree test for quotient polynomial

## Implementation Details

### Circle Point Generation

Generate n equally spaced points on the circle:

```
for k = 0 to n-1:
    θ = 2πk/n
    x_k = cos(θ) mod p
    y_k = sin(θ) mod p
```

where p is the field modulus.

### Circle FFT Algorithm

The Circle-FFT uses the group structure:

```
FFT_CIRCLE(p, n):
    for k = 0 to n-1:
        result[k] = p(cos(2πk/n), sin(2πk/n))
    return result
```

### Transition Function

The transition function maps circle points:

```
(x', y') = (x·cos(2π/n) - y·sin(2π/n), x·sin(2π/n) + y·cos(2π/n))
```

This rotates the point by angle 2π/n around the circle.

## Advantages of Circle-STARKs

1. **Efficient FFT**: Circle-FFT is naturally parallelizable
2. **Recursive Composition**: Circle structure enables efficient recursive proofs
3. **Small Field**: Can work over smaller fields than standard STARKs
4. **Natural Group Structure**: Circle group operations are efficient

## Soundness Analysis

Circle-STARKs maintain the same soundness properties as standard STARKs:

```
ε ≤ (1 - ρ)^t · (d / |F|)
```

where:
- ρ is the FRI rate
- t is the number of FRI rounds
- d is the maximum constraint degree
- |F| is the field size

## References

- "Circle-STARKs" (2023)
- Implementation: `internal/proteus/protocols/circle_starks.go`
- Related: `internal/proteus/core/circle_fft.go`

