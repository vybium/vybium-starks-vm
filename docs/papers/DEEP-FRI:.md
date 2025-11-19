# DEEP-FRI: Sampling Outside the Box Improves Soundness

## Overview

DEEP-FRI (Domain Extension to Eliminate Pretenders) is an enhancement to the FRI protocol that improves soundness by sampling evaluation points outside the original domain D. This eliminates "pretender" polynomials that are close to low-degree on D but not globally low-degree.

## Mathematical Foundation

### Standard FRI Protocol

FRI proves that a function f: D → F is δ-close to a polynomial of degree < d, where:
- D = ⟨ω⟩ is a multiplicative subgroup of F^*
- δ is the proximity parameter (typically δ = 1 - ρ, where ρ is the rate)
- d = ρ·|D| is the degree bound

### DEEP-FRI Enhancement

DEEP-FRI extends the domain to D̄ ⊃ D and samples external points z ∈ D̄ \ D. This improves soundness by ensuring that any function close to low-degree on D must also be low-degree globally.

## Mathematical Formulations

### Domain Extension

Given original domain D = {ω^0, ω^1, ..., ω^{N-1}} where N = |D|, extend to:

```
D̄ = D ∪ {external points}
```

The extended domain D̄ has size |D̄| = 2N (or larger).

### External Point Sampling

Sample external points z ∈ D̄ \ D uniformly at random. For each external point z, evaluate the function:

```
f(z) = Σ_{i=0}^{N-1} f(ω^i) · L_i(z)
```

where L_i(X) is the i-th Lagrange basis polynomial over D.

### DEEP Technique

The DEEP technique modifies the function before folding:

```
f'(x) = f(x) - U(x) + α · (f(z) - U(z))
```

where:
- U(X) is a polynomial that matches external evaluations
- z is an external point
- α is a random challenge from the verifier

This ensures consistency between the function on D and its evaluation at external points.

### Folding Formula with External Points

In each FRI round, the folding formula becomes:

```
f^{(i+1)}(y) = (1 - x^{(i)}) · f^{(i)}(y) + x^{(i)} · f^{(i)}(ω^i · y)
```

where:
- f^{(i)}: S^{(i)} → F is the function at layer i
- S^{(i)} = ⟨ω^{2^i}⟩ is the domain at layer i
- x^{(i)} is the verifier's challenge
- ω^i is the generator of the cyclic group

For external points, we compute:

```
f^{(i+1)}(z) = (1 - x^{(i)}) · f^{(i)}(z) + x^{(i)} · f^{(i)}(ω^i · z)
```

### Computing ω^i · z

For an external point z ∉ S^{(i)}, we need to compute ω^i · z. Since z is not in the cyclic group ⟨ω^{2^i}⟩, we use the field structure:

```
ω^i · z = z · ω^i
```

This multiplication is done directly in the field F.

### Soundness Improvement

DEEP-FRI improves soundness from:

```
ε_FRI ≈ (1 - ρ)^t
```

to:

```
ε_DEEP-FRI ≈ (1 - ρ)^t · (1 / |F|)
```

where t is the number of FRI rounds and |F| is the field size.

The additional factor 1/|F| comes from the probability that a pretender polynomial accidentally evaluates correctly at the external point.

## Implementation Details

### External Point Selection

1. Extend domain: D̄ = D ∪ {field elements outside D}
2. Sample k external points uniformly: z_1, ..., z_k ∈ D̄ \ D
3. Evaluate function at external points using Lagrange interpolation

### DEEP Modification

For each external point z_j:

1. Compute U_j(X) such that U_j(z_j) = f(z_j)
2. Modify function: f'(x) = f(x) - U_j(x) + α_j · (f(z_j) - U_j(z_j))
3. Proceed with standard FRI folding

### Verification

The verifier checks:

1. Merkle root consistency for each layer
2. External evaluations match claimed values
3. Folding consistency: f^{(i+1)}(y) matches the folding formula
4. Final polynomial has degree < d

## Mathematical Properties

### Group Theory

The domain D = ⟨ω⟩ forms a cyclic group of order N. For external points z:

- z ∉ ⟨ω⟩, so z is not a power of ω
- Multiplication by ω^i rotates within the group structure
- External points provide "out-of-group" constraints

### Polynomial Interpolation

For external evaluation at z:

```
f(z) = Σ_{i=0}^{N-1} f(ω^i) · L_i(z)
```

where L_i(z) = Π_{j≠i} (z - ω^j) / (ω^i - ω^j)

This requires O(N) field operations per external point.

## Soundness Analysis

The soundness error bound for DEEP-FRI is:

```
ε ≤ (1 - ρ)^t · (k / |F|)
```

where:
- ρ is the FRI rate (typically 1/4)
- t is the number of FRI rounds
- k is the number of external points
- |F| is the field size

For typical parameters (ρ = 1/4, t = 10, k = 2, |F| ≈ 2^64):

```
ε ≈ (3/4)^10 · (2 / 2^64) ≈ 0.056 · 2^{-63} ≈ 2^{-67}
```

## References

- "DEEP-FRI: Sampling Outside the Box Improves Soundness" (2019)
- Implementation: `internal/proteus/protocols/deep_fri.go`
- Related: `internal/proteus/protocols/fri.go`

