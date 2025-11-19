# Fast Reed-Solomon Interactive Oracle Proofs of Proximity (FRI)

## Overview

FRI is an Interactive Oracle Proof (IOP) system for proving that a function f: D → F is δ-close to a Reed-Solomon codeword of degree < d. FRI achieves logarithmic proof size and query complexity.

## Mathematical Foundation

### Reed-Solomon Codes

A Reed-Solomon code RS[F, D, d] consists of all polynomials p(X) over field F of degree < d, evaluated over domain D:

```
RS[F, D, d] = {p: D → F | deg(p) < d}
```

The code has:
- **Length**: N = |D|
- **Dimension**: d (number of coefficients)
- **Rate**: ρ = d/N
- **Distance**: N - d + 1 (minimum Hamming distance)

### Proximity Testing

Given function f: D → F, determine if f is δ-close to RS[F, D, d], i.e., if there exists polynomial p(X) with deg(p) < d such that:

```
|{x ∈ D : f(x) ≠ p(x)}| ≤ δ·N
```

## FRI Protocol Specification

### Setup

- **Field**: F (finite field, typically Goldilocks: p = 2^64 - 2^32 + 1)
- **Domain**: D = ⟨ω⟩ = {ω^0, ω^1, ..., ω^{N-1}} where ω is a primitive N-th root of unity
- **Rate**: ρ = d/N (typically ρ = 1/4 for soundness)
- **Proximity**: δ = 1 - ρ (typically δ = 3/4)

### Protocol Structure

FRI proceeds in layers, each halving the domain size:

1. **Layer 0**: Domain S^(0) = ⟨ω⟩, function f^(0): S^(0) → F
2. **Layer i**: Domain S^(i) = ⟨ω^{2^i}⟩, function f^(i): S^(i) → F
3. **Final**: Constant function (degree 0)

## Mathematical Formulations

### Domain Structure

The domain forms a multiplicative subgroup:

```
S^(0) = ⟨ω⟩ = {ω^0, ω^1, ..., ω^{N-1}}
S^(1) = ⟨ω^2⟩ = {ω^0, ω^2, ..., ω^{2(N/2-1)}}
S^(2) = ⟨ω^4⟩ = {ω^0, ω^4, ..., ω^{4(N/4-1)}}
...
S^(t) = {ω^0} = {1}  (constant)
```

Each domain S^(i) has size N/2^i and generator ω^{2^i}.

### Folding Formula

In each round i, the prover commits to f^(i) and receives challenge x^(i) from the verifier. The next function is:

```
f^(i+1)(y) = (1 - x^(i)) · f^(i)(y) + x^(i) · f^(i)(ω^i · y)
```

This formula folds the function by combining evaluations at y and ω^i · y.

### Collinearity Check

The folding formula ensures that for any y ∈ S^(i+1), the three points:

```
P_1 = (y, f^(i)(y))
P_2 = (ω^i · y, f^(i)(ω^i · y))
P_3 = (y, f^(i+1)(y))
```

are collinear. This is verified by checking that the points lie on a line:

```
det([P_1, P_2, P_3]) = 0
```

which simplifies to:

```
f^(i+1)(y) = (1 - x^(i)) · f^(i)(y) + x^(i) · f^(i)(ω^i · y)
```

The collinearity ensures that f^(i+1) is a valid folding of f^(i), maintaining the low-degree property.

### Computing ω^i · y

For y ∈ S^(i+1) = ⟨ω^{2^{i+1}}⟩, we have y = (ω^{2^{i+1}})^j for some j. Then:

```
ω^i · y = ω^i · (ω^{2^{i+1}})^j = ω^{i + j·2^{i+1}}
```

Since S^(i) = ⟨ω^{2^i}⟩, we need to find the index in S^(i):

```
ω^{i + j·2^{i+1}} = (ω^{2^i})^{k}  for some k
```

This requires computing the discrete logarithm or using the group structure directly.

### Soundness Analysis

The soundness error for FRI is:

```
ε_FRI ≤ (1 - ρ)^t
```

where:
- ρ is the rate (typically 1/4)
- t is the number of rounds (t = log_2(N))

For N = 2^20 and ρ = 1/4:

```
ε_FRI ≤ (3/4)^20 ≈ 0.0032 ≈ 2^{-8.3}
```

To achieve 2^{-λ} security, we need:

```
(1 - ρ)^t ≤ 2^{-λ}
t · log_2(1 - ρ) ≤ -λ
t ≥ λ / (-log_2(1 - ρ))
```

For ρ = 1/4: t ≥ λ / 1.415

### Query Complexity

FRI requires O(log N) queries:
- One query per layer to verify folding
- Total: t = log_2(N) queries

### Proof Size

The proof consists of:
- **Merkle roots**: O(t) = O(log N) hash digests
- **Final polynomial**: O(1) field elements (constant polynomial)
- **Merkle paths**: O(t · log N) = O((log N)^2) hash digests for query verification

Total: O((log N)^2) hash digests + O(1) field elements.

For N = 2^20:
- Merkle roots: ~20 hashes
- Merkle paths: ~400 hashes (for 20 queries)
- Final polynomial: 1 field element
- Total: ~421 hashes + 1 field element ≈ 13.5 KB

## Implementation Details

### Rate Validation

The rate must satisfy:

```
ρ = 2^{-R}  where R ≥ 2
```

This ensures ρ ≤ 1/4, which is required for soundness.

### Domain Generation

For domain size N = 2^k:

1. Find primitive N-th root of unity: ω such that ω^N = 1 and ω^i ≠ 1 for i < N
2. Generate domain: D = {ω^0, ω^1, ..., ω^{N-1}}

### Folding Implementation

For each round:

1. Prover commits to f^(i) via Merkle tree
2. Verifier sends random challenge x^(i) ∈ F
3. Prover computes f^(i+1) using folding formula
4. Verifier queries random points to verify collinearity

### Final Polynomial

When |S^(t)| = 1, the function is constant:

```
f^(t)(1) = c
```

The final polynomial is p(X) = c (constant polynomial).

## Optimization Techniques

### Batch Folding

Process multiple functions simultaneously:

```
f_1^(i+1)(y) = (1 - x^(i)) · f_1^(i)(y) + x^(i) · f_1^(i)(ω^i · y)
f_2^(i+1)(y) = (1 - x^(i)) · f_2^(i)(y) + x^(i) · f_2^(i)(ω^i · y)
```

This reduces the number of Merkle tree constructions.

### Parallel Evaluation

Evaluate folding formula in parallel:

```
for each y in S^(i+1) in parallel:
    f^(i+1)(y) = (1 - x^(i)) · f^(i)(y) + x^(i) · f^(i)(ω^i · y)
```

## References

- "Fast Reed-Solomon Interactive Oracle Proofs of Proximity" (TR17-134, 2017)
- Implementation: `internal/proteus/protocols/fri.go`
- Enhanced version: `internal/proteus/protocols/deep_fri.go`

