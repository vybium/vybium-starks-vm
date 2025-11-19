# Aurora: Transparent Succinct Arguments for R1CS

## Overview

Aurora is a transparent (no trusted setup) and succinct (sublinear proof size) argument system for Rank-1 Constraint Systems (R1CS). It achieves linear proof length O(N) with logarithmic query complexity O(log N).

## Mathematical Foundation

### Rank-1 Constraint System (R1CS)

An R1CS instance consists of three matrices A, B, C ∈ F^{m×n} and a public input vector v ∈ F^k. A witness w ∈ F^{n-k-1} satisfies the R1CS if:

```
(Az) ◦ (Bz) = Cz
```

where z = (1, v, w) ∈ F^n is the full assignment, and ◦ denotes element-wise (Hadamard) product.

### Aurora Protocol Structure

Aurora uses three main components:

1. **Reed-Solomon Encoding**: Encodes vectors as polynomials over a domain D
2. **Univariate Sumcheck**: Proves sums over subsets of the domain
3. **Rowcheck and Lincheck**: Verify R1CS constraints

## Mathematical Formulations

### Reed-Solomon Encoding

Given a vector z ∈ F^n, encode it as a polynomial f_z(X) such that:

```
f_z(α^i) = z_i  for i = 0, 1, ..., n-1
```

where D = {α^0, α^1, ..., α^{n-1}} is the evaluation domain.

The encoding polynomial is constructed via Lagrange interpolation:

```
f_z(X) = Σ_{i=0}^{n-1} z_i · L_i(X)
```

where L_i(X) is the i-th Lagrange basis polynomial:

```
L_i(X) = Π_{j≠i} (X - α^j) / (α^i - α^j)
```

### Linear Transformations

For matrix M ∈ F^{m×n} and vector z ∈ F^n, compute Mz:

```
f_{Mz}(X) = Σ_{i=0}^{m-1} (Σ_{j=0}^{n-1} M_{i,j} · z_j) · L_i(X)
```

This can be computed efficiently using polynomial evaluation and interpolation.

### Univariate Sumcheck Protocol

Given a polynomial f(X) and a subset H ⊆ D, prove:

```
Σ_{x ∈ H} f(x) = s
```

The sumcheck protocol proceeds in rounds:

1. **Round 0**: Prover sends polynomial g_0(X) = Σ_{x_1,...,x_k ∈ H} f(X, x_1, ..., x_k)
2. **Round i**: Verifier sends challenge r_i, prover sends g_i(X) = Σ_{x_{i+1},...,x_k ∈ H} f(r_0, ..., r_{i-1}, X, x_{i+1}, ..., x_k)
3. **Final**: Verifier checks g_k(r_k) = f(r_0, ..., r_k) and Σ_{x ∈ H} g_0(x) = s

### Rowcheck Protocol

Rowcheck verifies that the encoded witness satisfies row-wise constraints. For each row i:

```
Σ_{j=0}^{n-1} A_{i,j} · z_j = (Az)_i
```

This is proven using univariate sumcheck over the domain D.

### Lincheck Protocol

Lincheck verifies linear consistency between encoded vectors. Given f_{Az}, f_{Bz}, f_{Cz}, prove:

```
Σ_{x ∈ D} (f_{Az}(x) · f_{Bz}(x) - f_{Cz}(x)) · v(x) = 0
```

for a random challenge polynomial v(X) sampled by the verifier.

## Soundness Analysis

### IOP Soundness Error

The soundness error of Aurora IOP consists of multiple components:

```
ε_i ≤ (m + 1) / |F| + |L| / |F| + ε_FRI_i(F, L)
ε_q ≤ ε_FRI_q(L, ρ, δ)
```

where:
- m is the number of constraints
- |F| is the field size
- |L| is the size of the evaluation domain
- ε_FRI_i and ε_FRI_q are FRI soundness errors
- ρ is the FRI rate
- δ is the proximity parameter

### zkSNARK Soundness Error

For the zero-knowledge SNARK variant (after applying BCS transformation):

```
ε ≤ ((m + 1) / |F|)^λ_i + (|L| / |F|)^λ'_i + ε_FRI_i(F, L)^λ_FRI_i
```

where λ_i, λ'_i, λ_FRI_i are repetition parameters for amplification.

## Complexity Analysis

### IOP Complexity

For an R1CS instance with N = Ω(m + n) non-zero entries:

- **Proof Length**: p = (5 + 1/3)|L| field elements
- **Query Complexity**: q_π = O(log |L|)
- **Number of Rounds**: k = O(log |L|)
- **Prover Time**: t_P = O(|L| · log(n + m) + ||A|| + ||B|| + ||C||) + 17 · FFT(F, |L|)
- **Verifier Time**: t_V = O(||A|| + ||B|| + ||C|| + n + m + log |L|)

where ||A||, ||B||, ||C|| denote the number of non-zero entries in each matrix.

### zkSNARK Complexity

After applying the BCS transformation to the IOP:

- **Proof Length**: O_λ(log^2 N) field elements
- **Prover Time**: O_λ(N log N) field operations
- **Verifier Time**: O_λ(N) field operations

At 128 bits of security, proofs are less than 250 kB even for several million constraints, more than 10× shorter than prior zkSNARGs with similar features.

## Implementation Notes

- **Domain Selection**: Use multiplicative subgroup of F^* with size n = 2^k
- **Polynomial Interpolation**: Use NTT for efficient encoding/decoding
- **Sumcheck Rounds**: Number of rounds = log_2(|H|)
- **Query Complexity**: O(log N) queries to encoded polynomials
- **FFT Operations**: Each IOP round requires 17 FFT operations over domain |L|

## References

- "Aurora: Transparent Succinct Arguments for R1CS" (2019)
- Implementation: `internal/proteus/protocols/aurora_r1cs.go`
- Integration: `internal/proteus/protocols/aurora_stark_integration.go`

