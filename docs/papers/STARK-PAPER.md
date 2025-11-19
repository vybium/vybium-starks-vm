# STARKs: Scalable Transparent ARguments of Knowledge

## Overview

STARKs (Scalable Transparent ARguments of Knowledge) are zero-knowledge proof systems that provide:
- **Transparency**: No trusted setup required
- **Scalability**: Proof size and verification time scale logarithmically
- **Post-quantum security**: Based on hash functions, not discrete log
- **Efficiency**: Fast proving and verification

## Mathematical Foundation

### Arithmetic Intermediate Representation (AIR)

An AIR instance consists of:
- **Execution trace**: T = {T_0, T_1, ..., T_{n-1}} where each T_i ∈ F^w
- **Transition constraints**: Polynomials P_j(X, Y, T_i, T_{i+1}) = 0
- **Boundary constraints**: Polynomials B_k(T_0) = 0 or B_k(T_{n-1}) = 0

### Polynomial Commitment

STARKs use Merkle trees to commit to polynomial evaluations:

```
Commit(f) = MerkleRoot(f(ω^0), f(ω^1), ..., f(ω^{n-1}))
```

where f is a polynomial and ω is a primitive n-th root of unity.

## Mathematical Formulations

### Trace Polynomials

The execution trace is interpolated into polynomials:

```
T_j(X) = Σ_{i=0}^{n-1} T_{i,j} · L_i(X)
```

where L_i(X) is the i-th Lagrange basis polynomial over domain D = {ω^0, ..., ω^{n-1}}.

### Transition Constraints

Transition constraints are encoded as:

```
P(X, g·X, T_0(X), ..., T_{w-1}(X), T_0(g·X), ..., T_{w-1}(g·X)) = 0
```

for all X ∈ D \ {ω^{n-1}}, where g = ω is the domain generator.

This ensures:
```
T_{i+1} = TRANSITION(T_i)
```

### Boundary Constraints

Boundary constraints are:

```
B(T_0(1)) = 0  (initial state)
B(T_{w-1}(ω^{n-1})) = 0  (final state)
```

### Composition Polynomial

The composition polynomial combines all constraints:

```
C(X) = Σ_{j} α_j · P_j(X, g·X, T_0, ..., T_{w-1}) / Z(X)
```

where:
- α_j are random challenges from verifier
- Z(X) is the zerofier polynomial
- P_j are constraint polynomials

### Zerofier Polynomial

The zerofier Z(X) vanishes on the constraint domain:

```
Z(X) = Π_{x ∈ D_constraint} (X - x)
```

For transition constraints:
```
Z_transition(X) = (X^n - 1) / (X - ω^{n-1})
```

### Quotient Polynomial

The quotient polynomial is:

```
Q(X) = C(X) / Z(X)
```

This polynomial has degree:
```
deg(Q) ≤ max_degree - |D_constraint|
```

More precisely, if the composition polynomial C(X) has degree d_C and the zerofier Z(X) has degree d_Z, then:

```
deg(Q) = d_C - d_Z
```

For transition constraints with degree-2 polynomials and domain size n:
- d_C = 2·(n-1) (degree of composition)
- d_Z = n-1 (degree of transition zerofier)
- deg(Q) = n-1

The quotient domain must have size at least deg(Q) + 1 = n to accommodate Q(X).

### Low-Degree Extension

To achieve zero-knowledge, extend the trace to a larger domain:

```
D_extended = {ω^0, ..., ω^{2n-1}}
```

Add random values to extended portion:
```
T_j(ω^{n+i}) = random  for i = 0, ..., n-1
```

The extension factor (2x) ensures:
- **Zero-knowledge**: Random values hide the actual trace
- **Soundness**: Extension doesn't affect constraint satisfaction
- **Efficiency**: Minimal overhead (doubles domain size)

The randomized trace domain D_rand has size 2n, where:
- First n points: Original trace values
- Last n points: Random values (trace randomizers)

This provides statistical zero-knowledge with soundness error ≤ 1/|F| per randomizer.

### FRI Protocol

STARKs use FRI to prove that Q(X) has low degree:

1. **Commit**: Prover commits to Q(X) via Merkle tree
2. **Fold**: Verifier sends challenge, prover folds polynomial
3. **Repeat**: Continue until constant polynomial
4. **Verify**: Verifier checks final constant

## Soundness Analysis

### Soundness Error

The soundness error is:

```
ε ≤ (1 - ρ)^t · (d / |F|)
```

where:
- ρ is the FRI rate (typically 1/4)
- t is the number of FRI rounds
- d is the maximum constraint degree
- |F| is the field size

### Security Level

For security level λ (bits):

```
ε ≤ 2^{-λ}
```

This requires:
```
(1 - ρ)^t · (d / |F|) ≤ 2^{-λ}
```

Typical parameters:
- ρ = 1/4
- t = 20 (for n = 2^20)
- d = 2 (quadratic constraints)
- |F| = 2^64 (Goldilocks field)

```
ε ≤ (3/4)^20 · (2 / 2^64) ≈ 0.003 · 2^{-63} ≈ 2^{-68}
```

This provides ~68 bits of security.

## Proof Structure

### STARK Proof Components

1. **Trace Commitment**: Merkle root of trace evaluations
2. **Constraint Polynomials**: Commitments to constraint evaluations
3. **Quotient Commitment**: Merkle root of quotient polynomial
4. **FRI Proof**: Low-degree test for quotient
5. **Query Proofs**: Merkle paths for verifier queries

### Proof Size

- **Trace commitment**: 1 hash (32 bytes)
- **Constraint commitments**: O(1) hashes
- **Quotient commitment**: 1 hash
- **FRI proof**: O(log n) hashes
- **Query proofs**: O(λ · log n) hashes

Total: O(λ · log n) hashes ≈ O(λ · log n · 32) bytes

For n = 2^20, λ = 128:
```
Proof size ≈ 128 · 20 · 32 = 81,920 bytes ≈ 80 KB
```

## Verification Process

### Verifier Steps

1. **Receive commitments**: Get Merkle roots
2. **Send challenges**: Sample random field elements
3. **Receive FRI proof**: Get FRI layers and final polynomial
4. **Query trace**: Request trace values at random points
5. **Verify constraints**: Check constraint polynomials
6. **Verify FRI**: Check FRI proof consistency
7. **Accept/Reject**: Based on all checks

### Query Complexity

The verifier makes O(λ) queries:
- Trace queries: O(λ)
- Constraint queries: O(λ)
- FRI queries: O(log n)

Total: O(λ + log n) queries

## Implementation Details

### Domain Derivation

Domains are derived as:

1. **Trace domain**: D_trace = ⟨ω⟩, size = n
2. **Randomized trace**: D_rand = ⟨ω'⟩, size = 2n (for zero-knowledge)
3. **Quotient domain**: D_quotient = ⟨ω''⟩, size = next_power_of_2(max_degree)
4. **FRI domain**: D_FRI = ⟨ω_FRI⟩, size = expansion_factor · |D_quotient|

### Zero-Knowledge

Zero-knowledge is achieved by:
1. **Randomizers**: Add random values to trace extension
2. **Random challenges**: Verifier's challenges are random
3. **Hiding commitments**: Merkle trees hide individual values

### Optimization Techniques

1. **Batch verification**: Verify multiple proofs together
2. **Parallel FRI**: Compute FRI layers in parallel
3. **Fast interpolation**: Use NTT for polynomial operations

## References

- "Scalable, transparent, and post-quantum secure computational integrity" (2018)
- Implementation: `internal/proteus/protocols/stark.go`
- Prover: `internal/proteus/protocols/prover.go`
- Verifier: `internal/proteus/protocols/verifier.go`
- FRI: `internal/proteus/protocols/fri.go`

