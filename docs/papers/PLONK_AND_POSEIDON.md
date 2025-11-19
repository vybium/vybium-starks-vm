# PLONK and Poseidon

## Overview

PLONK (Permutations over Lagrange-bases for Oecumenical Noninteractive arguments of Knowledge) is a universal zk-SNARK that supports arbitrary circuits without per-circuit trusted setup. Poseidon is a hash function optimized for zero-knowledge proof systems, designed to minimize the number of constraints in R1CS/Plonk arithmetization.

## PLONK Protocol

### Mathematical Foundation

PLONK uses polynomial commitments and permutation arguments to prove circuit satisfiability. The protocol works over a finite field F with evaluation domain D = {ω^0, ω^1, ..., ω^{n-1}}.

### Circuit Arithmetization

A PLONK circuit is represented as:
- **Wires**: n wires with values a_0, a_1, ..., a_{n-1}
- **Gates**: Constraints of the form q_L·a_i + q_R·a_j + q_O·a_k + q_M·(a_i·a_j) + q_C = 0

### Copy Constraints

PLONK uses permutation arguments to enforce copy constraints (wire equality):

```
σ: [n] → [n]  (permutation)
```

The permutation ensures that wires with the same value are "copied" correctly.

### Polynomial Commitments

PLONK uses polynomial commitments to commit to:
- Wire values: a(X) such that a(ω^i) = a_i
- Permutation: S_{ID}(X), S_{σ}(X) encoding the permutation

### PLONK Proof Structure

1. **Round 1**: Prover commits to wire polynomials a(X), b(X), c(X)
2. **Round 2**: Verifier sends challenges β, γ
3. **Round 3**: Prover commits to permutation polynomial z(X)
4. **Round 4**: Verifier sends challenge α
5. **Round 5**: Prover commits to quotient polynomial t(X)
6. **Round 6**: Verifier sends challenge ζ
7. **Round 7**: Prover opens polynomials at ζ

### Permutation Argument

The permutation argument proves copy constraints (wire equality) using a product check:

```
Π_{i=0}^{n-1} (a_i + β·ω^i + γ) / (a_i + β·S_{σ}(ω^i) + γ) = 1
```

This is encoded as a polynomial z(X) that accumulates the product:

```
z(ω^0) = 1
z(ω^{i+1}) = z(ω^i) · (a(ω^i) + β·ω^i + γ) / (a(ω^i) + β·S_{σ}(ω^i) + γ)
```

The polynomial z(X) satisfies:

```
z(X) · (a(X) + β·X + γ) = z(g·X) · (a(X) + β·S_{σ}(X) + γ)
```

where g = ω is the domain generator. This ensures z(ω^n) = z(1) = 1, verifying all copy constraints.

### Quotient Polynomial

The quotient polynomial t(X) encodes all constraints:

```
t(X) = (gate_constraints + permutation_constraints) / Z_H(X)
```

where Z_H(X) = X^n - 1 is the vanishing polynomial over domain H.

## Poseidon Hash Function

### Mathematical Foundation

Poseidon is a cryptographic hash function based on the sponge construction, optimized for zero-knowledge proof systems. It uses:
- **Sponge Construction**: Absorb-squeeze paradigm
- **MDS Matrix**: Maximum Distance Separable matrix for diffusion
- **S-box**: x^α where α is small (typically 3 or 5)
- **Round Constants**: Generated using Grain LFSR

### Sponge Construction

Poseidon uses a sponge with:
- **State**: t field elements (width)
- **Rate**: r elements (absorbed per round)
- **Capacity**: c = t - r elements (security)

```
State = [s_0, s_1, ..., s_{t-1}]
```

### Poseidon Round Function

Each round consists of:

1. **AddRoundConstants**: state[i] += RC[round][i]
2. **S-box**: state[i] = state[i]^α
3. **MDS Matrix**: state = MDS · state

### Full Rounds vs Partial Rounds

- **Full Rounds (R_F)**: Apply S-box to all t elements
- **Partial Rounds (R_P)**: Apply S-box only to first element

Total rounds: R = R_F + R_P

### S-box Power

The S-box is x^α where α is chosen to minimize constraints:
- α = 3: Requires 2 constraints (x^2, then x^2·x)
- α = 5: Requires 3 constraints (x^2, x^4, then x^4·x)

### MDS Matrix

The MDS (Maximum Distance Separable) matrix ensures maximum diffusion:

```
MDS ∈ F^{t×t}  such that  any square submatrix is invertible
```

This guarantees that changing one input affects all outputs.

### Round Constant Generation

Round constants are generated using Grain LFSR:

```
Grain_LFSR(state) → (bit, new_state)
```

Constants are derived from the LFSR output to ensure no weak constants.

### Security Analysis

Poseidon security depends on:
- **Number of rounds**: R = R_F + R_P
- **S-box power**: α (affects algebraic degree)
- **MDS matrix**: Ensures full diffusion
- **Field size**: |F| (typically 2^64 for Goldilocks)

For 128-bit security:
- R_F = 8 (full rounds)
- R_P = 22 (partial rounds)
- Total: R = 30 rounds

## Integration of PLONK and Poseidon

### Poseidon in PLONK Circuits

Poseidon is optimized for PLONK because:
1. **Low constraint count**: S-box with α = 3 requires only 2 constraints
2. **Field-friendly**: Operations are native field arithmetic
3. **Efficient**: Minimal number of gates per hash

### Constraint Count

For Poseidon with t = 3, r = 2, α = 3:
- **Full round**: 3 S-boxes = 6 constraints + 1 MDS = 7 constraints
- **Partial round**: 1 S-box = 2 constraints + 1 MDS = 3 constraints
- **Total**: 8·7 + 22·3 = 56 + 66 = 122 constraints per hash

### PLONK with Poseidon

When using Poseidon in PLONK:
1. Poseidon hash is encoded as PLONK gates
2. Each S-box becomes 2-3 constraints
3. MDS multiplication becomes linear constraints
4. Total: ~122 constraints per hash call

## Implementation Details

### PLONK Parameters

- **Domain size**: n = 2^k (power of 2)
- **Primitive root**: ω (n-th root of unity)
- **Vanishing polynomial**: Z_H(X) = X^n - 1

### Poseidon Parameters

- **Width**: t (typically 3, 5, or 9)
- **Rate**: r (typically t - 1)
- **Rounds**: R = R_F + R_P
- **S-box power**: α (typically 3 or 5)

### Optimization

1. **Batch hashing**: Process multiple inputs together
2. **Precomputed MDS**: Store MDS matrix for fast multiplication
3. **Parallel S-boxes**: Compute S-boxes in parallel for full rounds

## References

- "PLONK: Permutations over Lagrange-bases for Oecumenical Noninteractive arguments of Knowledge" (2019)
- "Poseidon: A New Hash Function for Zero-Knowledge Proof Systems" (2019)
- Implementation: `internal/proteus/protocols/plonk_poseidon.go`
- Poseidon: `pkg/vybium-crypto/hash/poseidon.go`

