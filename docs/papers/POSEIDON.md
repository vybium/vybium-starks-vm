# Poseidon Hash Function

## Overview

Poseidon is a cryptographic hash function specifically designed for zero-knowledge proof systems. It minimizes the number of constraints in R1CS/Plonk arithmetization while maintaining strong security properties.

## Mathematical Foundation

### Sponge Construction

Poseidon uses the sponge construction paradigm:

```
State = [s_0, s_1, ..., s_{t-1}]  (t elements)
```

The sponge has two phases:
1. **Absorbing**: Input is XORed into rate portion [s_0, ..., s_{r-1}]
2. **Squeezing**: Output is read from rate portion

### State Structure

- **Width**: t (total state size)
- **Rate**: r (elements absorbed/squeezed per round)
- **Capacity**: c = t - r (security parameter)

For 128-bit security with t = 3:
- r = 2 (rate)
- c = 1 (capacity)

## Mathematical Formulations

### Round Function

Each Poseidon round consists of three operations:

#### 1. AddRoundConstants (ARC)

```
state[i] = state[i] + RC[round][i]  for i = 0, ..., t-1
```

where RC[round][i] are round constants.

#### 2. SubWords (S-box)

Apply S-box to state elements:

**Full Round**:
```
state[i] = state[i]^α  for i = 0, ..., t-1
```

**Partial Round**:
```
state[0] = state[0]^α
state[i] = state[i]  for i = 1, ..., t-1
```

where α is the S-box power (typically 3 or 5).

#### 3. MixLayer (MDS Matrix)

```
state = MDS · state
```

where MDS is a Maximum Distance Separable matrix.

### S-box Analysis

The S-box x^α provides:
- **Non-linearity**: High algebraic degree
- **Efficiency**: Low constraint count in ZK proofs

For α = 3:
- Constraint count: 2 (compute x^2, then x^2·x)
- Algebraic degree: 2

For α = 5:
- Constraint count: 3 (compute x^2, x^4, then x^4·x)
- Algebraic degree: 4

### MDS Matrix Properties

An MDS matrix M ∈ F^{t×t} satisfies:

```
det(M_{I,J}) ≠ 0  for any square submatrix M_{I,J}
```

This ensures:
- **Full diffusion**: One input change affects all outputs
- **Maximum distance**: Code distance = t + 1

### Round Constant Generation

Round constants are generated using Grain LFSR to avoid weak constants:

```
Grain_LFSR(state) → (output_bit, new_state)
```

Constants are derived from LFSR output to ensure:
- **Randomness**: No predictable patterns
- **Security**: No weak constant attacks

## Security Analysis

### Number of Rounds

The number of rounds R = R_F + R_P is determined by:

1. **Full rounds (R_F)**: Provide initial and final security
   - Typically R_F = 8 for 128-bit security
   - Typically R_F = 8 for 256-bit security

2. **Partial rounds (R_P)**: Provide middle security
   - R_P = 22 for t = 3, 128-bit security
   - R_P = 56 for t = 3, 256-bit security

### Security Level

For security level M (bits):

```
R_F = 8  (fixed)
R_P = f(t, M)  (depends on width and security)
```

Typical values:
- t = 3, M = 128: R_P = 22, Total = 30
- t = 3, M = 256: R_P = 56, Total = 64
- t = 5, M = 128: R_P = 8, Total = 16

### Algebraic Attacks

Poseidon resists:
- **Linear cryptanalysis**: High non-linearity from S-box
- **Differential cryptanalysis**: MDS provides full diffusion
- **Algebraic attacks**: High algebraic degree

## Implementation Details

### Parameter Selection

For field F with |F| = p:

1. **Choose width t**: Based on rate requirements
2. **Set rate r**: Typically r = t - 1
3. **Compute rounds**: R_F = 8, R_P from security analysis
4. **Generate MDS**: Construct MDS matrix over F
5. **Generate constants**: Use Grain LFSR

### MDS Matrix Construction

MDS matrices can be constructed using:

1. **Cauchy construction**:
   ```
   M_{i,j} = 1/(x_i - y_j)
   ```
   where {x_i} and {y_j} are disjoint sets of field elements. This guarantees MDS property.

2. **Vandermonde construction**:
   ```
   M_{i,j} = x_i^j
   ```
   where x_i are distinct field elements. Requires verification of MDS property.

3. **Circulant construction**:
   ```
   M_{i,j} = c_{(i-j) mod t}
   ```
   where c is a vector. More efficient but requires careful selection of c.

The Cauchy construction is preferred for guaranteed MDS properties, while circulant offers better performance.

### Optimization

1. **Precomputed MDS**: Store MDS matrix for fast multiplication
2. **Batch processing**: Process multiple blocks together
3. **Parallel S-boxes**: Compute S-boxes in parallel for full rounds

## Constraint Count in ZK Proofs

### R1CS Constraints

For S-box x^3:
```
w_1 = x^2      (1 constraint: w_1 = x · x)
w_2 = w_1 · x  (1 constraint: w_2 = w_1 · x)
```

Total: 2 constraints per S-box

For S-box x^5:
```
w_1 = x^2      (1 constraint)
w_2 = w_1^2    (1 constraint: w_2 = w_1 · w_1)
w_3 = w_2 · x  (1 constraint)
```

Total: 3 constraints per S-box

### Total Constraints

For Poseidon with t = 3, R_F = 8, R_P = 22, α = 3:

- **Full rounds**: 8 rounds × 3 S-boxes × 2 constraints = 48 constraints
- **Partial rounds**: 22 rounds × 1 S-box × 2 constraints = 44 constraints
- **MDS multiplications**: 30 rounds × 1 matrix = 30 constraints (linear)
- **Total**: ~122 constraints per hash

## Comparison with Other Hashes

### vs SHA-256

- **Constraints**: Poseidon ~122, SHA-256 ~25,000
- **Speed**: Poseidon faster in ZK proofs
- **Security**: Both 128-bit security

### vs Pedersen Hash

- **Constraints**: Similar (~100-200)
- **Security**: Poseidon has better security analysis
- **Flexibility**: Poseidon supports variable input length

## References

- "Poseidon: A New Hash Function for Zero-Knowledge Proof Systems" (2019)
- Implementation: `pkg/vybium-crypto/hash/poseidon.go`
- Enhanced version: `internal/proteus/core/poseidon_enhanced.go`
- Constraints: `internal/proteus/protocols/poseidon_constraints.go`

