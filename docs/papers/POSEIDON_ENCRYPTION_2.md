# Poseidon Encryption 2

## Overview

Poseidon Encryption 2 is an enhanced variant of the Poseidon hash function optimized for encryption use cases in zero-knowledge proof systems. It extends the basic Poseidon construction with encryption-specific features while maintaining the constraint efficiency of the original design.

## Mathematical Foundation

### Encryption Mode

Poseidon Encryption uses the hash function in an encryption mode:

```
C = H(K || M) ⊕ M
```

where:
- K is the encryption key
- M is the plaintext message
- H is the Poseidon hash function
- C is the ciphertext

### Keyed Hashing

The encryption variant uses keyed hashing:

```
H_K(M) = Poseidon(K || M)
```

The key K is absorbed into the sponge state before the message M.

## Mathematical Formulations

### Encryption Process

1. **Key Absorption**: Absorb key K into sponge state
   ```
   state = Poseidon_absorb(K)
   ```

2. **Message Processing**: Process message M in blocks
   ```
   for each block M_i:
       state = Poseidon_permute(state)
       C_i = state[0:r] ⊕ M_i
   ```

3. **Finalization**: Squeeze final ciphertext block
   ```
   C_final = Poseidon_squeeze(state, length)
   ```

### Decryption Process

Decryption is symmetric:

1. **Key Absorption**: Absorb same key K
2. **Ciphertext Processing**: XOR ciphertext with sponge output
3. **Message Recovery**: Recover plaintext M

### Security Properties

Poseidon Encryption 2 provides:
- **Confidentiality**: Ciphertext reveals no information about plaintext
- **Integrity**: Any modification is detected
- **ZK-friendly**: Low constraint count in proofs

## Enhanced Features

### Authentication

Add authentication tag:

```
T = H(K || M || nonce)
C = H(K || M) ⊕ M
```

Verification:
```
T' = H(K || M' || nonce)
Accept if T' = T
```

### Nonce Support

Include nonce for uniqueness:

```
C = H(K || nonce || M) ⊕ M
```

This ensures:
- **Uniqueness**: Same plaintext produces different ciphertexts
- **Replay protection**: Nonce prevents replay attacks

### Variable-Length Support

Handle variable-length messages:

1. **Padding**: Pad message to block size
2. **Length encoding**: Include length in hash input
3. **Final block**: Handle partial final block

## Implementation Details

### Key Schedule

The key K is processed as:

```
K = K_0 || K_1 || ... || K_{k-1}
```

Each key block K_i is absorbed into the sponge state.

### Message Blocks

Messages are processed in blocks of size r (rate):

```
M = M_0 || M_1 || ... || M_{m-1}
```

Each block M_i is XORed with sponge output.

### Constraint Count

For encryption of n blocks:

- **Key absorption**: 1 hash = ~122 constraints
- **Per block**: 1 permutation + XOR = ~4 constraints
- **Total**: 122 + 4n constraints

## Security Analysis

### IND-CPA Security

Poseidon Encryption 2 provides Indistinguishability under Chosen Plaintext Attack (IND-CPA) if:
- Poseidon hash is a secure PRF
- Nonce is unique for each encryption

### Key Size

Recommended key sizes:
- **128-bit security**: 128-bit key
- **256-bit security**: 256-bit key

### Nonce Requirements

- **Uniqueness**: Nonce must be unique per encryption
- **Randomness**: Nonce should be random or counter-based
- **Size**: Typically 64-128 bits

## Comparison with Standard Encryption

### vs AES

- **Constraints**: Poseidon ~126, AES ~6,400
- **Speed in ZK**: Poseidon much faster
- **Security**: Both provide 128-bit security

### vs ChaCha20

- **Constraints**: Similar (~100-200)
- **Security**: Both stream ciphers
- **ZK optimization**: Poseidon better optimized

## Use Cases

1. **Private Transactions**: Encrypt transaction data in ZK proofs
2. **Private Computation**: Encrypt intermediate values
3. **Commitment Schemes**: Use as commitment with encryption

## References

- "Poseidon Encryption 2" (variant specification)
- Base implementation: `pkg/vybium-crypto/hash/poseidon.go`
- Encryption mode: Extends base Poseidon with encryption-specific features

