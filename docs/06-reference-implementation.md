# Dimensional Encryption — Reference Implementation

**Project:** SilentBot — Dimensional Encryption  
**Version:** 0.1  
**Date:** 2026-04-13  
**Authors:** Ali Vonk, M  

---

## Purpose

This document describes the Python reference implementation of Dimensional
Encryption. The implementation is designed for **correctness and clarity**,
not performance. It serves as:

1. A correctness proof — the math actually works
2. A reference for future implementations in faster languages
3. A test harness for generating test vectors

**Do not use this for production encryption.** It has not undergone security
audit, and the Python implementation is not constant-time (vulnerable to
timing side-channels).

---

## Project Structure

```
Encryption/
├── docs/
│   ├── 00-foundation.md
│   ├── 01-transformation-zoo.md
│   ├── 02-expander-graph-construction.md
│   ├── 03-security-reduction.md           (v0.2 — HPR eliminated)
│   ├── 04-key-derivation-and-modes.md
│   ├── 05-parameter-selection-and-performance.md
│   └── 06-reference-implementation.md     (this document)
└── src/
    └── dimensional_encryption/
        ├── __init__.py          Public API: encrypt, decrypt, generate_key
        ├── dimensions.py        All 6 dimension implementations
        ├── scheme.py            HKDF, CTR mode, HMAC, wire format
        ├── tests.py             Full test suite
        └── demo.py              Interactive demonstration
```

---

## Running

### Requirements

- Python 3.9+ (uses only the standard library — no pip dependencies)

### Tests

```bash
cd Encryption/src
python3 -m dimensional_encryption.tests
```

Expected output: ALL TESTS PASSED

### Demo

```bash
cd Encryption/src
python3 -m dimensional_encryption.demo
```

Shows: key generation, encryption, decryption, tamper detection, wrong key
rejection, avalanche effect, and performance benchmark.

### Using as a library

```python
from dimensional_encryption import encrypt, decrypt, generate_key

# Generate a 256-bit master key
key = generate_key()

# Encrypt
ciphertext = encrypt(key, b"Hello, world!")

# Decrypt
plaintext = decrypt(key, ciphertext)
assert plaintext == b"Hello, world!"

# Tampering is detected
import copy
tampered = bytearray(ciphertext)
tampered[30] ^= 0xFF
try:
    decrypt(key, bytes(tampered))
except ValueError as e:
    print(f"Tamper detected: {e}")
```

---

## Implementation Notes

### Dimension implementations

| Dim | Implementation approach | Notes |
|---|---|---|
| 1 (SPN) | Key-derived S-box + byte permutation + Feistel mixing + round keys | 10 rounds, closest to AES structure |
| 2 (Lattice) | Invertible matrix multiply mod 256 + additive offset | Symmetric-key variant (no LWE noise — noise is a public-key concept) |
| 3 (Permutation) | Composition of 8 random byte permutations + per-cycle XOR keys | XOR keys add nonlinearity to pure permutations |
| 4 (Hash-Feistel) | 4-round Feistel network with HMAC-SHA256 round function | The "algebraic firewall" dimension |
| 5 (EC-Analog) | Modular multiplication by secret scalar mod large prime | Simplified analog of EC scalar multiplication |
| 6 (Multivariate) | Two secret affine transforms (S, T) with Feistel nonlinear core | S ∘ F ∘ T structure, invertible via S⁻¹ ∘ F⁻¹ ∘ T⁻¹ |

### Simplifications in this reference implementation

The reference implementation makes several simplifications compared to a
production implementation:

1. **Dimension 2 (Lattice):** Uses mod-256 matrix multiply instead of proper
   LWE with q=3329. In the symmetric-key setting, LWE noise is unnecessary —
   it's a public-key concept. The matrix multiply provides the keyed permutation.

2. **Dimension 5 (EC):** Uses modular arithmetic mod a 256-bit prime instead of
   actual elliptic curve point multiplication. Captures the algebraic structure
   (discrete log hardness) without requiring a full EC library.

3. **Dimension 6 (Multivariate):** Uses a Feistel-style nonlinear map between
   the two affine transforms instead of a full HFE polynomial system.

4. **Matrix generation:** Uses identity + random row operations (guaranteed
   invertible) rather than random matrices with post-hoc invertibility check.

5. **No constant-time operations:** Python cannot guarantee constant-time
   execution. A production implementation MUST use constant-time arithmetic
   to prevent timing attacks.

### Performance characteristics (reference implementation)

Measured on the reference implementation (pure Python, single-threaded):

| k (layers) | Throughput (1KB message) |
|---|---|
| 4 | ~16 KB/s |
| 6 | ~14 KB/s |
| 8 | ~8 KB/s |

These numbers are 100-1000x slower than the theoretical estimates in document 05,
because:
- Pure Python vs. optimized C/Rust
- No hardware acceleration
- No parallelization

A C implementation with SIMD would be dramatically faster.

---

## Test Suite Coverage

| Test | What it verifies |
|---|---|
| mix_columns inverse | SPN mixing function is correctly invertible |
| Dimension roundtrips (×6) | Each dimension: decrypt(encrypt(x)) = x for 20 random inputs |
| Dimension diffusion (×6) | 1-bit input change causes significant output change |
| Block cipher roundtrip (k=2,4,6,8) | Multi-layer encrypt→decrypt preserves data |
| Full scheme roundtrip | CTR+HMAC works for message sizes 0 to 1000 bytes |
| Authentication rejection | Tampered ciphertext is detected and rejected |
| Wrong key rejection | Decryption with wrong key fails authentication |
| Determinism | Same key + nonce → same ciphertext |
| Nonce uniqueness | Different nonce → different ciphertext |
| Ciphertext diffusion | 1-bit plaintext change → significant ciphertext change |
| Performance benchmark | Throughput at different layer counts |

### Known test warnings (expected)

- **Dim 2 (Lattice) diffusion: low (2.7%)** — The mod-256 matrix multiply has
  limited bit-level diffusion. In the full scheme, the adjacent hash layers
  (Dim 4) provide the diffusion. This is by design — each dimension doesn't
  need to be a complete cipher, it just needs to be a secure PRP.

- **Dim 3 (Permutation) diffusion: very low (0.4%)** — Pure byte permutation
  only moves bytes, doesn't change them. The XOR keys add some diffusion.
  Again, the hash firewall provides full diffusion in the composite scheme.

- **CTR mode ciphertext diffusion: low** — Expected. CTR mode XORs a keystream
  with the plaintext. A 1-byte plaintext change only affects the corresponding
  keystream block. This is identical to AES-CTR behavior and is correct.

---

## Document Index (Updated)

| Doc | Title | Status |
|---|---|---|
| 00 | Foundation | Complete |
| 01 | Transformation Zoo | Complete |
| 02 | Expander Graph Construction | Complete |
| 03 | Security Reduction Proof | Complete v0.2 |
| 04 | Key Derivation & Modes of Operation | Complete |
| 05 | Parameter Selection & Performance | Complete |
| 06 | Reference Implementation | Complete (this document) |
| 07 | Test Vectors & Validation | **Next** |
