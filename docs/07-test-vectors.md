# Dimensional Encryption — Test Vectors & Validation

**Project:** SilentBot — Dimensional Encryption  
**Version:** 0.1  
**Date:** 2026-04-13  
**Authors:** Ali Vonk, M  

---

## Purpose

Test vectors are the **compatibility contract** for any cryptographic scheme.
They allow independent implementations (in any language, on any platform) to
verify they produce identical results.

If your implementation doesn't match these vectors, it's wrong. No exceptions.

This is how AES, ChaCha20, and every serious cipher establishes interoperability.

---

## Test Vector File

The complete test vectors are in machine-readable JSON:

**`docs/test-vectors.json`**

Generated and validated by: `src/dimensional_encryption/test_vectors.py`

---

## Vector Categories

### 1. Individual Dimension Vectors (6 vectors)

Each of the 6 dimensions is tested in isolation:
- Fixed key (SHA-256 of "DE-test-vector-key-dimensions")
- Fixed input block (SHA-256 of "DE-test-vector-block-dimensions")
- Expected output for transform and verified inverse roundtrip

These vectors verify that each dimension's transform and inverse are
correctly implemented independent of the rest of the scheme.

### 2. Block Cipher Vectors (4 vectors)

Multi-layer encryption of a single block at k=2, 4, 6, 8:
- Fixed master key and nonce
- Full layer configuration recorded (dimension types + derived keys)
- Verifies key derivation + layer composition together

### 3. Full Scheme Vectors (7 vectors)

Complete DE-CTR-HMAC encrypt/decrypt at various message sizes:
- Empty message (0 bytes)
- Single byte
- Short text (30 bytes)
- Exact block boundary (32 bytes)
- Two full blocks (64 bytes)
- Partial block (50 bytes)
- Multi-block (225 bytes)

Each vector records: header, body, HMAC tag, full ciphertext, and
verified roundtrip decryption.

### 4. Key Derivation Vectors (6 vectors)

Verify that HKDF-based key derivation produces the same layer
configuration (dimension types + layer keys) for given inputs:
- 3 different master keys × 2 layer counts (k=6, k=8)
- Verifies the firewall rule (even positions = hash dimension)
- Verifies each derived layer key exactly

### 5. Authentication Vectors (6 vectors)

Verify tamper detection:
- Valid ciphertext → accepted
- Header tampered (1 bit in magic) → rejected
- Body tampered (byte 30 flipped) → rejected
- HMAC tag tampered (1 bit) → rejected
- Wrong decryption key → rejected
- Truncated ciphertext → rejected

---

## How to Validate

### Using the reference implementation

```bash
cd Encryption/src
python3 -m dimensional_encryption.test_vectors
```

Expected: `ALL VECTORS VALIDATED SUCCESSFULLY`

### Using the JSON file in another language

1. Load `docs/test-vectors.json`
2. For each vector category, implement the corresponding test
3. Compare your outputs byte-for-byte against the expected hex values

Example (pseudocode for dimension vectors):

```
for vector in json["vectors"]["dimensions"]:
    key = hex_decode(vector["key_hex"])
    input = hex_decode(vector["input_hex"])
    expected = hex_decode(vector["output_hex"])

    result = your_dimension_transform(vector["dimension"], key, input)
    assert result == expected, "Dimension {dim} output mismatch"

    roundtrip = your_dimension_inverse(vector["dimension"], key, result)
    assert roundtrip == input, "Dimension {dim} roundtrip failed"
```

---

## Test Vector Summary

| Category | Count | What it verifies |
|---|---|---|
| Dimension transforms | 6 | Each dimension independently correct |
| Block cipher | 4 | Multi-layer composition at k=2,4,6,8 |
| Full scheme | 7 | CTR mode + HMAC at various sizes |
| Key derivation | 6 | HKDF produces correct layer configs |
| Authentication | 6 | Tamper detection works correctly |
| **Total** | **29** | |

All 29 vectors validated against the reference implementation.

---

## Key Inputs (Deterministic Derivation)

All test inputs are derived deterministically from known strings to ensure
reproducibility:

```
Key:   SHA-256("DE-test-vector-key-{label}")
Block: SHA-256("DE-test-vector-block-{label}")
Nonce: SHA-256("DE-test-vector-nonce-{label}")[:16]
```

This means anyone can regenerate the inputs without the JSON file — the file
just provides the expected outputs.

---

## Validation Results (Reference Implementation)

```
Results: 29/29 vectors passed
ALL VECTORS VALIDATED SUCCESSFULLY
```

Run date: 2026-04-13  
Python: 3.9+  
Platform: macOS Darwin 25.4.0 (arm64)

---

## Document Index (Complete)

| Doc | Title | Status |
|---|---|---|
| 00 | Foundation | Complete |
| 01 | Transformation Zoo | Complete |
| 02 | Expander Graph Construction | Complete |
| 03 | Security Reduction Proof | Complete v0.2 |
| 04 | Key Derivation & Modes of Operation | Complete |
| 05 | Parameter Selection & Performance | Complete |
| 06 | Reference Implementation | Complete |
| 07 | Test Vectors & Validation | Complete (this document) |

---

## What's Next (Beyond the Foundation)

The mathematical framework and reference implementation are complete. The
path forward:

### Immediate (Weeks 1-4)
- [x] C reference implementation with BLAKE3 acceleration
- [x] Extended test vectors (edge cases, maximum-length messages)
- [ ] Direct outreach to academic cryptography groups

### Medium-term (Months 1-6)
- [ ] Challenge instances at reduced security levels (invite attack)
- [ ] Rust implementation with constant-time guarantees
- [ ] Independent cryptanalysis by at least one external researcher

### Long-term (Months 6-18)
- [ ] Workshop or informal presentation at a crypto venue
- [ ] Public cryptanalysis invitation
- [ ] If no breaks found: standardization discussion
