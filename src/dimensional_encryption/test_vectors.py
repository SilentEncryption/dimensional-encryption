#!/usr/bin/env python3
"""
Dimensional Encryption — Test Vector Generator & Validator

Generates deterministic test vectors using fixed keys and inputs.
Any correct implementation of Dimensional Encryption MUST produce
identical outputs for these inputs.

These vectors serve as the compatibility standard. If your implementation
doesn't match, it's wrong.
"""

import json
import os
import sys
import hashlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dimensional_encryption.dimensions import (
    BLOCK_SIZE, DIMENSION_REGISTRY,
)
from dimensional_encryption.scheme import (
    encrypt, decrypt, generate_key,
    _derive_layer_config, _encrypt_block, _decrypt_block,
    HEADER_SIZE, TAG_SIZE,
)


# ---------------------------------------------------------------------------
# Fixed test inputs (deterministic — derived from known seeds)
# ---------------------------------------------------------------------------

def _fixed_key(label: str) -> bytes:
    """Derive a deterministic 32-byte key from a label."""
    return hashlib.sha256(f"DE-test-vector-key-{label}".encode()).digest()


def _fixed_block(label: str) -> bytes:
    """Derive a deterministic 32-byte block from a label."""
    return hashlib.sha256(f"DE-test-vector-block-{label}".encode()).digest()


def _fixed_nonce(label: str) -> bytes:
    """Derive a deterministic 16-byte nonce from a label."""
    return hashlib.sha256(f"DE-test-vector-nonce-{label}".encode()).digest()[:16]


# ---------------------------------------------------------------------------
# Vector 1: Individual dimension transforms
# ---------------------------------------------------------------------------

def generate_dimension_vectors() -> list[dict]:
    """One test vector per dimension: fixed key + fixed block → expected output."""
    vectors = []
    key = _fixed_key("dimensions")
    block = _fixed_block("dimensions")

    for dim_id in sorted(DIMENSION_REGISTRY.keys()):
        dim = DIMENSION_REGISTRY[dim_id]
        encrypted = dim.transform(key, block)
        decrypted = dim.inverse(key, encrypted)

        vectors.append({
            "id": f"dim-{dim_id}",
            "description": f"Dimension {dim_id} ({dim.name}) single transform",
            "dimension": dim_id,
            "dimension_name": dim.name,
            "key_hex": key.hex(),
            "input_hex": block.hex(),
            "output_hex": encrypted.hex(),
            "roundtrip_match": decrypted == block,
        })

    return vectors


# ---------------------------------------------------------------------------
# Vector 2: Block cipher (multi-layer, fixed layer config)
# ---------------------------------------------------------------------------

def generate_block_cipher_vectors() -> list[dict]:
    """Multi-layer block cipher vectors at k=2, 4, 6, 8."""
    vectors = []
    master_key = _fixed_key("block-cipher")
    block = _fixed_block("block-cipher")
    nonce = _fixed_nonce("block-cipher")

    for k in [2, 4, 6, 8]:
        layers = _derive_layer_config(master_key, k, nonce)

        # Record the layer structure
        layer_info = []
        for dim_id, layer_key in layers:
            dim = DIMENSION_REGISTRY[dim_id]
            layer_info.append({
                "dimension": dim_id,
                "name": dim.name,
                "key_hex": layer_key.hex(),
            })

        encrypted = _encrypt_block(layers, block)
        decrypted = _decrypt_block(layers, encrypted)

        vectors.append({
            "id": f"block-k{k}",
            "description": f"Block cipher with k={k} layers",
            "master_key_hex": master_key.hex(),
            "nonce_hex": nonce.hex(),
            "num_layers": k,
            "layers": layer_info,
            "input_hex": block.hex(),
            "output_hex": encrypted.hex(),
            "roundtrip_match": decrypted == block,
        })

    return vectors


# ---------------------------------------------------------------------------
# Vector 3: Full scheme (CTR + HMAC) with various message sizes
# ---------------------------------------------------------------------------

def generate_scheme_vectors() -> list[dict]:
    """Full encrypt/decrypt vectors at various message sizes."""
    vectors = []
    master_key = _fixed_key("scheme")
    nonce = _fixed_nonce("scheme")

    test_messages = [
        ("empty", b""),
        ("one-byte", b"\x42"),
        ("short", b"Hello, Dimensional Encryption!"),
        ("exact-block", b"A" * 32),
        ("two-blocks", b"B" * 64),
        ("partial", b"C" * 50),
        ("longer", b"The quick brown fox jumps over the lazy dog. " * 5),
    ]

    for label, plaintext in test_messages:
        ciphertext = encrypt(master_key, plaintext, num_layers=8, nonce=nonce)
        decrypted = decrypt(master_key, ciphertext)

        vectors.append({
            "id": f"scheme-{label}",
            "description": f"Full scheme, message: {label} ({len(plaintext)} bytes)",
            "master_key_hex": master_key.hex(),
            "nonce_hex": nonce.hex(),
            "num_layers": 8,
            "plaintext_hex": plaintext.hex(),
            "plaintext_utf8": plaintext.decode("utf-8", errors="replace"),
            "ciphertext_hex": ciphertext.hex(),
            "ciphertext_length": len(ciphertext),
            "header_hex": ciphertext[:HEADER_SIZE].hex(),
            "body_hex": ciphertext[HEADER_SIZE:-TAG_SIZE].hex(),
            "tag_hex": ciphertext[-TAG_SIZE:].hex(),
            "roundtrip_match": decrypted == plaintext,
        })

    return vectors


# ---------------------------------------------------------------------------
# Vector 4: Key derivation (verify layer configs match)
# ---------------------------------------------------------------------------

def generate_key_derivation_vectors() -> list[dict]:
    """Verify that key derivation produces the same layer config."""
    vectors = []

    for i in range(3):
        master_key = _fixed_key(f"kdf-{i}")
        nonce = _fixed_nonce(f"kdf-{i}")

        for k in [6, 8]:
            layers = _derive_layer_config(master_key, k, nonce)
            layer_info = []
            for dim_id, layer_key in layers:
                layer_info.append({
                    "dimension": dim_id,
                    "key_hex": layer_key.hex(),
                })

            vectors.append({
                "id": f"kdf-{i}-k{k}",
                "description": f"Key derivation #{i}, k={k}",
                "master_key_hex": master_key.hex(),
                "nonce_hex": nonce.hex(),
                "num_layers": k,
                "derived_layers": layer_info,
            })

    return vectors


# ---------------------------------------------------------------------------
# Vector 5: Authentication (verify tamper detection)
# ---------------------------------------------------------------------------

def generate_auth_vectors() -> list[dict]:
    """Vectors for tamper detection: valid ciphertext + various corruptions."""
    vectors = []
    master_key = _fixed_key("auth")
    nonce = _fixed_nonce("auth")
    plaintext = b"Authentication test message - do not modify"

    ciphertext = encrypt(master_key, plaintext, num_layers=8, nonce=nonce)

    # Valid decryption
    vectors.append({
        "id": "auth-valid",
        "description": "Valid ciphertext, should decrypt successfully",
        "master_key_hex": master_key.hex(),
        "ciphertext_hex": ciphertext.hex(),
        "should_succeed": True,
        "expected_plaintext_hex": plaintext.hex(),
    })

    # Tamper with header (byte 3 — inside magic)
    tampered_header = bytearray(ciphertext)
    tampered_header[3] ^= 0x01
    vectors.append({
        "id": "auth-tampered-header",
        "description": "Header tampered (1 bit flipped in magic bytes)",
        "master_key_hex": master_key.hex(),
        "ciphertext_hex": bytes(tampered_header).hex(),
        "should_succeed": False,
        "tamper_position": 3,
        "tamper_description": "Flipped 1 bit in DENC magic",
    })

    # Tamper with body (byte 30)
    tampered_body = bytearray(ciphertext)
    tampered_body[30] ^= 0xFF
    vectors.append({
        "id": "auth-tampered-body",
        "description": "Ciphertext body tampered (byte 30 flipped)",
        "master_key_hex": master_key.hex(),
        "ciphertext_hex": bytes(tampered_body).hex(),
        "should_succeed": False,
        "tamper_position": 30,
        "tamper_description": "All bits flipped at position 30",
    })

    # Tamper with tag (last byte)
    tampered_tag = bytearray(ciphertext)
    tampered_tag[-1] ^= 0x01
    vectors.append({
        "id": "auth-tampered-tag",
        "description": "HMAC tag tampered (last bit flipped)",
        "master_key_hex": master_key.hex(),
        "ciphertext_hex": bytes(tampered_tag).hex(),
        "should_succeed": False,
        "tamper_position": len(ciphertext) - 1,
        "tamper_description": "1 bit flipped in HMAC tag",
    })

    # Wrong key
    wrong_key = _fixed_key("auth-wrong")
    vectors.append({
        "id": "auth-wrong-key",
        "description": "Valid ciphertext, wrong decryption key",
        "master_key_hex": wrong_key.hex(),
        "ciphertext_hex": ciphertext.hex(),
        "should_succeed": False,
        "tamper_description": "Correct ciphertext but wrong master key",
    })

    # Truncated (missing last byte)
    vectors.append({
        "id": "auth-truncated",
        "description": "Ciphertext truncated (last byte removed)",
        "master_key_hex": master_key.hex(),
        "ciphertext_hex": ciphertext[:-1].hex(),
        "should_succeed": False,
        "tamper_description": "Last byte of tag removed",
    })

    return vectors


# ---------------------------------------------------------------------------
# Generate all vectors
# ---------------------------------------------------------------------------

def generate_all_vectors() -> dict:
    """Generate the complete test vector set."""
    return {
        "schema_version": "1.0",
        "scheme": "Dimensional Encryption",
        "scheme_version": "0.1",
        "block_size_bits": BLOCK_SIZE * 8,
        "block_size_bytes": BLOCK_SIZE,
        "header_size": HEADER_SIZE,
        "tag_size": TAG_SIZE,
        "hash_function": "SHA-256 (via HMAC and HKDF)",
        "vectors": {
            "dimensions": generate_dimension_vectors(),
            "block_cipher": generate_block_cipher_vectors(),
            "full_scheme": generate_scheme_vectors(),
            "key_derivation": generate_key_derivation_vectors(),
            "authentication": generate_auth_vectors(),
        },
    }


# ---------------------------------------------------------------------------
# Validator: check vectors against current implementation
# ---------------------------------------------------------------------------

def validate_vectors(vectors: dict) -> bool:
    """Validate all test vectors against the current implementation."""
    all_passed = True
    total = 0
    passed = 0

    print("=" * 60)
    print("Dimensional Encryption — Test Vector Validation")
    print("=" * 60)

    # 1. Dimension vectors
    print("\n--- Dimension Vectors ---")
    for v in vectors["vectors"]["dimensions"]:
        total += 1
        key = bytes.fromhex(v["key_hex"])
        block = bytes.fromhex(v["input_hex"])
        expected = bytes.fromhex(v["output_hex"])
        dim = DIMENSION_REGISTRY[v["dimension"]]

        result = dim.transform(key, block)
        if result == expected:
            print(f"  [PASS] {v['id']}: output matches")
            passed += 1
        else:
            print(f"  [FAIL] {v['id']}: output mismatch")
            print(f"         Expected: {expected[:16].hex()}...")
            print(f"         Got:      {result[:16].hex()}...")
            all_passed = False

        # Also verify roundtrip
        roundtrip = dim.inverse(key, result)
        if roundtrip != block:
            print(f"  [FAIL] {v['id']}: roundtrip mismatch")
            all_passed = False

    # 2. Block cipher vectors
    print("\n--- Block Cipher Vectors ---")
    for v in vectors["vectors"]["block_cipher"]:
        total += 1
        master_key = bytes.fromhex(v["master_key_hex"])
        nonce = bytes.fromhex(v["nonce_hex"])
        block = bytes.fromhex(v["input_hex"])
        expected = bytes.fromhex(v["output_hex"])

        layers = _derive_layer_config(master_key, v["num_layers"], nonce)
        result = _encrypt_block(layers, block)

        if result == expected:
            print(f"  [PASS] {v['id']}: output matches")
            passed += 1
        else:
            print(f"  [FAIL] {v['id']}: output mismatch")
            all_passed = False

    # 3. Full scheme vectors
    print("\n--- Full Scheme Vectors ---")
    for v in vectors["vectors"]["full_scheme"]:
        total += 1
        master_key = bytes.fromhex(v["master_key_hex"])
        plaintext = bytes.fromhex(v["plaintext_hex"])
        expected_ct = bytes.fromhex(v["ciphertext_hex"])
        nonce = bytes.fromhex(v["nonce_hex"])

        result_ct = encrypt(master_key, plaintext, num_layers=v["num_layers"],
                           nonce=nonce)
        if result_ct == expected_ct:
            print(f"  [PASS] {v['id']}: ciphertext matches")
            passed += 1
        else:
            print(f"  [FAIL] {v['id']}: ciphertext mismatch")
            print(f"         Expected len: {len(expected_ct)}")
            print(f"         Got len:      {len(result_ct)}")
            all_passed = False

        # Verify decryption
        decrypted = decrypt(master_key, result_ct)
        if decrypted != plaintext:
            print(f"  [FAIL] {v['id']}: decryption mismatch")
            all_passed = False

    # 4. Key derivation vectors
    print("\n--- Key Derivation Vectors ---")
    for v in vectors["vectors"]["key_derivation"]:
        total += 1
        master_key = bytes.fromhex(v["master_key_hex"])
        nonce = bytes.fromhex(v["nonce_hex"])

        layers = _derive_layer_config(master_key, v["num_layers"], nonce)

        match = True
        for i, (dim_id, layer_key) in enumerate(layers):
            expected = v["derived_layers"][i]
            if dim_id != expected["dimension"] or layer_key.hex() != expected["key_hex"]:
                match = False
                break

        if match:
            print(f"  [PASS] {v['id']}: layer config matches")
            passed += 1
        else:
            print(f"  [FAIL] {v['id']}: layer config mismatch at layer {i}")
            all_passed = False

    # 5. Authentication vectors
    print("\n--- Authentication Vectors ---")
    for v in vectors["vectors"]["authentication"]:
        total += 1
        master_key = bytes.fromhex(v["master_key_hex"])
        ciphertext = bytes.fromhex(v["ciphertext_hex"])

        try:
            result = decrypt(master_key, ciphertext)
            succeeded = True
        except (ValueError, Exception):
            succeeded = False

        if succeeded == v["should_succeed"]:
            status = "accepted" if succeeded else "rejected"
            print(f"  [PASS] {v['id']}: correctly {status}")
            passed += 1
        else:
            expected = "succeed" if v["should_succeed"] else "fail"
            actual = "succeeded" if succeeded else "failed"
            print(f"  [FAIL] {v['id']}: expected to {expected}, but {actual}")
            all_passed = False

    # Summary
    print(f"\n{'=' * 60}")
    print(f"Results: {passed}/{total} vectors passed")
    if all_passed:
        print("ALL VECTORS VALIDATED SUCCESSFULLY")
    else:
        print("SOME VECTORS FAILED — implementation may be incorrect")
    print("=" * 60)

    return all_passed


# ---------------------------------------------------------------------------
# Main: generate, save, and validate
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Generate vectors
    print("Generating test vectors...")
    vectors = generate_all_vectors()

    # Count vectors
    total = sum(len(v) for v in vectors["vectors"].values())
    print(f"Generated {total} test vectors across {len(vectors['vectors'])} categories")

    # Save to JSON
    output_dir = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    output_path = os.path.join(output_dir, "docs", "test-vectors.json")

    with open(output_path, "w") as f:
        json.dump(vectors, f, indent=2)
    print(f"Saved to: {output_path}")

    # Validate
    print()
    success = validate_vectors(vectors)
    sys.exit(0 if success else 1)
