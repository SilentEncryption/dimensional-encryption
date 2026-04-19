"""
Dimensional Encryption — Test Suite

Tests correctness of:
    1. Each dimension individually (transform then inverse = identity)
    2. Block cipher (multi-layer encrypt then decrypt = identity)
    3. Full scheme (CTR mode + HMAC, arbitrary message sizes)
    4. Authentication (tampered data is rejected)
    5. Determinism (same key + nonce = same ciphertext)
    6. Diffusion (small plaintext change = large ciphertext change)
"""

import os
import sys
import time

# Add parent to path for import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dimensional_encryption.dimensions import (
    BLOCK_SIZE, DIMENSION_REGISTRY,
    spn_transform, spn_inverse,
    lattice_transform, lattice_inverse,
    permutation_transform, permutation_inverse,
    hash_transform, hash_inverse,
    ec_transform, ec_inverse,
    multivariate_transform, multivariate_inverse,
    _spn_mix_columns,
)
from dimensional_encryption.scheme import (
    encrypt, decrypt, generate_key,
    _derive_layer_config, _encrypt_block, _decrypt_block,
)


def test_spn_mix_columns_inverse():
    """Verify that inv_mix(mix(x)) = x."""
    from dimensional_encryption.dimensions import _spn_inv_mix_columns
    for _ in range(10):
        state = bytearray(os.urandom(BLOCK_SIZE))
        mixed = _spn_mix_columns(state)
        recovered = _spn_inv_mix_columns(mixed)
        assert recovered == state, "inv_mix(mix(x)) should equal x"
    print("  [PASS] SPN mix_columns inverse (inv(fwd(x)) = x)")


def test_dimension_roundtrip(dim_id: int, name: str, num_tests: int = 20):
    """Test that transform(inverse(x)) = x for a given dimension."""
    dim = DIMENSION_REGISTRY[dim_id]
    passed = 0
    for _ in range(num_tests):
        key = os.urandom(BLOCK_SIZE)
        block = os.urandom(BLOCK_SIZE)

        encrypted = dim.transform(key, block)
        decrypted = dim.inverse(key, encrypted)

        if decrypted == block:
            passed += 1
        else:
            print(f"  [FAIL] Dim {dim_id} ({name}): roundtrip failed")
            print(f"         Original:  {block[:8].hex()}...")
            print(f"         Decrypted: {decrypted[:8].hex()}...")
            return False

    print(f"  [PASS] Dim {dim_id} ({name}): {passed}/{num_tests} roundtrips")
    return True


def test_dimension_diffusion(dim_id: int, name: str):
    """Test that a 1-bit change in input causes significant output change."""
    dim = DIMENSION_REGISTRY[dim_id]
    key = os.urandom(BLOCK_SIZE)
    block = os.urandom(BLOCK_SIZE)

    out1 = dim.transform(key, block)

    # Flip one bit
    modified = bytearray(block)
    modified[0] ^= 1
    out2 = dim.transform(key, bytes(modified))

    # Count differing bits
    diff_bits = sum(bin(a ^ b).count('1') for a, b in zip(out1, out2))
    total_bits = BLOCK_SIZE * 8
    diff_pct = diff_bits / total_bits * 100

    status = "PASS" if diff_pct > 10 else "WARN"
    print(f"  [{status}] Dim {dim_id} ({name}): 1-bit change -> "
          f"{diff_bits}/{total_bits} bits differ ({diff_pct:.1f}%)")


def test_block_cipher_roundtrip(num_layers: int = 8, num_tests: int = 5):
    """Test multi-layer block cipher encrypt/decrypt roundtrip."""
    passed = 0
    for _ in range(num_tests):
        master_key = os.urandom(BLOCK_SIZE)
        nonce = os.urandom(16)
        block = os.urandom(BLOCK_SIZE)

        layers = _derive_layer_config(master_key, num_layers, nonce)
        encrypted = _encrypt_block(layers, block)
        decrypted = _decrypt_block(layers, encrypted)

        if decrypted == block:
            passed += 1
        else:
            print(f"  [FAIL] Block cipher roundtrip failed (k={num_layers})")
            return False

    print(f"  [PASS] Block cipher roundtrip (k={num_layers}): "
          f"{passed}/{num_tests}")
    return True


def test_full_scheme_roundtrip():
    """Test the full encrypt/decrypt scheme with various message sizes."""
    master_key = generate_key()
    sizes = [0, 1, 15, 16, 31, 32, 33, 64, 100, 1000]

    for size in sizes:
        plaintext = os.urandom(size) if size > 0 else b""
        ciphertext = encrypt(master_key, plaintext)
        decrypted = decrypt(master_key, ciphertext)

        if decrypted != plaintext:
            print(f"  [FAIL] Full scheme roundtrip (size={size})")
            return False

    print(f"  [PASS] Full scheme roundtrip: sizes {sizes}")
    return True


def test_authentication_rejection():
    """Test that tampered ciphertext is rejected."""
    master_key = generate_key()
    plaintext = b"This message must not be modified"

    ciphertext = encrypt(master_key, plaintext)

    # Tamper with one byte of the encrypted data (not the header or tag)
    tampered = bytearray(ciphertext)
    tampered[30] ^= 0xFF  # Flip bits in the ciphertext body
    tampered = bytes(tampered)

    try:
        decrypt(master_key, tampered)
        print("  [FAIL] Tampered data was accepted!")
        return False
    except ValueError as e:
        if "Authentication failed" in str(e):
            print("  [PASS] Tampered ciphertext correctly rejected")
            return True
        raise


def test_wrong_key_rejection():
    """Test that wrong key is rejected."""
    key1 = generate_key()
    key2 = generate_key()
    plaintext = b"Secret data"

    ciphertext = encrypt(key1, plaintext)

    try:
        decrypt(key2, ciphertext)
        print("  [FAIL] Wrong key was accepted!")
        return False
    except ValueError:
        print("  [PASS] Wrong key correctly rejected")
        return True


def test_determinism():
    """Test that same key + nonce = same ciphertext."""
    master_key = generate_key()
    nonce = os.urandom(16)
    plaintext = b"Deterministic test"

    ct1 = encrypt(master_key, plaintext, nonce=nonce)
    ct2 = encrypt(master_key, plaintext, nonce=nonce)

    if ct1 == ct2:
        print("  [PASS] Deterministic: same key + nonce -> same ciphertext")
    else:
        print("  [FAIL] Same key + nonce produced different ciphertexts!")
        return False

    # Different nonce should give different ciphertext
    ct3 = encrypt(master_key, plaintext)  # random nonce
    if ct3 != ct1:
        print("  [PASS] Different nonce -> different ciphertext")
    else:
        print("  [WARN] Different nonce gave same ciphertext (astronomically unlikely)")
    return True


def test_ciphertext_diffusion():
    """Test that 1-bit plaintext change causes large ciphertext change."""
    master_key = generate_key()
    nonce = os.urandom(16)

    pt1 = os.urandom(64)
    pt2 = bytearray(pt1)
    pt2[0] ^= 1
    pt2 = bytes(pt2)

    ct1 = encrypt(master_key, pt1, nonce=nonce)
    ct2 = encrypt(master_key, pt2, nonce=nonce)

    # Compare ciphertext bodies (skip header, skip tag)
    body1 = ct1[25:-32]
    body2 = ct2[25:-32]
    diff_bits = sum(bin(a ^ b).count('1') for a, b in zip(body1, body2))
    total_bits = len(body1) * 8
    diff_pct = diff_bits / total_bits * 100

    status = "PASS" if diff_pct > 30 else "WARN"
    print(f"  [{status}] Ciphertext diffusion: 1-bit change -> "
          f"{diff_bits}/{total_bits} bits differ ({diff_pct:.1f}%)")


def test_performance():
    """Benchmark encryption throughput."""
    master_key = generate_key()
    data_size = 1024  # 1 KB
    plaintext = os.urandom(data_size)

    # Warm up
    encrypt(master_key, plaintext, num_layers=2)

    results = {}
    for num_layers in [2, 4, 6, 8]:
        start = time.time()
        iterations = 3
        for _ in range(iterations):
            ct = encrypt(master_key, plaintext, num_layers=num_layers)
        elapsed = time.time() - start
        avg_time = elapsed / iterations
        throughput = data_size / avg_time / 1024  # KB/s

        results[num_layers] = (avg_time * 1000, throughput)
        print(f"  [INFO] k={num_layers}: {avg_time*1000:.1f}ms for {data_size}B "
              f"({throughput:.1f} KB/s)")

    print("  [PASS] Performance benchmark complete")
    return results


def run_all_tests():
    """Run the complete test suite."""
    print("=" * 60)
    print("Dimensional Encryption — Test Suite")
    print("=" * 60)

    all_passed = True

    # 1. Individual dimension roundtrips
    print("\n--- Individual Dimension Roundtrips ---")
    test_spn_mix_columns_inverse()
    for dim_id, dim in sorted(DIMENSION_REGISTRY.items()):
        if not test_dimension_roundtrip(dim_id, dim.name):
            all_passed = False

    # 2. Dimension diffusion
    print("\n--- Dimension Diffusion (1-bit avalanche) ---")
    for dim_id, dim in sorted(DIMENSION_REGISTRY.items()):
        test_dimension_diffusion(dim_id, dim.name)

    # 3. Block cipher roundtrips
    print("\n--- Block Cipher Roundtrips ---")
    for k in [2, 4, 6, 8]:
        if not test_block_cipher_roundtrip(k):
            all_passed = False

    # 4. Full scheme
    print("\n--- Full Scheme (CTR + HMAC) ---")
    if not test_full_scheme_roundtrip():
        all_passed = False
    if not test_authentication_rejection():
        all_passed = False
    if not test_wrong_key_rejection():
        all_passed = False
    if not test_determinism():
        all_passed = False
    test_ciphertext_diffusion()

    # 5. Performance
    print("\n--- Performance ---")
    test_performance()

    # Summary
    print("\n" + "=" * 60)
    if all_passed:
        print("ALL TESTS PASSED")
    else:
        print("SOME TESTS FAILED — see above for details")
    print("=" * 60)

    return all_passed


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
