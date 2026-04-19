#!/usr/bin/env python3
"""
Dimensional Encryption — Cryptanalysis & Statistical Testing

Three categories of tests:
1. Statistical randomness tests on ciphertext (does it look random?)
2. Known-plaintext analysis (does structure leak?)
3. Reduced-parameter challenge instances (can weak versions be broken?)

These tests are what a real cryptanalyst would run first.
"""

import os
import sys
import math
import time
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dimensional_encryption.scheme import (
    encrypt, decrypt, generate_key,
    _derive_layer_config, _encrypt_block,
    BLOCK_SIZE, HEADER_SIZE, TAG_SIZE,
)
from dimensional_encryption.dimensions import DIMENSION_REGISTRY


# =========================================================================
# PART 1: Statistical Randomness Tests
# =========================================================================
# A good cipher's output should be indistinguishable from random bytes.
# If ANY of these tests detect a pattern, the scheme has a problem.

def frequency_test(data: bytes) -> dict:
    """Monobit frequency test: are 0s and 1s roughly equal?
    NIST SP 800-22 Test 1."""
    bits = ''.join(format(b, '08b') for b in data)
    n = len(bits)
    ones = bits.count('1')
    zeros = n - ones
    # Under randomness, |ones - zeros| / sqrt(n) should be < 2 (95% confidence)
    stat = abs(ones - zeros) / math.sqrt(n)
    passed = stat < 2.0
    return {
        "test": "Frequency (Monobit)",
        "total_bits": n,
        "ones": ones,
        "zeros": zeros,
        "ratio": ones / n,
        "statistic": round(stat, 4),
        "threshold": 2.0,
        "passed": passed,
        "meaning": "Are 0s and 1s balanced? (expect ratio ~0.50)"
    }


def runs_test(data: bytes) -> dict:
    """Runs test: do bits alternate enough? Not too many long streaks.
    NIST SP 800-22 Test 2."""
    bits = ''.join(format(b, '08b') for b in data)
    n = len(bits)
    ones = bits.count('1')
    pi = ones / n

    # Pre-test: if frequency is too skewed, runs test is invalid
    if abs(pi - 0.5) >= 2 / math.sqrt(n):
        return {
            "test": "Runs",
            "passed": False,
            "meaning": "Frequency too skewed for runs test"
        }

    # Count runs (sequences of consecutive identical bits)
    runs = 1
    for i in range(1, n):
        if bits[i] != bits[i-1]:
            runs += 1

    # Expected runs under randomness
    expected = 1 + 2 * ones * (n - ones) / n
    variance = (expected - 1) * (expected - 2) / (n - 1) if n > 1 else 1
    stat = abs(runs - expected) / math.sqrt(variance) if variance > 0 else 0
    passed = stat < 2.0

    return {
        "test": "Runs",
        "total_runs": runs,
        "expected_runs": round(expected, 1),
        "statistic": round(stat, 4),
        "threshold": 2.0,
        "passed": passed,
        "meaning": "Do bits alternate naturally? (no long streaks)"
    }


def byte_frequency_test(data: bytes) -> dict:
    """Chi-squared test on byte values. All 256 byte values should appear
    roughly equally often."""
    n = len(data)
    counts = Counter(data)
    expected = n / 256

    chi_sq = sum((counts.get(i, 0) - expected) ** 2 / expected for i in range(256))

    # Chi-squared with 255 degrees of freedom
    # 95% threshold is approximately 293.25
    threshold = 293.25
    passed = chi_sq < threshold

    # Find most and least common bytes
    most_common = counts.most_common(3)
    least_common = counts.most_common()[-3:] if len(counts) >= 3 else counts.most_common()

    return {
        "test": "Byte Frequency (Chi-squared)",
        "unique_bytes": len(counts),
        "chi_squared": round(chi_sq, 2),
        "threshold": threshold,
        "expected_per_byte": round(expected, 2),
        "most_common": [(hex(b), c) for b, c in most_common],
        "least_common": [(hex(b), c) for b, c in least_common],
        "passed": passed,
        "meaning": "Are all byte values equally likely? (expect ~uniform)"
    }


def serial_correlation_test(data: bytes) -> dict:
    """Test for correlation between consecutive bytes.
    Random data should have near-zero correlation."""
    n = len(data)
    if n < 10:
        return {"test": "Serial Correlation", "passed": True, "meaning": "Too short"}

    mean = sum(data) / n
    var = sum((b - mean) ** 2 for b in data) / n

    if var == 0:
        return {"test": "Serial Correlation", "passed": False,
                "meaning": "Zero variance — all bytes identical!"}

    covar = sum((data[i] - mean) * (data[i+1] - mean) for i in range(n-1)) / (n-1)
    correlation = covar / var

    # For random data, correlation should be near 0
    # Threshold: |r| < 2/sqrt(n)
    threshold = 2 / math.sqrt(n)
    passed = abs(correlation) < threshold

    return {
        "test": "Serial Correlation",
        "correlation": round(correlation, 6),
        "threshold": round(threshold, 6),
        "passed": passed,
        "meaning": "Are consecutive bytes independent? (expect correlation ~0)"
    }


def avalanche_test(key: bytes, num_trials: int = 100) -> dict:
    """Strict Avalanche Criterion: flipping 1 input bit should flip ~50%
    of output bits."""
    from dimensional_encryption.scheme import _derive_layer_config, _encrypt_block
    nonce = os.urandom(16)
    layers = _derive_layer_config(key, 8, nonce)

    total_flipped = 0
    total_bits = 0

    for _ in range(num_trials):
        block = os.urandom(BLOCK_SIZE)
        ct1 = _encrypt_block(layers, block)

        # Flip one random bit
        modified = bytearray(block)
        byte_idx = os.urandom(1)[0] % BLOCK_SIZE
        bit_idx = os.urandom(1)[0] % 8
        modified[byte_idx] ^= (1 << bit_idx)
        ct2 = _encrypt_block(layers, bytes(modified))

        flipped = sum(bin(a ^ b).count('1') for a, b in zip(ct1, ct2))
        total_flipped += flipped
        total_bits += BLOCK_SIZE * 8

    avg_pct = total_flipped / total_bits * 100
    # Ideal is 50%. Acceptable range: 45-55%
    passed = 45.0 <= avg_pct <= 55.0

    return {
        "test": "Avalanche (Strict Avalanche Criterion)",
        "trials": num_trials,
        "avg_bits_flipped_pct": round(avg_pct, 2),
        "ideal": 50.0,
        "acceptable_range": "45-55%",
        "passed": passed,
        "meaning": "Does 1 input bit flip ~50% of output bits?"
    }


# =========================================================================
# PART 2: Known-Plaintext Analysis
# =========================================================================
# The attacker knows both plaintext and ciphertext. Can they learn the key?

def known_plaintext_pattern_test(key: bytes) -> dict:
    """Encrypt structured/patterned plaintexts and check if patterns survive."""
    nonce = os.urandom(16)
    results = []

    patterns = [
        ("all-zeros", b'\x00' * 64),
        ("all-ones", b'\xff' * 64),
        ("repeating-byte", b'\xAB' * 64),
        ("sequential", bytes(range(64))),
        ("two-blocks-identical", b'\x42' * 32 + b'\x42' * 32),
    ]

    for name, plaintext in patterns:
        ct = encrypt(key, plaintext, nonce=nonce)
        body = ct[HEADER_SIZE:-TAG_SIZE]

        # Check if ciphertext has the same pattern
        byte_counts = Counter(body)
        unique_ratio = len(byte_counts) / len(body)

        # For random output, unique_ratio should be high
        # For pattern leakage, it would be suspiciously low
        pattern_leaks = unique_ratio < 0.3  # Less than 30% unique bytes = suspicious

        results.append({
            "pattern": name,
            "plaintext_unique_bytes": len(set(plaintext)),
            "ciphertext_unique_bytes": len(byte_counts),
            "ciphertext_unique_ratio": round(unique_ratio, 3),
            "pattern_leaks": pattern_leaks,
        })

    all_passed = not any(r["pattern_leaks"] for r in results)
    return {
        "test": "Known-Plaintext Pattern Analysis",
        "results": results,
        "passed": all_passed,
        "meaning": "Do plaintext patterns survive encryption? (they shouldn't)"
    }


def ecb_penguin_test(key: bytes) -> dict:
    """The 'ECB penguin' test: encrypt identical blocks and check if they
    produce identical ciphertext blocks. In CTR mode they should NOT
    (because the counter makes each block input unique)."""
    nonce = os.urandom(16)
    plaintext = b'\x00' * 320  # 10 identical 32-byte blocks

    ct = encrypt(key, plaintext, nonce=nonce)
    body = ct[HEADER_SIZE:-TAG_SIZE]

    # Split ciphertext into 32-byte blocks
    blocks = [body[i:i+32] for i in range(0, len(body), 32)]
    unique_blocks = len(set(blocks))

    passed = unique_blocks == len(blocks)  # All blocks should be different

    return {
        "test": "ECB Penguin (identical block detection)",
        "total_blocks": len(blocks),
        "unique_blocks": unique_blocks,
        "passed": passed,
        "meaning": "Do identical plaintext blocks produce different ciphertext? (they should in CTR)"
    }


# =========================================================================
# PART 3: Reduced-Parameter Brute Force
# =========================================================================
# Can we break a deliberately weakened version?

def reduced_parameter_challenge():
    """Create tiny instances with reduced key bits and try to brute-force.
    This validates that security scales with key size as expected."""
    print("\n  Creating reduced-parameter challenge instances...")
    print("  (These use truncated keys to make brute force possible)\n")

    results = []

    for key_bits in [8, 12, 16, 20]:
        # Create a key where only `key_bits` bits matter
        full_key = os.urandom(BLOCK_SIZE)
        mask_bytes = key_bits // 8
        mask_remainder = key_bits % 8

        # Zero out everything after key_bits
        masked_key = bytearray(full_key)
        for i in range(BLOCK_SIZE):
            if i > mask_bytes:
                masked_key[i] = 0
            elif i == mask_bytes and mask_remainder > 0:
                masked_key[i] &= (0xFF << (8 - mask_remainder))
            elif i == mask_bytes and mask_remainder == 0:
                masked_key[i] = 0
        masked_key = bytes(masked_key)

        # Encrypt a known plaintext with k=2 (minimal layers for speed)
        nonce = os.urandom(16)
        plaintext = b"Challenge plaintext for brute force test!!"[:32]
        ct = encrypt(masked_key, plaintext, num_layers=2, nonce=nonce)

        # Try to brute-force: enumerate all possible keys with `key_bits` bits
        search_space = 2 ** key_bits
        start = time.time()
        found = False
        attempts = 0

        for candidate in range(min(search_space, 100000)):  # Cap at 100K attempts
            # Reconstruct candidate key
            candidate_key = bytearray(BLOCK_SIZE)
            for i in range(mask_bytes + 1):
                if i < mask_bytes:
                    candidate_key[i] = (candidate >> (8 * (mask_bytes - 1 - i))) & 0xFF
                elif mask_remainder > 0:
                    candidate_key[i] = ((candidate & ((1 << mask_remainder) - 1))
                                        << (8 - mask_remainder))
            candidate_key = bytes(candidate_key)
            attempts += 1

            try:
                result = decrypt(candidate_key, ct)
                if result == plaintext:
                    found = True
                    break
            except ValueError:
                continue  # Wrong key — authentication failed (expected)

        elapsed = time.time() - start

        results.append({
            "key_bits": key_bits,
            "search_space": search_space,
            "attempts": attempts,
            "found": found,
            "time_seconds": round(elapsed, 3),
            "attempts_per_second": round(attempts / elapsed, 0) if elapsed > 0 else 0,
        })

        status = "FOUND" if found else f"NOT FOUND (tried {attempts}/{search_space})"
        print(f"  {key_bits}-bit key: {status} in {elapsed:.3f}s "
              f"({attempts} attempts, {attempts/elapsed:.0f}/s)")

    return results


# =========================================================================
# PART 4: Real Document Encryption Test
# =========================================================================

def encrypt_real_document():
    """Encrypt an actual document and analyze the ciphertext."""
    print("\n  Encrypting a real document...")

    # Create a realistic document
    document = (
        b"CONFIDENTIAL REPORT - SilentBot Research Division\n"
        b"Date: 2026-04-13\n"
        b"Subject: Dimensional Encryption Field Test\n\n"
        b"This document contains sensitive information about the new encryption\n"
        b"scheme developed by SilentBot. The scheme uses heterogeneous algebraic\n"
        b"transformations composed in layers, with hash firewalls between each\n"
        b"algebraic layer.\n\n"
        b"Key findings:\n"
        b"1. The hybrid argument provides IND-CPA security\n"
        b"2. Fault tolerance survives partial primitive collapse\n"
        b"3. Performance is competitive with post-quantum alternatives\n\n"
        b"Financial projections: EUR 2,500,000 in Year 1\n"
        b"Account number: NL91 ABNA 0417 1643 00\n"
        b"API Key: sk-proj-abc123def456ghi789\n\n"
        b"This information must not be disclosed.\n"
        b"END OF REPORT\n"
    )

    key = generate_key()
    print(f"  Document size: {len(document)} bytes")
    print(f"  Key: {key[:8].hex()}...")

    ct = encrypt(key, document, num_layers=8)
    body = ct[HEADER_SIZE:-TAG_SIZE]

    print(f"  Ciphertext size: {len(ct)} bytes (overhead: {len(ct) - len(document)} bytes)")

    # Check: can we find any of the original strings in the ciphertext?
    sensitive_strings = [
        b"CONFIDENTIAL", b"SilentBot", b"EUR 2,500,000",
        b"NL91 ABNA", b"sk-proj-abc123", b"encryption",
        b"2026", b"report"
    ]

    print(f"\n  Searching for plaintext fragments in ciphertext:")
    any_found = False
    for s in sensitive_strings:
        found = s in body or s.lower() in body
        status = "FOUND (CRITICAL FAILURE!)" if found else "not found (good)"
        print(f"    '{s.decode()}': {status}")
        if found:
            any_found = True

    # Verify decryption still works
    decrypted = decrypt(key, ct)
    match = decrypted == document
    print(f"\n  Decryption verification: {'PASS' if match else 'FAIL'}")

    return {
        "document_size": len(document),
        "ciphertext_size": len(ct),
        "plaintext_fragments_found": any_found,
        "decryption_correct": match,
    }


# =========================================================================
# Run everything
# =========================================================================

def run_all_analysis():
    print("=" * 64)
    print("DIMENSIONAL ENCRYPTION — CRYPTANALYSIS SUITE")
    print("=" * 64)

    key = generate_key()

    # Generate a large ciphertext sample for statistical tests
    print("\n--- Generating ciphertext sample (10 KB) ---")
    plaintext = os.urandom(10240)
    ct = encrypt(key, plaintext, num_layers=8)
    body = ct[HEADER_SIZE:-TAG_SIZE]
    print(f"  Plaintext: {len(plaintext)} bytes (random)")
    print(f"  Ciphertext body: {len(body)} bytes")

    # Part 1: Statistical tests
    print("\n--- PART 1: Statistical Randomness Tests ---")
    stat_tests = [
        frequency_test(body),
        runs_test(body),
        byte_frequency_test(body),
        serial_correlation_test(body),
        avalanche_test(key),
    ]

    for result in stat_tests:
        status = "PASS" if result["passed"] else "FAIL"
        print(f"\n  [{status}] {result['test']}")
        print(f"        {result['meaning']}")
        for k, v in result.items():
            if k not in ("test", "passed", "meaning", "most_common",
                        "least_common", "results"):
                print(f"        {k}: {v}")

    # Part 2: Known-plaintext analysis
    print("\n--- PART 2: Known-Plaintext Analysis ---")
    kp_result = known_plaintext_pattern_test(key)
    status = "PASS" if kp_result["passed"] else "FAIL"
    print(f"\n  [{status}] {kp_result['test']}")
    for r in kp_result["results"]:
        leak = "LEAKS!" if r["pattern_leaks"] else "clean"
        print(f"    {r['pattern']:25s} → {r['ciphertext_unique_bytes']:3d} unique bytes "
              f"(ratio {r['ciphertext_unique_ratio']:.3f}) [{leak}]")

    penguin = ecb_penguin_test(key)
    status = "PASS" if penguin["passed"] else "FAIL"
    print(f"\n  [{status}] {penguin['test']}")
    print(f"        {penguin['total_blocks']} blocks → "
          f"{penguin['unique_blocks']} unique ({penguin['meaning']})")

    # Part 3: Reduced-parameter brute force
    print("\n--- PART 3: Reduced-Parameter Brute Force ---")
    reduced_parameter_challenge()

    # Part 4: Real document
    print("\n--- PART 4: Real Document Encryption ---")
    encrypt_real_document()

    # Summary
    print("\n" + "=" * 64)
    all_stats_pass = all(t["passed"] for t in stat_tests)
    print(f"Statistical tests: {'ALL PASSED' if all_stats_pass else 'SOME FAILED'}")
    print(f"Pattern analysis: {'PASSED' if kp_result['passed'] else 'FAILED'}")
    print(f"ECB penguin: {'PASSED' if penguin['passed'] else 'FAILED'}")
    print("=" * 64)


if __name__ == "__main__":
    run_all_analysis()
