#!/usr/bin/env python3
"""
Dimensional Encryption — Interactive Demo

Demonstrates the complete encryption/decryption cycle with
human-readable output showing what happens at each step.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dimensional_encryption.scheme import (
    encrypt, decrypt, generate_key,
    _derive_layer_config, _encrypt_block,
    BLOCK_SIZE, HEADER_SIZE, TAG_SIZE,
)
from dimensional_encryption.dimensions import DIMENSION_REGISTRY


def demo_basic():
    """Basic encrypt/decrypt demonstration."""
    print("=" * 60)
    print("DIMENSIONAL ENCRYPTION — DEMO")
    print("=" * 60)

    # Generate key
    master_key = generate_key()
    print(f"\n1. Generated master key ({len(master_key)*8} bits):")
    print(f"   {master_key.hex()}")

    # Encrypt a message
    message = b"Hello from SilentBot! This is Dimensional Encryption."
    print(f"\n2. Plaintext ({len(message)} bytes):")
    print(f'   "{message.decode()}"')

    start = time.time()
    ciphertext = encrypt(master_key, message, num_layers=8)
    enc_time = time.time() - start

    print(f"\n3. Ciphertext ({len(ciphertext)} bytes, {enc_time*1000:.1f}ms):")
    print(f"   Header:  {ciphertext[:HEADER_SIZE].hex()}")
    print(f"   Magic:   {ciphertext[:4]} (DENC)")
    print(f"   Version: {ciphertext[4]}")
    print(f"   Layers:  {ciphertext[5]}")
    print(f"   Nonce:   {ciphertext[9:25].hex()}")
    body = ciphertext[HEADER_SIZE:-TAG_SIZE]
    print(f"   Body:    {body[:32].hex()}{'...' if len(body) > 32 else ''}")
    print(f"   HMAC:    {ciphertext[-TAG_SIZE:].hex()}")
    print(f"   Overhead: {HEADER_SIZE + TAG_SIZE} bytes "
          f"({(HEADER_SIZE + TAG_SIZE) / len(message) * 100:.1f}% of plaintext)")

    # Decrypt
    start = time.time()
    decrypted = decrypt(master_key, ciphertext)
    dec_time = time.time() - start

    print(f"\n4. Decrypted ({dec_time*1000:.1f}ms):")
    print(f'   "{decrypted.decode()}"')
    print(f"   Match: {decrypted == message}")

    # Show the layer structure
    print(f"\n5. Layer structure (derived from key):")
    nonce = ciphertext[9:25]
    layers = _derive_layer_config(master_key, 8, nonce)
    for i, (dim_id, layer_key) in enumerate(layers):
        dim = DIMENSION_REGISTRY[dim_id]
        role = "firewall" if dim_id == 4 else "algebraic"
        print(f"   Layer {i+1}: Dim {dim_id} ({dim.name:15s}) "
              f"[{role}] key={layer_key[:4].hex()}...")


def demo_tamper_detection():
    """Show that tampering is detected."""
    print("\n" + "=" * 60)
    print("TAMPER DETECTION DEMO")
    print("=" * 60)

    key = generate_key()
    message = b"Transfer $1000 to account 12345"
    ct = encrypt(key, message)
    print(f"\n  Original: \"{message.decode()}\"")

    # Tamper with the ciphertext
    tampered = bytearray(ct)
    tampered[30] ^= 0xFF
    tampered = bytes(tampered)

    print(f"  Tampered byte 30 (flipped all bits)")
    try:
        decrypt(key, tampered)
        print("  Result: ACCEPTED (THIS SHOULD NOT HAPPEN)")
    except ValueError as e:
        print(f"  Result: REJECTED — {e}")


def demo_wrong_key():
    """Show that wrong key fails."""
    print("\n" + "=" * 60)
    print("WRONG KEY DEMO")
    print("=" * 60)

    key1 = generate_key()
    key2 = generate_key()
    message = b"Secret information"
    ct = encrypt(key1, message)
    print(f"\n  Encrypted with key1: {key1[:8].hex()}...")
    print(f"  Trying key2:         {key2[:8].hex()}...")
    try:
        decrypt(key2, ct)
        print("  Result: DECRYPTED (THIS SHOULD NOT HAPPEN)")
    except ValueError as e:
        print(f"  Result: REJECTED — {e}")


def demo_avalanche():
    """Show that a tiny change produces completely different ciphertext."""
    print("\n" + "=" * 60)
    print("AVALANCHE EFFECT DEMO")
    print("=" * 60)

    key = generate_key()
    nonce = os.urandom(16)

    msg1 = b"A" * 32
    msg2 = b"A" * 31 + b"B"  # Change last byte only

    ct1 = encrypt(key, msg1, nonce=nonce)
    ct2 = encrypt(key, msg2, nonce=nonce)

    body1 = ct1[HEADER_SIZE:-TAG_SIZE]
    body2 = ct2[HEADER_SIZE:-TAG_SIZE]

    diff_bits = sum(bin(a ^ b).count('1') for a, b in zip(body1, body2))
    total_bits = len(body1) * 8

    print(f"\n  Message 1: {'A'*32}")
    print(f"  Message 2: {'A'*31}B")
    print(f"  Changed:   1 byte (last position)")
    print(f"  Cipher 1:  {body1[:16].hex()}...")
    print(f"  Cipher 2:  {body2[:16].hex()}...")
    print(f"  Bits diff: {diff_bits}/{total_bits} ({diff_bits/total_bits*100:.1f}%)")


def demo_performance():
    """Benchmark at different message sizes."""
    print("\n" + "=" * 60)
    print("PERFORMANCE BENCHMARK")
    print("=" * 60)

    key = generate_key()
    sizes = [32, 256, 1024, 4096]

    print(f"\n  {'Size':>8s} | {'k=4':>10s} | {'k=6':>10s} | {'k=8':>10s}")
    print(f"  {'-'*8}-+-{'-'*10}-+-{'-'*10}-+-{'-'*10}")

    for size in sizes:
        data = os.urandom(size)
        row = f"  {size:>7d}B |"
        for k in [4, 6, 8]:
            start = time.time()
            iters = max(1, 5000 // size)
            for _ in range(iters):
                encrypt(key, data, num_layers=k)
            elapsed = (time.time() - start) / iters
            throughput = size / elapsed / 1024
            row += f" {throughput:>7.1f}K/s |"
        print(row)


if __name__ == "__main__":
    demo_basic()
    demo_tamper_detection()
    demo_wrong_key()
    demo_avalanche()
    demo_performance()
    print("\n" + "=" * 60)
    print("ALL DEMOS COMPLETE")
    print("=" * 60)
