"""
Dimensional Encryption — Core Scheme

Implements:
    - HKDF key derivation (master key → layer types + layer keys)
    - DE-CTR mode (counter mode encryption for arbitrary-length messages)
    - DE-CTR-HMAC authenticated encryption (Encrypt-then-MAC)

Wire format:
    [magic:4][version:1][params:4][nonce:16] || [ciphertext] || [hmac_tag:32]
"""

import hashlib
import hmac as hmac_mod
import os
import struct
from typing import Optional

from .dimensions import (
    BLOCK_SIZE, DIMENSION_REGISTRY, ALGEBRAIC_DIMS,
)


# Wire format constants
MAGIC = b"DENC"
VERSION = 0x01
HEADER_SIZE = 25  # 4 + 1 + 4 + 16
TAG_SIZE = 32     # HMAC-SHA256
NONCE_SIZE = 16


# ---------------------------------------------------------------------------
# HKDF (RFC 5869) — HMAC-based Key Derivation Function
# ---------------------------------------------------------------------------

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract: PRK = HMAC(salt, input_key_material)."""
    if not salt:
        salt = b"\x00" * 32
    return hmac_mod.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand: derive `length` bytes from PRK with context `info`."""
    hash_len = 32  # SHA-256
    n = (length + hash_len - 1) // hash_len
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac_mod.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Full HKDF: Extract-then-Expand."""
    prk = _hkdf_extract(salt, ikm)
    return _hkdf_expand(prk, info, length)


# ---------------------------------------------------------------------------
# Key Derivation: master key → (dimension types, layer keys)
# ---------------------------------------------------------------------------

def _derive_layer_config(master_key: bytes, num_layers: int,
                         nonce: bytes) -> list[tuple[int, bytes]]:
    """
    Derive dimension types and layer keys from master key.

    Returns list of (dimension_id, layer_key) tuples.

    Enforces the hash-firewall rule:
        Even positions (0, 2, 4, ...): always hash (Dimension 4)
        Odd positions (1, 3, 5, ...): algebraic dimension derived from key
    """
    salt = b"DimensionalEncryption-v1"
    prk = _hkdf_extract(salt, master_key)

    # Derive dimension types for algebraic layers
    type_bytes = _hkdf_expand(prk, b"DE-v1-types", num_layers)

    layers = []
    for i in range(num_layers):
        if i % 2 == 0:
            dim_id = 4  # Hash layer (firewall)
        else:
            # Map to one of the algebraic dimensions
            dim_id = ALGEBRAIC_DIMS[type_bytes[i] % len(ALGEBRAIC_DIMS)]

        # Derive layer key (nonce mixed into first layer only)
        if i == 0:
            info = b"DE-v1-layer-0" + nonce
        else:
            info = f"DE-v1-layer-{i}".encode()
        layer_key = _hkdf_expand(prk, info, BLOCK_SIZE)

        layers.append((dim_id, layer_key))

    return layers


# ---------------------------------------------------------------------------
# Block cipher: encrypt/decrypt a single 32-byte block
# ---------------------------------------------------------------------------

def _encrypt_block(layers: list[tuple[int, bytes]], block: bytes) -> bytes:
    """Apply all layers in forward order."""
    state = block
    for dim_id, layer_key in layers:
        dim = DIMENSION_REGISTRY[dim_id]
        state = dim.transform(layer_key, state)
    return state


def _decrypt_block(layers: list[tuple[int, bytes]], block: bytes) -> bytes:
    """Apply all layers in reverse order with inverse transforms."""
    state = block
    for dim_id, layer_key in reversed(layers):
        dim = DIMENSION_REGISTRY[dim_id]
        state = dim.inverse(layer_key, state)
    return state


# ---------------------------------------------------------------------------
# CTR mode: encrypt/decrypt arbitrary-length messages
# ---------------------------------------------------------------------------

def _ctr_keystream_block(layers: list[tuple[int, bytes]],
                         nonce: bytes, counter: int) -> bytes:
    """Generate one keystream block: DE(nonce || counter)."""
    counter_bytes = counter.to_bytes(NONCE_SIZE, "big")
    input_block = nonce + counter_bytes
    assert len(input_block) == BLOCK_SIZE
    return _encrypt_block(layers, input_block)


def _ctr_process(layers: list[tuple[int, bytes]],
                 nonce: bytes, data: bytes) -> bytes:
    """CTR mode encrypt/decrypt (same operation — XOR with keystream)."""
    output = bytearray()
    num_blocks = (len(data) + BLOCK_SIZE - 1) // BLOCK_SIZE

    for i in range(num_blocks):
        keystream = _ctr_keystream_block(layers, nonce, i + 1)
        block_start = i * BLOCK_SIZE
        block_end = min(block_start + BLOCK_SIZE, len(data))
        block = data[block_start:block_end]

        # XOR (truncate keystream for last partial block)
        for j in range(len(block)):
            output.append(block[j] ^ keystream[j])

    return bytes(output)


# ---------------------------------------------------------------------------
# Wire format
# ---------------------------------------------------------------------------

def _build_header(num_layers: int, nonce: bytes) -> bytes:
    """Build the 25-byte header."""
    params = struct.pack(">BBH", num_layers, BLOCK_SIZE, 0)  # k, B, reserved
    return MAGIC + bytes([VERSION]) + params + nonce


def _parse_header(header: bytes) -> tuple[int, int, bytes]:
    """Parse header, return (num_layers, block_size, nonce)."""
    if len(header) < HEADER_SIZE:
        raise ValueError("Header too short")
    if header[:4] != MAGIC:
        raise ValueError(f"Invalid magic: expected {MAGIC!r}, got {header[:4]!r}")
    version = header[4]
    if version != VERSION:
        raise ValueError(f"Unsupported version: {version}")
    num_layers, block_size, _ = struct.unpack(">BBH", header[5:9])
    nonce = header[9:25]
    return num_layers, block_size, nonce


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_key() -> bytes:
    """Generate a random 256-bit master key."""
    return os.urandom(BLOCK_SIZE)


def encrypt(master_key: bytes, plaintext: bytes,
            num_layers: int = 8, nonce: Optional[bytes] = None) -> bytes:
    """
    Authenticated encryption using DE-CTR-HMAC.

    Args:
        master_key: 32-byte master key
        plaintext: arbitrary-length plaintext
        num_layers: number of dimension layers (default 8, must be even)
        nonce: optional 16-byte nonce (random if not provided)

    Returns:
        header || ciphertext || hmac_tag
    """
    if len(master_key) != BLOCK_SIZE:
        raise ValueError(f"Master key must be {BLOCK_SIZE} bytes")
    if num_layers < 2 or num_layers % 2 != 0:
        raise ValueError("num_layers must be even and >= 2")

    # Generate nonce
    if nonce is None:
        nonce = os.urandom(NONCE_SIZE)
    elif len(nonce) != NONCE_SIZE:
        raise ValueError(f"Nonce must be {NONCE_SIZE} bytes")

    # Derive layer configuration
    layers = _derive_layer_config(master_key, num_layers, nonce)

    # Build header
    header = _build_header(num_layers, nonce)

    # CTR mode encryption
    ciphertext = _ctr_process(layers, nonce, plaintext)

    # Compute HMAC over header + ciphertext (Encrypt-then-MAC)
    mac_key = _hkdf(master_key, b"DimensionalEncryption-v1",
                    b"DE-v1-mac", BLOCK_SIZE)
    tag = hmac_mod.new(mac_key, header + ciphertext, hashlib.sha256).digest()

    return header + ciphertext + tag


def decrypt(master_key: bytes, data: bytes) -> bytes:
    """
    Authenticated decryption using DE-CTR-HMAC.

    Args:
        master_key: 32-byte master key
        data: output of encrypt()

    Returns:
        plaintext

    Raises:
        ValueError: if authentication fails (data tampered or wrong key)
    """
    if len(master_key) != BLOCK_SIZE:
        raise ValueError(f"Master key must be {BLOCK_SIZE} bytes")
    if len(data) < HEADER_SIZE + TAG_SIZE:
        raise ValueError("Data too short to contain header + tag")

    # Split components
    header = data[:HEADER_SIZE]
    tag = data[-TAG_SIZE:]
    ciphertext = data[HEADER_SIZE:-TAG_SIZE]

    # Verify HMAC FIRST (before any decryption)
    mac_key = _hkdf(master_key, b"DimensionalEncryption-v1",
                    b"DE-v1-mac", BLOCK_SIZE)
    expected_tag = hmac_mod.new(mac_key, header + ciphertext,
                                hashlib.sha256).digest()
    if not hmac_mod.compare_digest(tag, expected_tag):
        raise ValueError("Authentication failed: data has been tampered with "
                         "or wrong key")

    # Parse header
    num_layers, block_size, nonce = _parse_header(header)

    # Derive layer configuration
    layers = _derive_layer_config(master_key, num_layers, nonce)

    # CTR mode decryption (same as encryption — XOR is its own inverse)
    plaintext = _ctr_process(layers, nonce, ciphertext)

    return plaintext
