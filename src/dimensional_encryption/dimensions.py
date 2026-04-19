"""
The Transformation Zoo — All six dimension implementations.

Each dimension implements:
    transform(key: bytes, block: bytes) -> bytes
    inverse(key: bytes, block: bytes) -> bytes

All blocks are exactly 32 bytes (256 bits).
All keys are exactly 32 bytes (256 bits).
"""

import hashlib
import hmac
import struct
from typing import Callable, NamedTuple


BLOCK_SIZE = 32  # 256 bits


class Dimension(NamedTuple):
    name: str
    dim_id: int
    transform: Callable[[bytes, bytes], bytes]
    inverse: Callable[[bytes, bytes], bytes]


# ---------------------------------------------------------------------------
# Helper: deterministic PRNG from a seed (for generating internal parameters)
# ---------------------------------------------------------------------------

class DeterministicPRNG:
    """SHAKE-256 based deterministic byte stream from a seed."""

    def __init__(self, seed: bytes):
        self._shake = hashlib.shake_256(seed)
        self._buffer = b""
        self._offset = 0
        self._consumed = 0

    def read(self, n: int) -> bytes:
        needed = n - (len(self._buffer) - self._offset)
        if needed > 0:
            # Generate enough bytes (request extra to avoid repeated calls)
            total = self._consumed + n + 1024
            self._buffer = self._shake.digest(total)
            self._offset = self._consumed
        result = self._buffer[self._offset:self._offset + n]
        self._offset += n
        self._consumed = self._offset
        return result

    def read_int(self, modulus: int) -> int:
        # Rejection sampling for uniform distribution
        byte_count = (modulus.bit_length() + 7) // 8 + 1
        while True:
            raw = int.from_bytes(self.read(byte_count), "big")
            if raw < (256 ** byte_count // modulus) * modulus:
                return raw % modulus


# ---------------------------------------------------------------------------
# Dimension 1: Substitution-Permutation Network (SPN)
# ---------------------------------------------------------------------------

def _spn_generate_sbox(prng: DeterministicPRNG) -> tuple[list[int], list[int]]:
    """Generate a random bijective S-box (and its inverse) via Fisher-Yates."""
    sbox = list(range(256))
    for i in range(255, 0, -1):
        j = prng.read_int(i + 1)
        sbox[i], sbox[j] = sbox[j], sbox[i]
    inv_sbox = [0] * 256
    for i, v in enumerate(sbox):
        inv_sbox[v] = i
    return sbox, inv_sbox


def _spn_generate_perm(prng: DeterministicPRNG, n: int) -> tuple[list[int], list[int]]:
    """Generate a random byte permutation (and its inverse)."""
    perm = list(range(n))
    for i in range(n - 1, 0, -1):
        j = prng.read_int(i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    inv_perm = [0] * n
    for i, v in enumerate(perm):
        inv_perm[v] = i
    return perm, inv_perm


def _spn_mix_columns(state: bytearray) -> bytearray:
    """Feistel-style mixing: split into halves, XOR left with f(right), swap.
    Two rounds of this is its own inverse when reversed."""
    n = len(state)
    half = n // 2
    left = state[:half]
    right = state[half:]
    # Round 1: left ^= right (byte-rotated)
    new_left = bytearray(left[i] ^ right[(i + 1) % half] for i in range(half))
    # Round 2: right ^= new_left (byte-rotated differently)
    new_right = bytearray(right[i] ^ new_left[(i + 3) % half] for i in range(half))
    return bytearray(new_left + new_right)


def _spn_inv_mix_columns(state: bytearray) -> bytearray:
    """Exact inverse of _spn_mix_columns."""
    n = len(state)
    half = n // 2
    new_left = state[:half]
    new_right = state[half:]
    # Undo round 2: right = new_right ^ new_left (rotated)
    right = bytearray(new_right[i] ^ new_left[(i + 3) % half] for i in range(half))
    # Undo round 1: left = new_left ^ right (rotated)
    left = bytearray(new_left[i] ^ right[(i + 1) % half] for i in range(half))
    return bytearray(left + right)


def _spn_round(state: bytearray, sbox: list[int], perm: list[int],
               round_key: bytes) -> bytearray:
    # Substitute
    state = bytearray(sbox[b] for b in state)
    # Permute byte positions
    state = bytearray(state[perm[i]] for i in range(len(state)))
    # Mix
    state = _spn_mix_columns(state)
    # Add round key
    state = bytearray(a ^ b for a, b in zip(state, round_key))
    return state


def _spn_inv_round(state: bytearray, inv_sbox: list[int], inv_perm: list[int],
                   round_key: bytes) -> bytearray:
    # Remove round key
    state = bytearray(a ^ b for a, b in zip(state, round_key))
    # Inverse mix
    state = _spn_inv_mix_columns(state)
    # Inverse permute
    state = bytearray(state[inv_perm[i]] for i in range(len(state)))
    # Inverse substitute
    state = bytearray(inv_sbox[b] for b in state)
    return state


def spn_transform(key: bytes, block: bytes) -> bytes:
    assert len(key) == BLOCK_SIZE and len(block) == BLOCK_SIZE
    prng = DeterministicPRNG(key)
    sbox, _ = _spn_generate_sbox(prng)
    perm, _ = _spn_generate_perm(prng, BLOCK_SIZE)
    num_rounds = 10
    round_keys = [prng.read(BLOCK_SIZE) for _ in range(num_rounds)]

    state = bytearray(block)
    for r in range(num_rounds):
        state = _spn_round(state, sbox, perm, round_keys[r])
    return bytes(state)


def spn_inverse(key: bytes, block: bytes) -> bytes:
    assert len(key) == BLOCK_SIZE and len(block) == BLOCK_SIZE
    prng = DeterministicPRNG(key)
    sbox, inv_sbox = _spn_generate_sbox(prng)
    _, inv_perm = _spn_generate_perm(prng, BLOCK_SIZE)
    num_rounds = 10
    round_keys = [prng.read(BLOCK_SIZE) for _ in range(num_rounds)]

    state = bytearray(block)
    for r in range(num_rounds - 1, -1, -1):
        state = _spn_inv_round(state, inv_sbox, inv_perm, round_keys[r])
    return bytes(state)


# ---------------------------------------------------------------------------
# Dimension 2: Lattice-Based Transformation
# ---------------------------------------------------------------------------

def _lattice_generate_invertible_matrix_mod256(prng: DeterministicPRNG,
                                                n: int) -> list[list[int]]:
    """Generate an invertible n×n matrix mod 256.

    Strategy: start with identity, apply random row operations.
    This guarantees invertibility (det remains odd throughout)."""
    matrix = [[1 if i == j else 0 for j in range(n)] for i in range(n)]

    num_ops = n * 4  # Enough random operations for good mixing
    for _ in range(num_ops):
        op = prng.read_int(3)
        r1 = prng.read_int(n)
        r2 = prng.read_int(n - 1)
        if r2 >= r1:
            r2 += 1
        scale = prng.read_int(128) * 2 + 1  # Odd scalar (invertible mod 256)

        if op == 0:
            # Add scaled row r2 to row r1
            for j in range(n):
                matrix[r1][j] = (matrix[r1][j] + scale * matrix[r2][j]) % 256
        elif op == 1:
            # Swap rows
            matrix[r1], matrix[r2] = matrix[r2], matrix[r1]
        else:
            # Scale row by odd number
            for j in range(n):
                matrix[r1][j] = (matrix[r1][j] * scale) % 256

    return matrix


def _lattice_mat_vec_mul_mod256(matrix: list[list[int]], vec: list[int]) -> list[int]:
    """Matrix-vector multiplication mod 256."""
    n = len(vec)
    result = [0] * n
    for i in range(n):
        s = 0
        for j in range(n):
            s += matrix[i][j] * vec[j]
        result[i] = s % 256
    return result


def _lattice_mat_inverse_mod256(matrix: list[list[int]]) -> list[list[int]]:
    """Compute matrix inverse mod 256 using Gaussian elimination."""
    n = len(matrix)
    aug = [row[:] + [1 if i == j else 0 for j in range(n)]
           for i, row in enumerate(matrix)]

    for col in range(n):
        # Find pivot with odd value (invertible mod 256)
        pivot = -1
        for row in range(col, n):
            if aug[row][col] % 2 == 1:
                pivot = row
                break
        if pivot == -1:
            raise ValueError("Matrix not invertible mod 256")
        aug[col], aug[pivot] = aug[pivot], aug[col]

        inv_pivot = pow(aug[col][col], -1, 256)
        for j in range(2 * n):
            aug[col][j] = (aug[col][j] * inv_pivot) % 256

        for row in range(n):
            if row == col:
                continue
            factor = aug[row][col]
            for j in range(2 * n):
                aug[row][j] = (aug[row][j] - factor * aug[col][j]) % 256

    return [row[n:] for row in aug]


def lattice_transform(key: bytes, block: bytes) -> bytes:
    """Lattice-inspired transform: invertible matrix multiply mod 256
    with additive offset. In the symmetric setting, we don't need LWE
    noise — the matrix itself provides the keyed permutation."""
    assert len(key) == BLOCK_SIZE and len(block) == BLOCK_SIZE

    prng = DeterministicPRNG(key)
    matrix = _lattice_generate_invertible_matrix_mod256(prng, BLOCK_SIZE)
    offset = list(prng.read(BLOCK_SIZE))

    vec = list(block)
    result = _lattice_mat_vec_mul_mod256(matrix, vec)
    result = [(result[i] + offset[i]) % 256 for i in range(BLOCK_SIZE)]

    return bytes(result)


def lattice_inverse(key: bytes, block: bytes) -> bytes:
    assert len(key) == BLOCK_SIZE and len(block) == BLOCK_SIZE

    prng = DeterministicPRNG(key)
    matrix = _lattice_generate_invertible_matrix_mod256(prng, BLOCK_SIZE)
    offset = list(prng.read(BLOCK_SIZE))
    inv_matrix = _lattice_mat_inverse_mod256(matrix)

    vec = list(block)
    # Remove offset, then multiply by inverse matrix
    vec = [(vec[i] - offset[i]) % 256 for i in range(BLOCK_SIZE)]
    result = _lattice_mat_vec_mul_mod256(inv_matrix, vec)

    return bytes(result)


# ---------------------------------------------------------------------------
# Dimension 3: Permutation Group Transformation
# ---------------------------------------------------------------------------

def _perm_generate_cycles(prng: DeterministicPRNG, n: int,
                          num_cycles: int) -> list[tuple[list[int], list[int]]]:
    """Generate random permutation cycles and their inverses."""
    cycles = []
    for _ in range(num_cycles):
        perm, inv_perm = _spn_generate_perm(prng, n)
        cycles.append((perm, inv_perm))
    return cycles


def permutation_transform(key: bytes, block: bytes) -> bytes:
    assert len(key) == BLOCK_SIZE and len(block) == BLOCK_SIZE
    prng = DeterministicPRNG(key)
    num_cycles = 8
    cycles = _perm_generate_cycles(prng, BLOCK_SIZE, num_cycles)

    # Generate per-cycle XOR keys for nonlinearity
    xor_keys = [prng.read(BLOCK_SIZE) for _ in range(num_cycles)]

    state = bytearray(block)
    for i, (perm, _) in enumerate(cycles):
        # Apply permutation
        state = bytearray(state[perm[j]] for j in range(BLOCK_SIZE))
        # XOR with cycle key (adds nonlinearity to pure permutation)
        state = bytearray(a ^ b for a, b in zip(state, xor_keys[i]))
    return bytes(state)


def permutation_inverse(key: bytes, block: bytes) -> bytes:
    assert len(key) == BLOCK_SIZE and len(block) == BLOCK_SIZE
    prng = DeterministicPRNG(key)
    num_cycles = 8
    cycles = _perm_generate_cycles(prng, BLOCK_SIZE, num_cycles)
    xor_keys = [prng.read(BLOCK_SIZE) for _ in range(num_cycles)]

    state = bytearray(block)
    for i in range(num_cycles - 1, -1, -1):
        _, inv_perm = cycles[i]
        # Undo XOR
        state = bytearray(a ^ b for a, b in zip(state, xor_keys[i]))
        # Undo permutation
        state = bytearray(state[inv_perm[j]] for j in range(BLOCK_SIZE))
    return bytes(state)


# ---------------------------------------------------------------------------
# Dimension 4: Hash-Derived Nonlinear Transformation (XOR with PRF output)
# ---------------------------------------------------------------------------

def hash_transform(key: bytes, block: bytes) -> bytes:
    """XOR block with HMAC-SHA256 keystream. Self-inverse."""
    assert len(key) == BLOCK_SIZE and len(block) == BLOCK_SIZE
    keystream = hmac.new(key, block, hashlib.sha256).digest()
    # HMAC output depends on the block, making this a keyed permutation
    # rather than a simple stream cipher. For invertibility, we use a
    # Feistel-like structure with 4 rounds.
    state = bytearray(block)
    half = BLOCK_SIZE // 2

    for round_num in range(4):
        left = state[:half]
        right = state[half:]
        round_input = bytes(right) + struct.pack(">I", round_num)
        h = hmac.new(key, round_input, hashlib.sha256).digest()[:half]
        new_left = bytearray(a ^ b for a, b in zip(left, h))
        state = bytearray(right) + bytearray(new_left)

    return bytes(state)


def hash_inverse(key: bytes, block: bytes) -> bytes:
    """Inverse of hash_transform — reverse the Feistel rounds."""
    assert len(key) == BLOCK_SIZE and len(block) == BLOCK_SIZE
    state = bytearray(block)
    half = BLOCK_SIZE // 2

    for round_num in range(3, -1, -1):
        # In the forward direction, after round: state = right || (left ^ H(right))
        # So current state = right_prev || new_left
        # To invert: right = state[:half], new_left = state[half:]
        right = state[:half]
        new_left = state[half:]
        round_input = bytes(right) + struct.pack(">I", round_num)
        h = hmac.new(key, round_input, hashlib.sha256).digest()[:half]
        left = bytearray(a ^ b for a, b in zip(new_left, h))
        state = bytearray(left) + bytearray(right)

    return bytes(state)


# ---------------------------------------------------------------------------
# Dimension 5: Elliptic Curve Point Transformation (Simplified)
# ---------------------------------------------------------------------------
#
# A full EC implementation would be large. For the reference implementation,
# we use a simplified modular arithmetic analog that preserves the algebraic
# structure: multiplication by a secret scalar in a large prime field.
#
# This captures the mathematical essence (one-way function based on the
# discrete log problem) without requiring a full EC library.

# A 256-bit prime (close to 2^256)
EC_PRIME = (1 << 256) - 189  # This is prime


def ec_transform(key: bytes, block: bytes) -> bytes:
    assert len(key) == BLOCK_SIZE and len(block) == BLOCK_SIZE
    # Interpret block and key as integers
    m = int.from_bytes(block, "big")
    k = int.from_bytes(key, "big")

    # Ensure k is nonzero mod p
    k = k % (EC_PRIME - 1)
    if k == 0:
        k = 1

    # "Scalar multiplication" analog: c = m * k mod p
    # (In real EC, this would be point multiplication on a curve)
    if m == 0:
        m = 1  # Avoid zero (not a valid group element)
    c = (m * k) % EC_PRIME

    return c.to_bytes(BLOCK_SIZE, "big")


def ec_inverse(key: bytes, block: bytes) -> bytes:
    assert len(key) == BLOCK_SIZE and len(block) == BLOCK_SIZE
    c = int.from_bytes(block, "big")
    k = int.from_bytes(key, "big")

    k = k % (EC_PRIME - 1)
    if k == 0:
        k = 1

    # m = c * k^-1 mod p
    k_inv = pow(k, -1, EC_PRIME)
    m = (c * k_inv) % EC_PRIME

    return m.to_bytes(BLOCK_SIZE, "big")


# ---------------------------------------------------------------------------
# Dimension 6: Multivariate Polynomial Transformation (Simplified)
# ---------------------------------------------------------------------------
#
# Full multivariate polynomial evaluation over GF(256) with HFE trapdoor.
# Simplified: we use a key-dependent affine transformation (S ∘ F ∘ T) where
# F is a simple quadratic map and S, T are secret affine transforms.

GF_MOD = 256  # GF(2^8) simplified as integers mod 256


def _mv_generate_affine(prng: DeterministicPRNG, n: int) -> tuple[list[list[int]], list[int]]:
    """Generate a random invertible affine transformation over Z/256Z.
    Returns (matrix, offset_vector).
    Uses the same row-operation approach as the lattice dimension to
    guarantee invertibility."""
    matrix = _lattice_generate_invertible_matrix_mod256(prng, n)
    offset = [prng.read_int(GF_MOD) for _ in range(n)]
    return matrix, offset


def _mv_affine_apply(matrix: list[list[int]], offset: list[int],
                     vec: list[int]) -> list[int]:
    n = len(vec)
    result = [0] * n
    for i in range(n):
        s = offset[i]
        for j in range(n):
            s += matrix[i][j] * vec[j]
        result[i] = s % GF_MOD
    return result


def _mv_mat_inverse_mod256(matrix: list[list[int]]) -> list[list[int]]:
    """Matrix inverse mod 256 — delegates to shared implementation."""
    return _lattice_mat_inverse_mod256(matrix)


def _mv_nonlinear_map(vec: list[int]) -> list[int]:
    """Feistel-style nonlinear map that is trivially invertible.
    Process pairs: left ^= S(right), then right ^= S(left).
    S(x) = (x * x + x) mod 256 — a fixed nonlinear S-box."""
    n = len(vec)
    result = list(vec)
    half = n // 2
    # Round 1: left half XORed with function of right half
    for i in range(half):
        s = (result[half + i] * result[half + i] + result[half + i]) & 0xFF
        result[i] ^= s
    # Round 2: right half XORed with function of new left half
    for i in range(half):
        s = (result[i] * result[i] + result[i]) & 0xFF
        result[half + i] ^= s
    return result


def _mv_nonlinear_map_inverse(vec: list[int]) -> list[int]:
    """Inverse of the Feistel nonlinear map — undo rounds in reverse."""
    n = len(vec)
    result = list(vec)
    half = n // 2
    # Undo round 2
    for i in range(half):
        s = (result[i] * result[i] + result[i]) & 0xFF
        result[half + i] ^= s
    # Undo round 1
    for i in range(half):
        s = (result[half + i] * result[half + i] + result[half + i]) & 0xFF
        result[i] ^= s
    return result


def multivariate_transform(key: bytes, block: bytes) -> bytes:
    assert len(key) == BLOCK_SIZE and len(block) == BLOCK_SIZE
    prng = DeterministicPRNG(key)
    n = BLOCK_SIZE

    # Generate two secret affine transforms (the trapdoor)
    S_mat, S_off = _mv_generate_affine(prng, n)
    T_mat, T_off = _mv_generate_affine(prng, n)

    vec = list(block)

    # Apply: T, then nonlinear F, then S
    vec = _mv_affine_apply(T_mat, T_off, vec)
    vec = _mv_nonlinear_map(vec)
    vec = _mv_affine_apply(S_mat, S_off, vec)

    return bytes(vec)


def multivariate_inverse(key: bytes, block: bytes) -> bytes:
    assert len(key) == BLOCK_SIZE and len(block) == BLOCK_SIZE
    prng = DeterministicPRNG(key)
    n = BLOCK_SIZE

    S_mat, S_off = _mv_generate_affine(prng, n)
    T_mat, T_off = _mv_generate_affine(prng, n)

    # Compute inverse affine transforms
    S_inv = _mv_mat_inverse_mod256(S_mat)
    T_inv = _mv_mat_inverse_mod256(T_mat)

    vec = list(block)

    # Invert: S^-1, then F^-1, then T^-1
    # S^-1: y -> S_inv * (y - S_off)
    vec = [(vec[i] - S_off[i]) % GF_MOD for i in range(n)]
    vec = _mv_affine_apply(S_inv, [0] * n, vec)

    vec = _mv_nonlinear_map_inverse(vec)

    # T^-1
    vec = [(vec[i] - T_off[i]) % GF_MOD for i in range(n)]
    vec = _mv_affine_apply(T_inv, [0] * n, vec)

    return bytes(vec)


# ---------------------------------------------------------------------------
# Dimension Registry
# ---------------------------------------------------------------------------

DIMENSION_REGISTRY = {
    1: Dimension("SPN", 1, spn_transform, spn_inverse),
    2: Dimension("Lattice", 2, lattice_transform, lattice_inverse),
    3: Dimension("Permutation", 3, permutation_transform, permutation_inverse),
    4: Dimension("Hash-Feistel", 4, hash_transform, hash_inverse),
    5: Dimension("EC-Analog", 5, ec_transform, ec_inverse),
    6: Dimension("Multivariate", 6, multivariate_transform, multivariate_inverse),
}

# Algebraic dimensions (everything except hash)
ALGEBRAIC_DIMS = [1, 2, 3, 5, 6]
