"""
Dimensional Encryption — Reference Implementation

A heterogeneous multi-layer encryption scheme where security derives from
composing transformations across independent algebraic families.

This is a REFERENCE IMPLEMENTATION for correctness verification and study.
It is NOT optimized for production use. Do not use for real encryption
until the scheme has undergone public cryptanalysis review.

Authors: Ali Vonk, M
Version: 0.1
License: Proprietary — SilentBot
"""

from .scheme import encrypt, decrypt, generate_key
from .dimensions import DIMENSION_REGISTRY

__version__ = "0.1.0"
__all__ = ["encrypt", "decrypt", "generate_key", "DIMENSION_REGISTRY"]
