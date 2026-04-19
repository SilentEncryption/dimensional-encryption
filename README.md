# Dimensional Encryption

A symmetric block cipher that composes transformations from independent
algebraic families, with a formally proven fault tolerance property:
the scheme retains security even if a majority of its constituent
families are completely broken.

**Status:** Research preview. Not yet audited. Do not use for production encryption.

---

## What's new

Modern symmetric ciphers (AES, ChaCha20, Camellia) are built on a single
algebraic primitive. A mathematical breakthrough against that primitive
would invalidate every bit of data encrypted with it. Post-quantum
standards like CRYSTALS-Kyber concentrate trust in one hardness assumption
(Module-LWE).

**Dimensional Encryption (DE)** composes layers drawn from six different
algebraic families — substitution-permutation networks, lattice-based
linear maps, permutation group compositions, hash-derived Feistel
networks, elliptic curve analogs, and multivariate polynomials —
separated by hash-layer "firewalls."

We prove three properties using only standard techniques (no new hardness
assumptions):

1. **IND-CPA security** with tight reduction via hybrid argument
2. **Fault tolerance** — the scheme remains secure as long as at least
   one algebraic family and one adjacent hash layer survive, even if
   every other layer is completely broken
3. **Composition safety** — hash layers prevent cross-family algebraic
   attacks by the standard PRF argument

To our knowledge, no prior symmetric cipher offers provable fault
tolerance across heterogeneous algebraic families.

---

## Documents

| Doc | Content |
|---|---|
| [`paper/`](paper/) | The formal paper (LaTeX + PDF) |
| [`docs/00-foundation.md`](docs/00-foundation.md) | Scheme definition and attacker model |
| [`docs/01-transformation-zoo.md`](docs/01-transformation-zoo.md) | Six dimensions from six algebraic families |
| [`docs/02-expander-graph-construction.md`](docs/02-expander-graph-construction.md) | Expander graph construction and mixing proof |
| [`docs/03-security-reduction.md`](docs/03-security-reduction.md) | Three theorems with full proofs |
| [`docs/04-key-derivation-and-modes.md`](docs/04-key-derivation-and-modes.md) | HKDF, CTR mode, Encrypt-then-MAC |
| [`docs/05-parameter-selection-and-performance.md`](docs/05-parameter-selection-and-performance.md) | Concrete parameter sets and benchmarks |
| [`docs/06-reference-implementation.md`](docs/06-reference-implementation.md) | Implementation notes |
| [`docs/07-test-vectors.md`](docs/07-test-vectors.md) | 29 test vectors (JSON) |

---

## Implementation

### Python reference implementation

Pure Python, zero dependencies outside the standard library. Designed
for correctness and auditability, not speed.

```bash
cd src/
python3 -m dimensional_encryption.tests          # Full test suite
python3 -m dimensional_encryption.demo           # Live demonstration
python3 -m dimensional_encryption.test_vectors   # Generate & validate vectors
python3 -m dimensional_encryption.cryptanalysis  # Statistical analysis suite
```

All 29 test vectors pass. Statistical tests (NIST-style frequency, runs,
chi-squared, serial correlation, avalanche) all pass on generated
ciphertext.

### C implementation (BLAKE3-accelerated)

Optimized C implementation with BLAKE3 for the hash dimension.

```bash
cd src/c/
make          # Requires OpenSSL and BLAKE3 (e.g. `brew install openssl blake3`)
./de_bench
```

Throughput on Apple Silicon (M-series):

| Profile | Throughput | Notes |
|---|---|---|
| DE-256-Fast (k=8, no EC) | ~12.9 MB/s | Recommended default |
| DE-128-Fast (k=6, no EC) | ~17.6 MB/s | Faster, slightly less fault tolerance |
| k=4 | ~23.3 MB/s | Minimal viable |
| AES-256-GCM (software) | ~32 MB/s | For reference |
| AES-256-GCM (AES-NI) | ~228 MB/s | Hardware accelerated |

---

## Using as a library

```python
from dimensional_encryption import encrypt, decrypt, generate_key

key = generate_key()
ciphertext = encrypt(key, b"Hello, world!")
plaintext = decrypt(key, ciphertext)
assert plaintext == b"Hello, world!"
```

Authentication is built in via HMAC-SHA256. Tampered ciphertexts raise
`ValueError` on decryption.

---

## Status and caveats

This is a **research preview** published to invite cryptanalysis. It has
not been audited by the cryptographic community. Do not use it for
anything that matters until independent review has happened.

Things we know are sharp edges:
- Python reference is not constant-time (side-channel vulnerable)
- BLAKE3 C implementation has not been reviewed for constant-time execution
- Parameter choices are reasonable but have not survived cryptanalysis

Things we *don't* know:
- Whether any unexpected algebraic interactions survive the hash-firewall argument
- Whether Dimension 5 (EC analog) composition introduces new attack vectors
  beyond the quantum vulnerability already acknowledged

If you find an attack, please open an issue or contact the author.

---

## Citing

If this work is useful to you, cite it as:

```
Vonk, A. (2026). Dimensional Encryption: A Fault-Tolerant Cipher from
Heterogeneous Pseudorandom Permutations. SilentBot Technical Report.
https://github.com/SilentEncryption/dimensional-encryption
```

A BibTeX entry is in [`CITATION.bib`](CITATION.bib).

---

## Contact

Ali Vonk — `silentbot@icloud.com` — SilentBot, Netherlands

---

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).

The mathematical scheme itself is in the public domain; the license
governs only the source code and documentation.
