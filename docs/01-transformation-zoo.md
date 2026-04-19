# Dimensional Encryption — The Transformation Zoo

**Project:** SilentBot — Dimensional Encryption  
**Version:** 0.1  
**Date:** 2026-04-13  
**Authors:** Ali Vonk, M  
**Prerequisite:** Read 00-foundation.md first  

---

## Purpose

This document defines the specific transformation families ("dimensions") available
in our scheme. Each one is a well-studied, invertible operation from a distinct
branch of mathematics. The security of any individual transform is not our
contribution — decades of research already established that. Our contribution is
composing them heterogeneously with hidden selection.

---

## Selection Criteria

Every transform in the zoo must satisfy ALL of these:

| Criterion | Why |
|---|---|
| **Invertible** | Decryption must be possible with the key |
| **Efficient** | Polynomial-time encrypt and decrypt (fast enough to be practical) |
| **Well-studied** | At least 10+ years of cryptanalysis literature |
| **Distinct algebraic family** | No two transforms share the same underlying math — this is our heterogeneity requirement |
| **Fixed output size** | Every transform maps a block of size B to a block of size B (composability) |
| **Post-quantum candidate** | Not broken by Shor's algorithm or known quantum attacks |

---

## The Six Dimensions

### Dimension 1: Substitution-Permutation Network (SPN)

**Mathematical family:** Finite field arithmetic (GF(2^8)) + bit permutations  
**Lineage:** Shannon (1949), Rijndael/AES (1998)  
**Years of study:** 75+  

**What it does:**  
Splits the data block into cells (e.g., 16 bytes). Each cell is pushed through a
substitution box (S-box) — a nonlinear lookup table over GF(2^8). Then the cells
are shuffled and mixed using linear operations (ShiftRows, MixColumns in AES terms).

**The key (params) controls:**
- The S-box contents (which substitution table to use)
- The permutation pattern (how cells are rearranged)
- Round constants for mixing

**Invertible?** Yes — S-boxes are bijections (one-to-one mappings), permutations
have inverses, linear mixing is invertible via matrix inverse.

**Why it's here:** SPN is the most battle-tested symmetric primitive in existence.
AES has survived 25+ years of sustained global attack. We're not using AES itself
(that would be redundant) — we're using the SPN *structure* with key-dependent
S-boxes, giving us a parameterized family.

**Analogy:** Think of it as a complex letter-substitution cipher on steroids. Each
letter gets replaced according to a secret lookup table, then the letters get
rearranged. Repeat several times.

---

### Dimension 2: Lattice-Based Transformation

**Mathematical family:** Integer lattice geometry (ℤⁿ)  
**Lineage:** Ajtai (1996), Regev/LWE (2005), NIST finalist CRYSTALS (2022)  
**Years of study:** 30+  

**What it does:**  
Treats the data block as a vector in n-dimensional integer space. Multiplies it by
a secret matrix A and adds controlled noise (a small error vector). The result is a
new point in lattice space that looks random without knowledge of A.

```
Encrypt: c = A · m + e  (mod q)
Decrypt: m = A⁻¹ · (c - e)  (mod q)
```

Where:
- `m` = message (as a vector)
- `A` = secret matrix (part of key)
- `e` = small noise vector (part of key — must be stored or derived)
- `q` = modulus

**The key (params) controls:**
- The matrix A
- The noise distribution parameters
- The modulus q

**Invertible?** Yes — given A and the noise parameters, you can subtract noise
and multiply by A⁻¹.

**Why it's here:** Lattice problems (LWE, SIS) are the foundation of most NIST
post-quantum standards. The hardness of finding short vectors in lattices has
resisted quantum attacks. This is mathematically *completely different* from
Dimension 1 — we've moved from finite field arithmetic to geometry in
high-dimensional integer space.

**Analogy:** Imagine hiding a message by shifting it to a random-looking position
in a huge grid, then adding a tiny wobble. Without knowing the grid pattern and
the wobble recipe, you can't find the original position.

---

### Dimension 3: Permutation Group Transformation

**Mathematical family:** Symmetric group theory (Sₙ)  
**Lineage:** Cayley (1854), modern: Keedwell (1999), Vaudenay (2003)  
**Years of study:** 170+ (group theory), 25+ (crypto applications)  

**What it does:**  
Treats the data block as a sequence of elements and applies a secret permutation —
a specific reordering pattern. But not a simple shuffle: it applies a *composition*
of permutation cycles, where the cycle structure is key-dependent.

Given a block of n elements [b₁, b₂, ..., bₙ]:

```
Encrypt: apply permutation σ = σ_k ∘ σ_{k-1} ∘ ... ∘ σ_1
         where each σ_i is derived from the key
Decrypt: apply σ⁻¹ = σ_1⁻¹ ∘ σ_2⁻¹ ∘ ... ∘ σ_k⁻¹
```

**The key (params) controls:**
- The number of component permutations
- The cycle structure of each component
- The composition order

**Invertible?** Yes — every permutation has a unique inverse permutation.

**Why it's here:** Permutation groups are a fundamentally different algebraic
object from fields (Dim 1) or lattices (Dim 2). The symmetric group Sₙ is
non-abelian (order matters: σ∘τ ≠ τ∘σ in general), which means the composition
structure resists attacks that exploit commutativity. Recovering a permutation
from its effect on unknown data, composed with other unknown permutations, is
hard.

**Analogy:** Imagine shuffling a deck of cards. You do 5 different specific
shuffles in sequence. Someone sees the final order but not the individual shuffles.
Reconstructing which 5 shuffles you did — in order — is combinatorially explosive.

---

### Dimension 4: Hash-Derived Nonlinear Transformation

**Mathematical family:** Cryptographic hash functions (pseudorandom functions)  
**Lineage:** Merkle-Damgård (1979), SHA family, BLAKE (2008), keyed-hash MACs  
**Years of study:** 45+  

**What it does:**  
Uses a keyed hash function to generate a pseudorandom stream, then XORs (combines)
this stream with the data. This is essentially a stream cipher layer, but the
key point is that the pseudorandom function is from a completely different
mathematical family than Dimensions 1-3.

```
Encrypt: c = m ⊕ H(key, counter)
Decrypt: m = c ⊕ H(key, counter)
```

Where H is a keyed hash (e.g., HMAC-SHA3 or BLAKE3 in keyed mode).

**The key (params) controls:**
- The hash function selection (from an approved set)
- The key input to the hash
- Initialization vector / counter starting value

**Invertible?** Yes — XOR is its own inverse. Apply the same operation twice
and you get the original back.

**Why it's here:** Hash functions derive their security from entirely different
assumptions than algebra — they rely on the pseudorandomness of iterating
compression functions. No algebraic structure to attack. This dimension acts as
a "firewall" between the algebraic dimensions: even if an attacker finds
structure in Dimensions 1-3, the hash layer destroys any pattern they could
exploit.

**Analogy:** You generate a long sequence of random-looking numbers from a
secret seed, then use those numbers to scramble your message. Without the seed,
the numbers look completely random — and the message is unrecoverable.

---

### Dimension 5: Elliptic Curve Point Transformation

**Mathematical family:** Elliptic curve arithmetic over finite fields  
**Lineage:** Miller (1985), Koblitz (1987), ECDH, EdDSA  
**Years of study:** 40+  

**What it does:**  
Maps the data block to a point on an elliptic curve (or a pair of points), then
applies a secret scalar multiplication — the elliptic curve equivalent of
exponentiation.

```
Encrypt: C = encode(m) then Q = k · P  (scalar multiplication on curve)
Decrypt: m = decode(k⁻¹ · Q)
```

Where:
- `P` = point derived from plaintext
- `k` = secret scalar (key)
- The curve parameters are fixed and public

**The key (params) controls:**
- The secret scalar k
- The encoding method (how data maps to curve points)
- Curve selection (from an approved set: e.g., Curve25519, P-256, Ed448)

**Invertible?** Yes — given k, compute k⁻¹ (mod curve order) and multiply.

**Why it's here:** Elliptic curves are algebraically rich but structurally
different from everything above. The discrete log problem on curves is in a
different complexity class from lattice problems, permutation composition, and
hash inversion. An attacker who masters any of the other dimensions still faces
a completely foreign structure here.

**Important caveat for post-quantum:** Shor's algorithm breaks standard ECDLP.
However, in our scheme the attacker doesn't know *which* dimension uses EC, and
the other dimensions protect the data even if this one is individually broken.
We may also substitute isogeny-based operations (CSIDH family) for quantum
resistance, pending further analysis.

**Analogy:** You take your message, place it as a point on a curved surface,
then "walk" along the surface a secret number of steps. The curved geometry
makes it very hard to figure out how many steps were taken just from the start
and end points.

---

### Dimension 6: Multivariate Polynomial Transformation

**Mathematical family:** Multivariate polynomial systems over finite fields  
**Lineage:** Matsumoto-Imai (1988), HFE (1996), NIST candidate GeMSS  
**Years of study:** 35+  

**What it does:**  
Treats the data block as a vector of variables (x₁, x₂, ..., xₙ) in a finite
field, then evaluates a system of secret quadratic (degree-2) polynomial equations:

```
y₁ = Σ a_{ij} · x_i · x_j + Σ b_i · x_i + c₁
y₂ = Σ d_{ij} · x_i · x_j + Σ e_i · x_i + c₂
...
```

**The key (params) controls:**
- The polynomial coefficients (a, b, c, d, e, ...)
- A secret affine transformation applied before and after (the "trapdoor")

**Invertible?** Yes — the trapdoor structure allows the legitimate key holder
to efficiently invert the system, while without the trapdoor, solving a random
multivariate quadratic system is NP-hard (and Grover gives only √ speedup
quantum).

**Why it's here:** Solving random MQ (multivariate quadratic) systems is one
of the oldest known NP-hard problems. It resists quantum attack beyond Grover's
generic speedup. Structurally, polynomial evaluation over finite fields is
completely different from lattices, permutations, hashes, and curves. It adds
genuine algebraic diversity.

**Analogy:** You feed your data values into a system of scrambled equations.
Only someone with the original equation structure (the trapdoor) can unscramble
the results. To everyone else, it looks like trying to solve a huge system of
intertwined equations simultaneously — which is known to be extremely hard.

---

## Composition: How Dimensions Work Together

### The selection problem (for the attacker)

Given 6 dimension types and a secret number of layers n, the attacker faces:

| n (layers) | Possible type combinations | Possible orderings |
|---|---|---|
| 4 | 6⁴ = 1,296 | 1,296 |
| 6 | 6⁶ = 46,656 | 46,656 |
| 8 | 6⁸ = 1,679,616 | 1,679,616 |

And for each combination, they must also guess the parameters — typically 128-256
bits per layer. So with 8 layers of 256-bit parameters:

**Total brute-force space: 1,679,616 × (2^256)^8 = 1,679,616 × 2^2048**

This is astronomically beyond brute-force reach.

But brute force isn't the real concern — **structural attacks** are. That's what
the security reduction (next document) addresses: proving that no shortcut through
the structure exists.

### Composability requirement

All six dimensions must map **fixed-size blocks to fixed-size blocks**. We
standardize on a block size B (e.g., 256 bits = 32 bytes). Each dimension:

```
Transform_i : {0,1}^B → {0,1}^B
```

This ensures any dimension can follow any other dimension without size mismatches.

### Interaction safety (the hard question)

The critical open question from the foundation document: **do these dimensions
interact safely?**

Potential risks:
1. **Algebraic cancellation:** Could Dimension 5 (EC) undo part of what
   Dimension 2 (lattice) did, creating a shortcut?
2. **Structure leakage:** Could the output of Dimension 3 (permutation) reveal
   structural information that helps attack Dimension 6 (polynomial)?
3. **Differential propagation:** Could carefully chosen plaintexts produce
   differences that survive specific dimension combinations predictably?

**Mitigation strategy:** The hash dimension (Dimension 4) acts as an
"algebraic firewall." By placing a hash-derived layer between algebraic layers,
we destroy any algebraic relationship between adjacent layers' inputs and outputs.

**Recommended minimum composition rule:**
> Never place two algebraic dimensions (1, 2, 3, 5, 6) adjacent without a
> hash dimension (4) between them.

This is conservative — it may be overly cautious — but it's the safe starting
point. Relaxing this rule requires proving specific pairwise composition safety.

---

## Summary Table

| Dim | Name | Math Family | Key Feature | Post-Quantum | Years Studied |
|---|---|---|---|---|---|
| 1 | SPN | Finite fields GF(2^8) | Nonlinear substitution + permutation | Yes | 75+ |
| 2 | Lattice | Integer lattices ℤⁿ | Noisy linear algebra | Yes (NIST standard) | 30+ |
| 3 | Permutation | Symmetric group Sₙ | Non-abelian composition | Yes | 170+ / 25+ |
| 4 | Hash-XOR | PRF/hash families | Algebraic firewall | Yes | 45+ |
| 5 | Elliptic Curve | EC over finite fields | Curved geometry DLP | Partial* | 40+ |
| 6 | Multivariate | Polynomial systems GF(q) | NP-hard MQ problem | Yes | 35+ |

*EC is vulnerable to Shor — mitigated by layering with quantum-resistant dimensions,
or by substituting CSIDH-family isogeny operations.

---

## Next Document: 02-expander-graph-construction.md

With the transforms defined, the next step is to formally construct the expander
graph where:
- Nodes = data states ({0,1}^B)
- Edges = applying one dimension's transform with specific parameters
- Graph family = must be proven to have good spectral expansion

This is where the security reduction will live.
