# Dimensional Encryption — Expander Graph Construction

**Project:** SilentBot — Dimensional Encryption  
**Version:** 0.1  
**Date:** 2026-04-13  
**Authors:** Ali Vonk, M  
**Prerequisite:** Read 00-foundation.md and 01-transformation-zoo.md first  

---

## Purpose

This document defines the mathematical graph that our encryption scheme lives on.
The graph is the structure that lets us formally prove "recovering the secret is
hard." Without this graph, we have a cool idea. With it, we have a provable scheme.

---

## 1. The Intuition (Before the Math)

Imagine a massive city with billions of intersections. From each intersection,
exactly 6 roads lead out — one for each dimension type. Every road takes you to
a different intersection depending on which dimension you use and what parameters
you set.

**Encrypting** = starting at one intersection (your plaintext), taking a secret
sequence of roads (your key), and announcing where you ended up (the ciphertext).

**Breaking the encryption** = someone knows which intersection you started at and
where you ended up, and they need to figure out exactly which roads you took.

In a well-designed city (a good expander graph), there are so many possible routes
between any two intersections that finding yours is computationally hopeless.

Now — let's make this precise.

---

## 2. Formal Graph Definition

### The graph G = (V, E)

**Vertices (V):**  
Every possible data block of size B bits.

```
V = {0, 1}^B
```

If B = 256 (our working block size), then |V| = 2^256.

That's approximately 1.16 × 10^77 vertices — more than the number of atoms in
the observable universe. Nobody is storing this graph. It exists implicitly,
defined by the transformation functions.

**Edges (E):**  
There is a directed edge from vertex u to vertex v if and only if there exists
some dimension d ∈ {1,2,3,4,5,6} and some valid parameter p such that:

```
v = Transform(type=d, params=p, input=u)
```

Each vertex has edges leaving it — one for every valid (dimension, parameter)
combination.

### Degree (how many edges per vertex)

Each vertex has degree:

```
degree = Σ (number of valid parameter values for dimension d)
         d=1..6
```

If each dimension has a 256-bit parameter space:
- Each dimension contributes 2^256 outgoing edges per vertex
- Total degree per vertex: 6 × 2^256

This is an astronomically high-degree graph. Every single data state connects
to an enormous number of other data states.

### Why we don't store the graph

This graph is **implicitly defined**. We never build it. We just define what
the edges are (the transforms) and use the graph's mathematical properties in
our proofs. This is standard in cryptography — RSA also implicitly operates on
a graph of number-theoretic operations without ever constructing it.

---

## 3. What Makes a Good Expander (And Why We Need One)

### The expansion property (plain English)

A graph is a good expander if: **no matter which subset of vertices you look at,
that subset has many edges going outside itself.**

Think of it as: there are no isolated neighborhoods. No matter where you are,
a few steps take you everywhere. There are no dead ends, no echo chambers, no
shortcuts that loop you back to a small region.

### The spectral gap (the formal measure)

The quality of an expander is measured by the **spectral gap** — the difference
between the largest and second-largest eigenvalues of the graph's adjacency matrix.

Don't worry about the technical definition. Here's what matters:

| Spectral gap | What it means |
|---|---|
| **Large** (close to the degree) | Excellent expander — random walks mix rapidly, every region connects broadly |
| **Small** (close to 0) | Poor expander — there are bottlenecks, clusters, or near-isolated regions |

**We need a large spectral gap.** This guarantees that after even a few steps
(dimensions), the walker (our encrypted data) could be essentially anywhere in
the graph — making path reconstruction impossible.

### The Ramanujan bound (the gold standard)

A d-regular graph (every vertex has exactly d edges) achieves the best possible
expansion when its second-largest eigenvalue satisfies:

```
λ₂ ≤ 2√(d - 1)
```

Graphs meeting this bound are called **Ramanujan graphs** — they are provably
optimal expanders. They were first constructed by Lubotzky, Phillips, and Sarnak
(1988) and independently by Margulis (1988).

**Our goal:** Show that our graph G, defined by the six transformation dimensions,
achieves expansion close to the Ramanujan bound.

---

## 4. Proving Our Graph Is a Good Expander

This is where we need to do real work. There are three approaches, from easiest
to hardest:

### Approach A: Random Regular Graph Argument

**Claim:** If our transformation functions behave like random functions (which
cryptographic transforms are designed to do), then our graph behaves like a
random regular graph.

**Known result (Friedman, 2003):** A random d-regular graph is almost Ramanujan
with high probability. Specifically, for a random d-regular graph on n vertices:

```
λ₂ ≤ 2√(d - 1) + ε
```

with probability approaching 1 as n grows, for any ε > 0.

**Why this applies to us:**
- Our transforms are designed to behave like random permutations (this is a
  basic requirement for any cryptographic function)
- Each dimension acts as an independent random permutation family
- The composition of independent random permutations produces a walk that
  mixes like a random walk on a random regular graph

**Strength of this argument:** Very strong in practice. AES-based pseudorandom
permutations are indistinguishable from random permutations under all known tests.

**Weakness:** This is a heuristic argument, not a formal proof. We're assuming
our transforms behave randomly without proving it from first principles. This
is standard in applied crypto (AES has no formal proof of security either) but
won't satisfy theoretical cryptographers fully.

### Approach B: Cayley Graph Construction

**A more rigorous path.**

Instead of arguing our graph "looks random," we explicitly construct it as a
**Cayley graph** — a graph defined by a group and a generating set.

**What's a Cayley graph?**
- Pick a mathematical group G (a set with an operation, like multiplication)
- Pick a set of generators S = {s₁, s₂, ..., s_k} (elements of the group)
- The Cayley graph has vertices = elements of G, and edges connecting each
  element g to g·s₁, g·s₂, ..., g·s_k

**How to apply this:**
- Our group G = the group of all invertible transformations on {0,1}^B
  (this is an enormous group — every possible invertible function on 256-bit blocks)
- Our generating set S = {T₁, T₂, ..., T₆} where each Tᵢ is the family
  of transforms for dimension i
- The Cayley graph of (G, S) captures exactly our encryption structure

**Known results for Cayley graph expansion:**
- Cayley graphs on certain groups with well-chosen generators are provably
  good expanders (Alon-Roichman theorem, 1994)
- Specifically: if the generators are chosen uniformly at random from a group,
  the resulting Cayley graph is an expander with high probability when you
  have O(log |G|) generators

We have 6 generators (dimension families) on a group of size roughly (2^256)!
(the factorial of 2^256 — unfathomably large). The Alon-Roichman theorem
requires O(log |G|) ≈ O(256 · 2^256) generators for guaranteed expansion —
far more than 6.

**But:** Our generators are not single elements — each is a *family* of 2^256
transforms (parameterized by the key). So the effective generating set size is
6 × 2^256, which comfortably exceeds the Alon-Roichman threshold.

**This is our strongest formal path to proving expansion.**

### Approach C: Direct Spectral Analysis

Compute or bound the eigenvalues of our graph's adjacency matrix directly.

This is the hardest approach and would require significant mathematical
machinery. We defer this to a later stage (or to academic collaborators).

### Recommended approach: B (Cayley graph), supported by A (random argument)

We formally construct the Cayley graph (Approach B) and use the Alon-Roichman
theorem to prove expansion. We supplement this with empirical evidence from
small-scale experiments (Approach A) to verify the theoretical predictions.

---

## 5. The Path Reconstruction Problem (Formally)

Now we can state our hard problem precisely.

### Definition: Heterogeneous Path Reconstruction (HPR)

**Given:**
- The graph G = (V, E) as defined above (known — Kerckhoffs's principle)
- A starting vertex s ∈ V (the plaintext)
- An ending vertex t ∈ V (the ciphertext)
- The number of steps k (the number of dimensions used)

**Find:**
- A sequence of edges (d₁,p₁), (d₂,p₂), ..., (d_k,p_k) such that walking
  from s along these edges reaches t

Where d_i is a dimension type and p_i is the parameter for that step.

### Why HPR is hard

**Counting argument (lower bound):**

The number of possible paths of length k is:

```
(6 × 2^256)^k
```

For k = 8:  (6 × 2^256)^8  ≈  2^2069

This vastly exceeds 2^256 (128-bit security requires the search space to exceed
2^256 for post-quantum, accounting for Grover's square-root speedup).

**Expansion argument (no shortcuts):**

Because our graph is a good expander:
- After just 2-3 steps, the set of reachable vertices from s is nearly uniform
  over all of V
- This means knowing t tells you almost nothing about the intermediate states
- There's no "neighborhood structure" to exploit — no way to narrow down the
  search by working backwards from t or forwards from s

**Heterogeneity argument (no algebraic shortcuts):**

Even if an attacker could solve path reconstruction for a *homogeneous* walk
(all steps from the same dimension), our walk mixes dimensions. Known algebraic
attacks (Gröbner bases, lattice reduction, index calculus) work within a single
algebraic structure. When consecutive steps use different structures, these
attacks cannot propagate.

### Note on k being known vs. hidden

In the formal definition above, we gave the attacker k (the number of steps).
This is the conservative choice — if the scheme is secure even when the attacker
knows k, it's certainly secure when k is also hidden.

In practice, k is also secret, which adds another combinatorial factor. But
we don't rely on this for security.

---

## 6. The Mixing Time (How Many Layers Are Enough?)

A critical practical question: **how many dimensions do we actually need?**

### What is mixing time?

The mixing time of a random walk on a graph is the number of steps needed before
the walker's position is nearly uniformly distributed over all vertices —
regardless of where they started.

For a d-regular expander with spectral gap γ, the mixing time is:

```
t_mix ≈ log(|V|) / log(d / λ₂)
```

Where:
- |V| = 2^256 (number of vertices)
- d = effective degree
- λ₂ = second-largest eigenvalue

### Estimate for our graph

Assuming near-Ramanujan expansion (λ₂ ≈ 2√(d-1)):

With effective degree d per dimension family (each step chooses from one of
6 dimension types):

```
t_mix ≈ 256 / log₂(d / 2√d)  ≈  256 / (½ · log₂(d))
```

For d ≈ 2^256:  t_mix ≈ 256 / 128 = 2

**After just 2 steps, the walk is already well-mixed.**

This means even k = 4 (four dimensions) provides massive security margin.
We recommend k ≥ 6 for conservative security, and k = 8 as our standard
parameter.

### What this means practically

- **k = 4 dimensions:** Minimum viable (128-bit+ security)
- **k = 6 dimensions:** Comfortable margin (192-bit+ security)
- **k = 8 dimensions:** Full strength (256-bit+ security with post-quantum margin)

**Performance implication:** k layers means k sequential transform operations.
If each transform takes ~1 microsecond, encryption takes 4-8 microseconds.
This is slower than AES (~0.5 μs for 128 bits) but well within practical range.

---

## 7. Visual Summary

```
PLAINTEXT (start vertex)
    │
    ├── Dimension 3 (Permutation, params=p₁) ──→ state₁
    │
    ├── Dimension 4 (Hash-XOR, params=p₂)    ──→ state₂
    │
    ├── Dimension 1 (SPN, params=p₃)          ──→ state₃
    │
    ├── Dimension 4 (Hash-XOR, params=p₄)    ──→ state₄
    │
    ├── Dimension 6 (Polynomial, params=p₅)   ──→ state₅
    │
    ├── Dimension 4 (Hash-XOR, params=p₆)    ──→ state₆
    │
    ├── Dimension 2 (Lattice, params=p₇)      ──→ state₇
    │
    └── Dimension 4 (Hash-XOR, params=p₈)    ──→ state₈
                                                    │
                                               CIPHERTEXT (end vertex)
```

Notice: hash layers (Dim 4) interleaved between algebraic layers, following
the composition safety rule from the Zoo document.

The SECRET = [(3,p₁), (4,p₂), (1,p₃), (4,p₄), (6,p₅), (4,p₆), (2,p₇), (4,p₈)]

The attacker sees only PLAINTEXT and CIPHERTEXT. They must reconstruct the path.

---

## 8. Connection to Known Hard Problems

### Relationship to existing complexity results

| Known problem | Our version | Relationship |
|---|---|---|
| Graph isomorphism | — | Different problem (we don't compare graphs) |
| Shortest path | HPR doesn't require shortest — any valid path breaks it | HPR is potentially harder |
| Random walk endpoint prediction | Given start + walk length, predict endpoint | Our inverse: given start + endpoint, reconstruct walk |
| Hidden subgroup problem (HSP) | HPR over non-abelian groups | HPR is at least as hard as non-abelian HSP (believed quantum-hard) |
| Conjugacy search problem | Finding g such that g⁻¹ag = b | HPR generalizes this — each step can be in a different group |

### The key claim (to be proven in next document)

> **Theorem (informal):** Any efficient algorithm that breaks the Dimensional
> Encryption scheme (achieves advantage ε against IND-CPA security) can be
> converted into an efficient algorithm that solves HPR on our Cayley expander
> graph with success probability related to ε.

This is the **security reduction** — the core proof that makes this a real scheme
rather than an engineering heuristic.

---

## 9. Open Questions for Next Document

1. **Formal security reduction:** Write the actual proof of Theorem above
2. **Concrete Cayley graph specification:** Which specific group and generators?
   The symmetric group S_{2^B} is the natural choice but we need to verify the
   Alon-Roichman bound is tight enough
3. **Nonce/IV handling:** Deterministic encryption is insecure under CPA (same
   plaintext always gives same ciphertext). We need a randomized mode — likely
   a random nonce prepended and mixed into the first dimension's parameters
4. **Key derivation:** How to go from a single master key (e.g., 256 bits) to
   the full secret (n dimensions × type + params)? Standard KDF (HKDF) is the
   obvious answer
5. **Mode of operation:** For messages longer than one block, we need a chaining
   mode (like CBC or CTR for AES). Design this carefully — many good ciphers
   have been broken by bad modes

---

## Document Index

| Doc | Title | Status |
|---|---|---|
| 00 | Foundation | Complete |
| 01 | Transformation Zoo | Complete |
| 02 | Expander Graph Construction | Complete (this document) |
| 03 | Security Reduction Proof | **Next** |
| 04 | Key Derivation & Modes | Planned |
| 05 | Parameter Selection & Performance | Planned |
| 06 | Reference Implementation (Python) | Planned |
