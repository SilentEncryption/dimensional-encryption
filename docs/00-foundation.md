# Dimensional Encryption — Foundation Document

**Project:** SilentBot — Dimensional Encryption  
**Version:** 0.1 (Foundation)  
**Date:** 2026-04-13  
**Authors:** Ali Vonk, M  

---

## 1. What This Scheme Does

### In Plain English

Dimensional encryption transforms plaintext into ciphertext by pushing it through
a series of independent transformation layers. Each layer operates in a different
mathematical "dimension" — meaning it uses a different type of operation.

The secret is not a single key value. The secret is:
- **How many layers** were applied (the attacker doesn't know)
- **What type** each layer is (the attacker doesn't know)
- **What parameters** each layer used (the attacker doesn't know)

This is like a combination lock, except the attacker doesn't know how many dials
exist, doesn't know if each dial is numbers, letters, or colors, and doesn't know
the sequence in which they were set.

### Formally

```
Encrypt(plaintext, secret) → ciphertext
Decrypt(ciphertext, secret) → plaintext
```

Where `secret` is a structured object:

```
secret = {
    n:          number of dimensions (hidden)
    types:      [t₁, t₂, ..., tₙ]     — what kind of transformation each layer uses
    params:     [p₁, p₂, ..., pₙ]     — the parameters (keys) for each layer
}
```

Encryption applies each layer in sequence:

```
state₀ = plaintext
state₁ = Transform(type=t₁, params=p₁, input=state₀)
state₂ = Transform(type=t₂, params=p₂, input=state₁)
...
stateₙ = Transform(type=tₙ, params=pₙ, input=stateₙ₋₁)
ciphertext = stateₙ
```

Decryption applies the inverse of each layer in reverse order:

```
stateₙ = ciphertext
stateₙ₋₁ = InverseTransform(type=tₙ, params=pₙ, input=stateₙ)
...
state₀ = InverseTransform(type=t₁, params=p₁, input=state₁)
plaintext = state₀
```

**Critical requirement:** Every Transform must be invertible given knowledge of
(type, params). Without that knowledge, it must be a one-way function.

---

## 2. The Attacker Model

### What the attacker KNOWS

- The general scheme design (Kerckhoffs's principle — the algorithm is public)
- The set of possible transformation types (the "menu" of available dimensions)
- Arbitrary plaintext-ciphertext pairs (chosen-plaintext attack model, CPA)
- The ciphertext they want to decrypt

### What the attacker DOES NOT KNOW

- How many dimensions (n) were used
- Which types were selected and in what order
- The parameters for each layer

### What the attacker is trying to do

Given a ciphertext C and knowledge of the scheme, recover the plaintext P.

Equivalently: reconstruct *any valid secret* that maps C back to P. They don't
need to find *your* secret — any secret that works is a break.

### Security goal

The scheme is secure if no efficient algorithm (classical or quantum) can
distinguish the output of Encrypt from random data, even given chosen plaintexts.

This is called **IND-CPA security** (indistinguishability under chosen-plaintext
attack) — the standard minimum bar for any serious encryption scheme.

---

## 3. Why We Believe This Is Hard

### The Core Hard Problem: Path Reconstruction on Expander Graphs

We anchor security to a well-studied problem from graph theory and theoretical
computer science.

#### What is an expander graph?

Think of a network of cities connected by roads. An **expander graph** is a
network where:
- Every city has roughly the same number of roads (it's "regular")
- There are no bottlenecks — you can't split the cities into two groups with
  only a few roads between them
- From any city, a short random walk will take you to essentially any other
  city with near-equal probability

These graphs are extremely well-connected. They're used in network design,
error-correcting codes, and cryptography precisely because of this property.

**Key intuition:** If you take a random walk of k steps on a good expander graph,
and I tell you only where you ended up — reconstructing which path you took is
computationally infeasible. There are exponentially many paths that could have
led to that endpoint.

#### How this maps to our scheme

| Graph concept | Encryption concept |
|---|---|
| Node (city) | A data state (intermediate encryption result) |
| Edge (road) | One transformation layer applied |
| Walk of k steps | Applying k transformation layers in sequence |
| Starting node | Plaintext |
| Ending node | Ciphertext |
| The specific path taken | The secret |

The attacker sees the start (plaintext) and the end (ciphertext). They need
to find the path. On a good expander graph, this is exponentially hard in k
(the number of steps / dimensions).

#### Why this is better than previous approaches

| Failed scheme | Why it broke | Why we're different |
|---|---|---|
| Braid groups | The group had too much exploitable structure (normal forms) | We use heterogeneous transforms — no single algebraic structure to attack |
| Chaotic maps | Statistical patterns leaked through the chaos | Expander graphs have provably uniform mixing — no statistical shortcuts |
| SIKE (isogenies) | Auxiliary torsion points leaked path information | We don't publish any auxiliary information — only start and end |
| Matrix groups | Linear algebra gives efficient shortcuts | Our dimensions are non-linear and heterogeneous |

#### The heterogeneous advantage (our unique contribution)

Standard expander graph walks use the **same type** of step at each hop. Our
scheme uses **different types** of steps — some might be based on elliptic curves,
some on lattices, some on permutation groups, some on hash functions.

This means the attacker can't exploit the structure of any single algebraic
system. They face a *hybrid* hard problem: reconstruct a path where each step
lives in a different mathematical universe.

No existing attack methodology handles this. Algebraic attacks need a single
consistent structure. Statistical attacks need repeated identical operations.
We give them neither.

---

## 4. What We Need to Prove (The Roadmap)

Before this is more than a promising idea, we need formal proofs of four things:

### Proof 1: Correctness
> Decrypt(Encrypt(P, S), S) = P for all plaintexts P and valid secrets S.

This is the easiest — it follows directly from each Transform being invertible.

### Proof 2: Security Reduction
> Breaking the scheme is **at least as hard as** the path reconstruction problem
> on the specific expander graph family we choose.

This is the critical proof. It means: if someone breaks our scheme, they've also
solved a problem that the entire math/CS community believes is hard.

### Proof 3: Parameter Selection
> For concrete security level λ (e.g., 128-bit or 256-bit security), we need:
> - Minimum number of dimensions n
> - Minimum parameter sizes per dimension
> - Which specific transformation types to use

### Proof 4: Quantum Resistance
> The path reconstruction problem on our chosen expander family is not efficiently
> solvable by Grover's algorithm, Shor's algorithm, or known quantum walk algorithms.

For expander graphs, this is believed to hold — quantum walks give at most a
quadratic speedup (square root), which we compensate by doubling parameters.

---

## 5. Concrete Next Steps

### Step A: Define the Transformation Zoo
Pick 4-6 specific, well-studied invertible transformations from different algebraic
families. Each must be:
- Efficiently computable (encrypt/decrypt in polynomial time)
- Individually secure (each layer alone doesn't break)
- From a distinct mathematical family (heterogeneity is our strength)

### Step B: Construct the Expander Graph
Define the specific graph family where nodes are data states and edges correspond
to applying one transformation. Prove it's a good expander (spectral gap analysis).

### Step C: Write the Security Reduction
Show formally that CPA-breaking our scheme → solving path reconstruction on
our graph.

### Step D: Prototype
Implement a minimal version in Python to test correctness and measure performance.

---

## 6. Glossary

| Term | Meaning |
|---|---|
| **Plaintext** | The original data you want to protect |
| **Ciphertext** | The encrypted (unreadable) output |
| **CPA** | Chosen-Plaintext Attack — attacker can encrypt anything they want and study the results |
| **IND-CPA** | Indistinguishability under CPA — gold standard: attacker can't tell real ciphertext from random noise |
| **Expander graph** | A graph where information spreads rapidly and uniformly — no bottlenecks |
| **Spectral gap** | Mathematical measure of how "well-connected" a graph is (bigger = better expander) |
| **Security reduction** | A proof that "if you break X, you also break Y" — links our scheme to a known hard problem |
| **Post-quantum** | Secure even against a computer running quantum algorithms |
| **Kerckhoffs's principle** | The scheme must be secure even if the attacker knows everything except the key |
| **Heterogeneous** | Using different mathematical structures together (our key differentiator) |
| **Dimension** | One transformation layer in our scheme, operating with its own algebraic rules |

---

## Open Questions (To Resolve in Next Document)

1. **Composition safety:** Do heterogeneous transforms compose securely, or can
   interactions between different algebraic structures create weaknesses?
2. **Key size:** How large is the secret in practice? If n=8 dimensions with
   256-bit params each, that's 2048+ bits of key material — acceptable?
3. **Performance:** What's the encryption speed relative to AES? We need to be
   within 10-100x to be practical.
4. **Key exchange:** Can we build a Diffie-Hellman-like protocol for this, or
   is it symmetric-only?
5. **Specific graph family:** Cayley graphs? LPS Ramanujan graphs? Random regular?
