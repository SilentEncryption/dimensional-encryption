# Dimensional Encryption — Key Derivation & Modes of Operation

**Project:** SilentBot — Dimensional Encryption  
**Version:** 0.1  
**Date:** 2026-04-13  
**Authors:** Ali Vonk, M  
**Prerequisite:** Read documents 00-03 first  

---

## Purpose

Documents 00-03 defined the scheme and proved it secure for a single fixed-size
block. Real data isn't a single block. This document answers the two practical
questions that turn a block cipher into a usable encryption system:

1. **Key Derivation:** How does a user's single master key (e.g., 256 bits)
   expand into the full secret (dimension types + parameters for all k layers)?
2. **Mode of Operation:** How do we encrypt messages longer than one block?

Both of these have destroyed otherwise-good ciphers when done poorly. ECB mode
(the naive "encrypt each block independently") famously leaks patterns — the
encrypted Linux penguin that still looks like a penguin. We won't make that
mistake.

---

## Part 1: Key Derivation

### The Problem

Our scheme requires a structured secret:

```
secret = {
    n:      number of layers (e.g., 8)
    types:  [d₁, d₂, ..., d₈]     — which dimension each layer uses
    params: [p₁, p₂, ..., p₈]     — 256-bit parameter per layer
}
```

That's a lot of key material — dimension selections + 2048 bits of parameters.
But users need a single, memorizable (or storable) master key.

### The Solution: HKDF (HMAC-based Key Derivation Function)

HKDF is the industry standard for expanding a short key into multiple derived
keys. It's used in TLS 1.3, Signal Protocol, WireGuard, and virtually every
modern protocol. Defined in RFC 5869, built on HMAC, proven secure.

We use HKDF in two stages:

#### Stage 1: Extract

Takes the master key and an optional salt, produces a pseudorandom key (PRK):

```
PRK = HKDF-Extract(salt, master_key)
```

The salt can be empty for basic use, or set to an application-specific value
for domain separation (ensuring keys derived for different purposes don't
collide).

#### Stage 2: Expand

Derives all layer keys from the PRK:

```
dimension_types  = HKDF-Expand(PRK, info="DE-v1-types",  length=k)
layer_key_1      = HKDF-Expand(PRK, info="DE-v1-layer-1", length=32)
layer_key_2      = HKDF-Expand(PRK, info="DE-v1-layer-2", length=32)
...
layer_key_k      = HKDF-Expand(PRK, info="DE-v1-layer-k", length=32)
```

The `info` parameter is a unique string for each derivation, ensuring all
outputs are independent even though they come from the same PRK.

### Dimension Type Selection

The `dimension_types` output is k bytes. Each byte is mapped to a dimension:

```
For each byte b_i in dimension_types:
    if layer i is at an even position (0, 2, 4, 6):
        type_i = 4  (hash layer — enforcing the firewall rule)
    else:
        type_i = (b_i mod 5) + 1  (maps to dimensions 1, 2, 3, 5, or 6)
        if type_i >= 4: type_i += 1  (skip 4 — that's the hash dimension)
```

This enforces the composition safety rule from Theorem 3: hash layers are always
interleaved between algebraic layers.

**Example with k=8:**

```
Position:  0     1     2     3     4     5     6     7
Rule:      hash  alg   hash  alg   hash  alg   hash  alg
Type:      4     ?     4     ?     4     ?     4     ?

Where ? is derived from the master key — could be 1, 2, 3, 5, or 6.
```

The attacker knows the pattern (hash-alg-hash-alg-...) because that's part of
the public algorithm. But they don't know which algebraic dimension fills each
"alg" slot — that's derived from the key.

### Nonce Integration

For IND-CPA security, each encryption must be randomized. We mix a fresh
16-byte (128-bit) random nonce into the first layer's key:

```
effective_key_1 = HKDF-Expand(PRK, info="DE-v1-layer-1" || nonce, length=32)
```

The nonce is prepended to the ciphertext (it's public):

```
output = nonce || ciphertext
```

**Nonce uniqueness requirement:** The nonce MUST be unique for every encryption
under the same master key. Using a 128-bit random nonce, the probability of
collision is negligible for up to 2^64 encryptions (birthday bound). For
higher volumes, use a counter-based nonce.

### Complete Key Derivation Flow

```
┌──────────────┐
│  Master Key   │  (256 bits — user's secret)
│  (256 bits)   │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ HKDF-Extract │  salt = "DimensionalEncryption-v1"
└──────┬───────┘
       │
       ▼
┌──────────────┐
│     PRK      │  (256-bit pseudorandom key)
└──────┬───────┘
       │
       ├───────────────────────────────────────────────┐
       │                                               │
       ▼                                               ▼
┌──────────────────┐                    ┌─────────────────────────┐
│ Derive dim types │                    │ Derive layer keys       │
│ info="DE-v1-     │                    │ info="DE-v1-layer-{i}"  │
│       types"     │                    │ (one per layer, 32B)    │
└──────────────────┘                    └─────────────────────────┘
       │                                               │
       ▼                                               ▼
┌──────────────────┐                    ┌─────────────────────────┐
│ Apply firewall   │                    │ Mix nonce into key 1    │
│ rule: even=hash, │                    │ info="DE-v1-layer-1"    │
│ odd=derived      │                    │      || nonce           │
└──────────────────┘                    └─────────────────────────┘
       │                                               │
       └───────────────────┬───────────────────────────┘
                           │
                           ▼
                 ┌───────────────────┐
                 │   Full Secret S   │
                 │                   │
                 │ types: [4,d,4,d,  │
                 │        4,d,4,d]   │
                 │ keys:  [k₁...k₈] │
                 └───────────────────┘
```

### Security of Key Derivation

HKDF is proven secure (Krawczyk, 2010) under the assumption that HMAC is a
secure PRF. This is the same assumption underlying TLS 1.3, Signal, and
WireGuard. No new assumptions needed.

The derived layer keys are computationally independent — knowing one layer's key
gives no information about any other layer's key. This follows directly from the
PRF security of HKDF-Expand.

---

## Part 2: Modes of Operation

### The Problem

Our block cipher encrypts B-bit blocks (B=256, i.e., 32 bytes). Real messages
are larger. We need a way to encrypt arbitrary-length messages securely.

**The trap:** The naive approach (ECB — encrypt each block independently with the
same key) leaks patterns. Identical plaintext blocks produce identical ciphertext
blocks. This is catastrophically insecure.

### Our Mode: DE-CTR (Counter Mode for Dimensional Encryption)

We use counter mode (CTR) adapted for our scheme. CTR mode is:
- Proven IND-CPA secure if the block cipher is a secure PRP (which we proved)
- Parallelizable (blocks can be encrypted independently — good for performance)
- Does not require padding (handles arbitrary message lengths)
- Used by AES-GCM (the most widely deployed authenticated encryption mode)

#### How CTR mode works

Instead of encrypting the message directly, we encrypt a series of counter
values and XOR the results with the message:

```
For message M split into blocks M₁, M₂, ..., M_n:

    keystream_i = DE_Encrypt(key=S, plaintext=(nonce || counter_i))
    ciphertext_i = M_i ⊕ keystream_i
```

Where:
- `nonce` is a fresh 128-bit random value (same for all blocks in one message)
- `counter_i` is a 128-bit counter: 0, 1, 2, 3, ...
- `nonce || counter_i` is the 256-bit block input (128 + 128 = 256 = B)
- `⊕` is XOR

#### Why this is secure

The block cipher (our DE scheme) is a secure PRP. In CTR mode, it's applied to
distinct inputs (nonce || 0, nonce || 1, nonce || 2, ...). Since the inputs are
all different, the outputs are pseudorandom and independent. XORing pseudorandom
data with the message produces a secure ciphertext.

**Formally:** If DE is a secure PRP, then DE-CTR is IND-CPA secure.  
(Standard result — Bellare et al., 1997.)

#### Complete encryption flow

```
ENCRYPT(master_key, plaintext):

1. Generate random nonce (16 bytes)
2. Derive full secret S from master_key (using HKDF, Section 1)
3. Split plaintext into 32-byte blocks: M₁, M₂, ..., M_n
   (last block may be partial — no padding needed)
4. For each block i = 1 to n:
     counter_input = nonce || i    (256-bit input block)
     keystream_i = DE(S, counter_input)
     C_i = M_i ⊕ keystream_i      (for partial last block, truncate keystream)
5. Output: nonce || C₁ || C₂ || ... || C_n
```

```
DECRYPT(master_key, ciphertext_with_nonce):

1. Extract nonce (first 16 bytes)
2. Derive full secret S from master_key (same HKDF, same nonce)
3. Split remaining ciphertext into 32-byte blocks: C₁, C₂, ..., C_n
4. For each block i = 1 to n:
     counter_input = nonce || i
     keystream_i = DE(S, counter_input)
     M_i = C_i ⊕ keystream_i
5. Output: M₁ || M₂ || ... || M_n
```

### Visual Example

Encrypting the message "Hello, this is a test of dimensional encryption!!"
(50 bytes = 2 blocks, last one partial):

```
plaintext (50 bytes):
  Block 1: "Hello, this is a test of dime" (32 bytes)
  Block 2: "nsional encryption!!"           (20 bytes)

nonce: 0xA3F7...29B1 (16 random bytes, generated fresh)

counter inputs (256-bit each):
  Input 1: A3F7...29B1 || 0000...0001
  Input 2: A3F7...29B1 || 0000...0002

Dimensional Encryption (8-layer cascade for each input):
  Input 1 → [Dim4→Dim2→Dim4→Dim6→Dim4→Dim1→Dim4→Dim3] → keystream_1 (32 bytes)
  Input 2 → [Dim4→Dim2→Dim4→Dim6→Dim4→Dim1→Dim4→Dim3] → keystream_2 (32 bytes)

XOR:
  C₁ = Block 1 ⊕ keystream_1                    (32 bytes)
  C₂ = Block 2 ⊕ keystream_2[:20]               (20 bytes, truncated)

output (82 bytes):
  nonce (16) || C₁ (32) || C₂ (20)
  overhead: 16 bytes (the nonce) — 32% for this short message, <1% for large files
```

---

## Part 3: Authenticated Encryption (Integrity Protection)

### Why encryption alone isn't enough

IND-CPA security guarantees confidentiality — the attacker can't learn the
plaintext. But it does NOT guarantee integrity — the attacker might modify the
ciphertext, and the recipient would decrypt it to a different (corrupted)
plaintext without knowing.

This is a real attack. In CTR mode, flipping a bit in the ciphertext flips
the corresponding bit in the plaintext. An attacker who knows (or guesses)
the plaintext structure can make targeted modifications.

### Solution: Encrypt-then-MAC (DE-CTR-HMAC)

We add an authentication tag — a cryptographic checksum that verifies the
ciphertext hasn't been tampered with.

```
AUTHENTICATED ENCRYPT(master_key, plaintext):

1. ciphertext = DE-CTR-ENCRYPT(master_key, plaintext)
   (as defined above — includes nonce)

2. mac_key = HKDF-Expand(PRK, info="DE-v1-mac", length=32)
   (derived from same master key, but independent of encryption keys)

3. tag = HMAC-SHA256(mac_key, ciphertext)
   (computed over the ENTIRE ciphertext including nonce)

4. Output: ciphertext || tag  (tag is 32 bytes)
```

```
AUTHENTICATED DECRYPT(master_key, data):

1. Split: ciphertext = data[:-32], tag = data[-32:]

2. mac_key = HKDF-Expand(PRK, info="DE-v1-mac", length=32)

3. expected_tag = HMAC-SHA256(mac_key, ciphertext)

4. IF tag ≠ expected_tag:
     REJECT — data has been tampered with (return error, not decrypted data)

5. plaintext = DE-CTR-DECRYPT(master_key, ciphertext)

6. Output: plaintext
```

**Critical:** Always verify the tag BEFORE decrypting. Never return partially
decrypted data. The comparison must be constant-time (to prevent timing attacks).

### Why Encrypt-then-MAC (not MAC-then-Encrypt)

Three composition orders exist. Only one is universally safe:

| Order | Security | Used by |
|---|---|---|
| **Encrypt-then-MAC** | Always secure (proven) | IPsec ESP, our scheme |
| MAC-then-Encrypt | Sometimes insecure (padding oracle attacks) | TLS < 1.3 (broken) |
| Encrypt-and-MAC | Sometimes insecure | SSH (partial weakness) |

Encrypt-then-MAC is proven secure by Bellare & Namprempre (2000). We use it.

### Security of the authenticated scheme

The authenticated scheme (DE-CTR-HMAC) provides:

- **IND-CPA security** — from DE-CTR mode (Theorem 1 + standard CTR proof)
- **INT-CTXT security** (ciphertext integrity) — from HMAC-SHA256
  (an attacker cannot forge a valid ciphertext-tag pair)
- Combined: **IND-CCA2 security** (the strongest standard notion — secure even
  if the attacker can ask for decryptions of other ciphertexts)

This follows from the generic composition theorem of Bellare & Namprempre:
Encrypt-then-MAC achieves IND-CCA2 if the encryption is IND-CPA and the MAC
is strongly unforgeable.

```
┌─────────────────────────────────────────────────────────┐
│                                                         │
│  DE-CTR-HMAC achieves IND-CCA2 security:                │
│                                                         │
│  - Confidentiality: IND-CPA from Theorem 1 + CTR mode  │
│  - Integrity: INT-CTXT from HMAC-SHA256                 │
│  - Combined: IND-CCA2 (strongest standard notion)       │
│                                                         │
│  Assumptions: same as Theorem 1 + HMAC is a secure MAC  │
│  New assumptions: NONE                                  │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Part 4: Wire Format

The complete encrypted message format:

```
┌────────┬──────────────────────────────┬──────────┐
│ Header │ Encrypted Data               │ Auth Tag │
│ (25 B) │ (same length as plaintext)   │ (32 B)   │
└────────┴──────────────────────────────┴──────────┘

Header (25 bytes):
  ┌─────────┬─────────┬─────────┬──────────────────┐
  │ Magic   │ Version │ Params  │ Nonce            │
  │ (4 B)   │ (1 B)   │ (4 B)   │ (16 B)           │
  └─────────┴─────────┴─────────┴──────────────────┘

  Magic:    0x44 0x45 0x4E 0x43  ("DENC" — Dimensional ENCryption)
  Version:  0x01  (scheme version — allows future upgrades)
  Params:   4-byte encoding of:
            - k (number of layers): 1 byte
            - B (block size in bytes): 1 byte (32 = 256 bits)
            - reserved: 2 bytes (0x0000)
  Nonce:    16 random bytes (unique per encryption)

Auth Tag (32 bytes):
  HMAC-SHA256 over (Header || Encrypted Data)
```

**Total overhead:** 57 bytes (25 header + 32 tag) regardless of message size.

- For a 1 KB message: 5.6% overhead
- For a 1 MB message: 0.005% overhead
- For a 1 GB message: negligible

### Why the header is authenticated

The HMAC covers the header too — not just the encrypted data. This prevents an
attacker from modifying the version or parameter fields to trick the decryptor
into using weaker settings.

### Version field for agility

If a dimension is broken in the future (e.g., quantum computers break EC),
we increment the version and the new version excludes that dimension. Old
ciphertexts remain labeled with their version, so the decryptor knows which
parameter set to use.

---

## Part 5: Symmetric Key Exchange (Sharing the Master Key)

Everything above is **symmetric encryption** — both parties need the same master
key. How do they agree on one?

### Option A: Pre-shared key

Both parties exchange the 256-bit master key through a secure channel (in person,
via a separate encrypted channel, etc.). Simple, common, and appropriate for
many use cases (disk encryption, database encryption, file encryption).

### Option B: Key agreement using existing protocols

Use an established key exchange (ECDH, Kyber KEM, or a hybrid) to derive a
shared secret, then use that as the master key for Dimensional Encryption.

```
Alice                              Bob
  │                                  │
  ├─── Kyber KEM encapsulate ──────→ │
  │                                  │
  │ ←── Kyber KEM decapsulate ────── │
  │                                  │
  │    shared_secret (256 bits)      │
  │         = master_key             │
  │                                  │
  ├─── DE-CTR-HMAC(master_key, msg)→ │
  │                                  │
```

This is the pragmatic approach: use Kyber (NIST standard) for key exchange,
Dimensional Encryption for bulk data encryption.

### Option C: Native key exchange (future work)

Building a Diffie-Hellman-like key exchange natively from our dimensional
primitives would be elegant but is non-trivial. The standard DH construction
requires a commutative operation: Alice applies her secret, Bob applies his,
and they arrive at the same result regardless of order. Our heterogeneous
transforms are explicitly non-commutative.

Possible approaches:
- Commutative subsets of our dimension families
- A protocol where order is agreed upon in advance
- Isogeny-based constructions adapted to our framework

This is deferred to a future document. For now, Options A and B cover all
practical use cases.

---

## Part 6: Summary of Decisions

| Decision | Choice | Why |
|---|---|---|
| Key derivation | HKDF (RFC 5869) | Industry standard, proven secure, used by TLS/Signal/WireGuard |
| Dimension type selection | Deterministic from key, interleaved with hash | Enforces Theorem 3 firewall rule automatically |
| Randomization | 128-bit random nonce per encryption | Standard approach, safe for 2^64 encryptions |
| Encryption mode | CTR (counter mode) | Proven secure, parallelizable, no padding needed |
| Authentication | Encrypt-then-MAC with HMAC-SHA256 | Proven IND-CCA2, universally safe composition |
| Wire format | Header + ciphertext + tag | 57 bytes overhead, version-agile, fully authenticated |
| Key exchange | External (pre-shared or Kyber KEM) | Pragmatic — use established protocols |

---

## Part 7: Security Properties of the Complete System

The full system (DE-CTR-HMAC with HKDF key derivation) provides:

| Property | Guaranteed? | Basis |
|---|---|---|
| **Confidentiality** (can't read the data) | Yes | Theorem 1 + CTR mode proof |
| **Integrity** (can't modify undetected) | Yes | HMAC-SHA256 + Encrypt-then-MAC |
| **Authenticity** (came from key holder) | Yes | HMAC verifies sender knows key |
| **Ciphertext indistinguishability** | Yes | IND-CCA2 (strongest notion) |
| **Fault tolerance** | Yes | Theorem 2 — survives partial breaks |
| **Post-quantum confidentiality** | Yes | Grover halving compensated by parameters |
| **Post-quantum integrity** | Yes | HMAC-SHA256 is quantum-resistant |
| **Forward secrecy** | No* | Requires key exchange protocol support |
| **Resistance to key compromise** | Partial | If master key leaks, all messages are exposed |

*Forward secrecy can be achieved by combining with an ephemeral key exchange
(Option B with ephemeral Kyber keys). This is a protocol-level decision, not a
cipher-level one.

---

## Document Index (Updated)

| Doc | Title | Status |
|---|---|---|
| 00 | Foundation | Complete |
| 01 | Transformation Zoo | Complete |
| 02 | Expander Graph Construction | Complete |
| 03 | Security Reduction Proof | Complete v0.2 |
| 04 | Key Derivation & Modes of Operation | Complete (this document) |
| 05 | Parameter Selection & Performance | **Next** |
| 06 | Reference Implementation (Python) | Planned |
| 07 | Test Vectors & Validation | Planned |
