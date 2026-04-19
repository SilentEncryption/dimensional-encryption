# LinkedIn Post — Dimensional Encryption Release

## The post

```
Today I'm releasing Dimensional Encryption — a symmetric block cipher
I've been working on under SilentBot.

Every current encryption standard has a single point of failure. If
someone breaks AES, everything encrypted with AES is exposed. Same
for ChaCha20, same for CRYSTALS-Kyber. These ciphers are secure, but
a single mathematical breakthrough invalidates everything built on
them.

Dimensional Encryption takes a different approach: each layer uses a
different branch of mathematics — finite fields, lattices, permutation
groups, hash functions, elliptic curves, multivariate polynomials —
with hash layers acting as "firewalls" between them.

The formal result I am most proud of: the scheme remains secure even
if a majority of its constituent families are completely broken. As
long as one algebraic family and one adjacent hash layer survive,
your data stays protected.

All the math reduces to standard cryptographic assumptions (no new
hardness problems). The scheme is a research preview — not yet
reviewed by the wider community, not ready for production use — but
the paper, reference implementations (Python and C), and 29 test
vectors are now public:

https://github.com/SilentEncryption/dimensional-encryption

If you work in cryptography, I'd welcome your scrutiny. If you find
an attack, please tell me. Breaking it is how we learn whether it
holds.

#cryptography #informationsecurity #cybersecurity #research
```

## Alternative shorter version (if you want something more casual)

```
After months of work, I'm sharing something I've been building at
SilentBot: Dimensional Encryption, a cipher that is still secure
even if a majority of its building blocks are completely broken.

Every current encryption standard rests on one mathematical
assumption. If that assumption falls, so does the cipher. Dimensional
Encryption rests on six independent families — and the formal proof
shows it survives as long as any single family plus a hash layer
holds.

Paper, code, test vectors, and the proofs are at:
https://github.com/SilentEncryption/dimensional-encryption

Research preview — not yet reviewed, not production-ready. But
open for anyone who wants to try to break it.

#cryptography #cybersecurity
```

## Tips

- **Post from your personal account, not OpusLogic's.** This is
  SilentBot/Ali's research.
- **Time it for Tuesday-Thursday morning CET.** Best LinkedIn reach.
- **First comment from your own account** can add context: "Happy to
  answer questions — the paper link goes straight to the PDF in the
  repository."
- **Don't boost or pay to promote.** Let it stand on its own.
- **If someone skeptical comments, don't get defensive.** A short,
  calm reply ("Fair point — that's addressed in Section 3 of the
  paper if you want to look") beats an argument every time.
- **Turn off LinkedIn's "attach a PDF" feature** and just share the
  GitHub link. You want traffic to the repo, not to LinkedIn's own
  document viewer.

## What NOT to include

- No mention of the ePrint rejection. It's not relevant and just
  invites speculation.
- No claim that this replaces AES or any existing standard.
- No performance comparison bragging (we are 2.5x slower than
  software AES; that's not a headline).
- No venture-capital language ("revolutionary", "game-changing",
  "disruptive"). Cryptographers hate that.

## What signals you want to send

- Technical depth (link to GitHub + paper, not a marketing page)
- Honesty about status (research preview, not yet audited)
- Invitation to scrutiny (you want to be attacked)
- Specificity (the fault tolerance property is concrete)
- Humility (you are not claiming to have solved cryptography — you
  are claiming to have built something worth looking at)

That posture is what gets cryptographers to take you seriously.
Arrogance gets you ignored.
