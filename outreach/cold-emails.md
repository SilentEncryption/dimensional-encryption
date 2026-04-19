# Cold Emails — Academic Outreach

**Purpose:** Get 1-2 qualified cryptographers to glance at the paper and
either (a) point to prior work we missed, or (b) confirm the construction
is in open territory.

**Principle:** Ask a specific question. Don't ask for validation. Give
them an easy escape if they don't want to engage.

---

## Before sending — verification checklist

- [ ] Confirm the researcher is still at the listed institution
      (check their university page)
- [ ] Confirm the email address on their official page
- [ ] Read one of their recent papers so you can mention it if the
      conversation continues
- [ ] Send one at a time, spaced a few days apart — not a mass blast
- [ ] Use BCC if you ever send to multiple people (never reveal the list)

---

## Target 1: Bart Mennink (Maastricht University)

**Why him:** Modern symmetric cryptography, authenticated encryption,
composition security — our exact topic. He publishes on cascade-style
constructions and has a reputation for being approachable.

**Verify email address** on https://www.maastrichtuniversity.nl or his
personal page (https://www.cs.ru.nl/~bmennink/ may still redirect). Likely
format is `b.mennink@maastrichtuniversity.nl` — CONFIRM before sending.

```
Subject: Heterogeneous-family cascade cipher — is this construction known?

Dear Dr. Mennink,

I am a cybersecurity practitioner of 25 years who, in trying to
think seriously about the fragility of single-primitive encryption,
ended up drafting a construction and would like to ask whether it
is already in the literature.

I have been working on a symmetric block cipher that composes
transformations from independent algebraic families (SPN,
lattice, permutation group, hash-Feistel, multivariate) with hash
layers acting as "firewalls" between algebraic layers. The main
property I would like to highlight is that the scheme retains
IND-CPA security even if a majority of its constituent families
are completely broken — reducing to the PRP security of any single
surviving algebraic-plus-hash pair.

My question is whether this construction or a close variant is
already in the literature. I have searched cascade cipher and
superencryption work (Even-Goldreich 1985, Maurer-Massey 1993,
Bellare-Rogaway 2006) and have not found this specific framing,
but I may well be missing something.

The paper, reference implementation, and test vectors are at:
https://github.com/SilentEncryption/dimensional-encryption

Any pointers to prior work or related constructions would be
appreciated.

Kind regards,
Ali Vonk
SilentBot, Netherlands
(Founder of OpusLogic, a network automation and compliance platform)
```

---

## Target 2: Joan Daemen (Radboud University, Nijmegen)

**Why him:** Co-designer of AES. Deeply familiar with SPN construction.
Respected and senior — unlikely to give a full review but a one-line
reply from him would be gold.

**Likely email:** `joan@cs.ru.nl` (verify on ru.nl)

**Note:** He gets a lot of email. Keep this shorter and more specific.

```
Subject: Fault-tolerant cascade cipher with heterogeneous algebraic layers

Dear Prof. Daemen,

I am a cybersecurity practitioner of 25 years. In trying to think
seriously about the fragility of single-primitive encryption, I
drafted a symmetric cipher that composes one SPN layer with
layers from independent algebraic families (lattice, permutation
group, hash-Feistel, multivariate), separated by hash-layer
firewalls. The intended property is fault tolerance: IND-CPA
security survives even if a majority of the individual families
are broken.

I would value any thoughts on whether this general approach has
been examined before, and whether the hash-firewall argument is
sound. The paper is short — 10 pages — at:
https://github.com/SilentEncryption/dimensional-encryption

Thank you for your time.

Kind regards,
Ali Vonk
SilentBot, Netherlands
(Founder of OpusLogic, a network automation and compliance platform)
```

---

## Target 3: Tanja Lange (TU Eindhoven)

**Why her:** Cryptanalysis background, post-quantum symmetric work,
historically active with Dutch-based research and approachable to
outside contributors.

**Likely email:** `tanja@hyperelliptic.org` or `t.lange@tue.nl`
(she uses the hyperelliptic.org address in practice — verify)

```
Subject: Heterogeneous cascade cipher — seeking prior-work pointers

Dear Prof. Lange,

I am a cybersecurity practitioner of 25 years. Working on the
fragility of single-primitive encryption, I ended up drafting a
symmetric cipher that composes layers from distinct algebraic
families (SPN, lattice, permutation group, hash-Feistel,
multivariate), with hash layers interleaved as structural firewalls
between algebraic layers. The central claim is that the scheme
remains IND-CPA secure even when a majority of its constituent
families are completely broken — security reduces to the PRP
property of any single surviving algebraic-plus-hash pair.

I have searched the cascade cipher literature (Even-Goldreich 1985,
Maurer-Massey 1993, Bellare-Rogaway 2006) but have not found this
specific framing. I would be grateful for any pointers to related
work I may have missed.

Paper, reference implementation (Python and C), and 29 test vectors:
https://github.com/SilentEncryption/dimensional-encryption

Kind regards,
Ali Vonk
SilentBot, Netherlands
(Founder of OpusLogic, a network automation and compliance platform)
```

---

## Target 4: Marc Stevens (CWI Amsterdam)

**Why him:** Practical cryptanalysis expert (SHA-1 collision work).
Less focused on composition but has broad view of symmetric primitives.

**Likely email:** `marc.stevens@cwi.nl` (verify on cwi.nl)

```
Subject: Heterogeneous-family cascade cipher — is this in the literature?

Dear Dr. Stevens,

I am a cybersecurity practitioner of 25 years. I have written up a
symmetric cipher construction that composes transformations from
independent algebraic families, separated by hash layers that act
as algebraic firewalls. The claim is that the scheme remains secure
even if a majority of its constituent families are completely
broken — security reduces to the PRP security of any single
surviving algebraic-plus-hash pair, via a standard hybrid argument.

My question: is this construction or a close variant already known?
I have gone through the cascade cipher literature (Even-Goldreich,
Maurer-Massey, Bellare-Rogaway) and have not found this specific
framing, but may be missing something.

Paper and code: https://github.com/SilentEncryption/dimensional-encryption

Any pointers would be appreciated.

Kind regards,
Ali Vonk
SilentBot, Netherlands
(Founder of OpusLogic, a network automation and compliance platform)
```

---

## Sending strategy

1. Send **one** email first — I would pick Bart Mennink. Wait 10-14 days.
2. If no reply, send to Tanja Lange. Wait 10-14 days.
3. Then Joan Daemen. Wait 10-14 days.
4. Then Marc Stevens.

Spacing matters. If you send all four at once and one responds with a
problem, it looks less coordinated if the others haven't already landed
in inboxes. More importantly, replies from one person might inform how
you frame the next.

**Do not follow up** for at least 3 weeks. Academics are slow. Following
up too early looks pushy.

**If someone replies:**
- Short, concrete reply
- Don't over-explain
- Answer their question, offer to discuss further if they want
- Don't ask them to endorse, review, or co-author — let them drive

**If the reply is negative** (e.g., "this is already known as X"):
- Say thank you sincerely
- Read whatever they pointed you to
- Update the paper/docs to cite it and reposition the contribution
- This is valuable feedback even when it hurts

**If no one replies:**
- That's fine. Silence doesn't mean the work is bad.
- The GitHub repo is the permanent timestamp regardless.
- Move on to other work (password vault product, OpusLogic compliance,
  whatever SilentBot decides to do with the scheme).
