# Security and Cryptanalysis

This scheme is a research preview. We **want** you to find weaknesses.

## Reporting a cryptanalytic attack

If you have found a distinguisher, key recovery, or other attack against
Dimensional Encryption, please either:

1. Open a public issue on this repository describing the attack, or
2. Contact the author privately at `silentbot@icloud.com` if you prefer
   coordinated disclosure before going public.

Both are welcome. There is no bug bounty, but we will credit you
prominently in any revision of the paper or scheme.

## What counts as an attack

- A distinguisher that beats random guessing with non-negligible
  advantage, using fewer resources than brute force.
- A key recovery algorithm that succeeds with non-negligible probability
  using fewer queries or less time than brute force.
- A forgery attack against the authenticated mode (DE-CTR-HMAC).
- A practical side-channel attack against the reference or C
  implementation (timing, cache, power). These are implementation bugs,
  not scheme issues, but we want to fix them.

## Reduced-parameter challenge instances

If you want to try attacks on a concrete target before committing to
analysis of the full scheme, we can provide reduced-parameter instances
(smaller block size, fewer layers, weakened families). Open an issue
titled "Request: challenge instances" and we will generate some.

## What is NOT a security issue

- The Python reference implementation is not constant-time. Known and
  documented.
- The scheme uses HMAC-SHA-256 or BLAKE3 for the hash layer; if either
  is ever broken as a PRF, the scheme's fault tolerance kicks in, but
  we still want to know.
- Dimension 5 (EC analog) is individually vulnerable to Shor's
  algorithm. This is known and documented.
