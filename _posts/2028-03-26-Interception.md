---
layout: post
title: "Interception"
date: 2028-03-26 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, rsa, coppersmith, known-plaintext, carmichael, lattice]
description: "A single RSA channel where the modulus is never given, a greeting set of known plaintexts leaks it via GCD, a 'forgot key' feature hands out the top 643 bits of a prime for Coppersmith, and a supposedly astronomical N-iteration loop collapses to one modular exponentiation with Carmichael's theorem."
---

## Overview

Interception is a Medium crypto challenge that must be solved in a **single connection** — every connection generates a fresh RSA modulus `N`, and the oracle, the leaked token, and the encrypted plans are all tied to that `N`. The menu offers `[S]end`, `[R]eveal`, and `[F]orgot key`. Three sub-attacks chain together, and the flag hides inside the decrypted "internal plans".

## Step 1 — Recover the RSA modulus `N`

The banner and every successful `[S]` reply are RSA encryptions of **known** plaintexts — a fixed set of greetings/answers (three options each), `c = m^e mod N`, `e = 0x10001`. So `N | (m^e − c)`.

One greeting sample isn't enough for a GCD. But `[S]` decrypts your ciphertext and only succeeds if the result is valid UTF-8 — so **echo the greeting ciphertext back**: it round-trips to the greeting string and the server rewards you with a fresh answer ciphertext. Harvest a handful, then GCD the product over the candidate plaintexts (we don't know *which* of the three each ciphertext is):

```python
N = gcd_i( prod_{m in candidates}(m^e − c_i) )     # each product is a multiple of N
# strip small common factors
```

Use gmpy2 — the `m^e` values reach ~24 million bits, but it's still ~3 seconds.

## Step 2 — `[F]` leaks the top bits of `q`, then Coppersmith

`[F]` first makes you prove you know `N` (`sha256(str(N))` — which we now do) and returns a token:

```python
d = q.bit_length() - 643
token = ((q >> d) << d) | random.getrandbits(d)    # top 643 bits of q, low 381 randomized
```

That's the **top 643 of q's 1024 bits**. With well over half the bits known, [Coppersmith's method](https://en.wikipedia.org/wiki/Coppersmith_method) (Howgrave-Graham, an LLL lattice) recovers the remaining 381 and factors `N`. With no SageMath on hand, the lattice is built by hand and reduced with **fpylll**, and the short vector's integer root is extracted with **sympy** (`numpy.roots` overflows on the huge coefficients).

## Step 3 — the AES key without running the loop

The plans are AES-ECB encrypted under a key from a loop that *claims* to be astronomically expensive:

```python
ct = 0x1337
for _ in range(N):            # "runs in milliseconds on our super computer"
    ct = pow(ct, a, N)        # a = 0xdeadbeef
key = long_to_bytes(ct)[:16]
```

Iterating `x → x^a` exactly `N` times gives `ct = 0x1337^(a^N) mod N`. You never loop — you reduce the exponent with **Carmichael's theorem** (the flag's own punchline, *"we don't even need Euler"*):

```python
lam = lcm(p-1, q-1)
key = long_to_bytes(pow(0x1337, pow(0xdeadbeef, N, lam), N))[:16]
```

`[R]` with `key.hex()` makes the server decrypt its own plans; Plan 2 carries the flag `HTB{...}`.

## Why it worked

- **Textbook RSA over a known message set** leaks the modulus by GCD — always pad (OAEP) and randomize plaintexts.
- **Partial private-key disclosure**: revealing the top 643 bits of a prime is a full break, since anything past ~half the bits lets Coppersmith factor `N`.
- A computation that merely *looks* infeasible (an `N`-iteration loop) is `O(1)` once you reduce the exponent modulo the group order — apparent cost is not security.

## Fix / defense

- Use OAEP and non-repeating random plaintexts so `m^e − c` GCDs don't apply.
- Never reveal any bits of `p`/`q`; a recovery/"forgot key" flow must leak zero key material.
- Assume the attacker knows the same algebraic shortcuts you do — never rely on brute-force cost you can also skip.
