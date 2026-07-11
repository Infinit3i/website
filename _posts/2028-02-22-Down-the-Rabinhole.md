---
layout: post
title: "Down the Rabinhole"
date: 2028-02-22 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, rabin, related-message, gcd-attack, modular-arithmetic]
description: "A Rabin-flavoured cipher c = m(m+C) where the 128-bit coefficient is reused across two moduli and leaks structurally through gcd(n-4) — combined with a padded/unpadded related-message trick, the flag falls out with two GCDs and two modular inverses, no factoring."
---

## Overview

Down the Rabinhole is a Medium crypto challenge from Cyber Apocalypse 2022. Each half of the flag is encrypted twice under a fresh ~1282-bit modulus using a Rabin-flavoured map `c = m(m + C) mod n`. The whole thing collapses without ever factoring `n`: the shared coefficient `C` leaks through a greatest-common-divisor over the moduli, and the fact that both a message *and* its padded form are encrypted lets you linearize away the quadratic term.

## The technique

The encryption for each half produces two ciphertexts under one modulus:

```python
c1 = (m * (m + coefficient)) % n            # unpadded message
c2 = (padded * (padded + coefficient)) % n  # pad(m, 256) — PKCS7 to 256 bytes
```

Two design mistakes stack:

1. **The 128-bit prime `coefficient` (`C`) is reused** for both flag halves and both moduli.
2. The primes are constructed as `p = 3*C*a + 2`, `q = 3*C*b + 2`, so
   `n = 9C²ab + 6C(a+b) + 4`, i.e. `n - 4 = 3C·(3C·ab + 2(a+b))`. Every modulus carries `3C` as a factor of `n-4`.

## Solution

**Step 1 — leak the coefficient with a GCD.** Because both moduli share the factor `3C` in `n-4` and the remaining cofactors are effectively coprime, one line recovers the "secret":

```python
C = math.gcd(n1 - 4, n2 - 4) // 3
```

No factoring of `n` required — the flag itself taunts you about *"the gcd trick"*.

**Step 2 — linearize the padded equation.** The padded message is `M = m·256^K + P`, where `K` is the number of PKCS7 pad bytes (equal to the pad value) and `P` is the integer formed from those bytes. From `c1 = m² + C·m` you have `m² = c1 − C·m`; substitute it into the expanded `c2 = M² + C·M` and the quadratic term cancels, leaving a linear equation in `m` solved by a single modular inverse.

Full `solve.py`:

```python
import math

n1, c1, c2, n2, c3, c4, L = map(int, open('out.txt').read().splitlines())

C = math.gcd(n1 - 4, n2 - 4) // 3

def recover(n, cu, cp, k):
    P = int(hex(k)[2:] * k, 16)          # PKCS7 padding integer
    b = 256 ** k
    X = (cp - P * P - P * C) * pow(b, -1, n) % n
    return (X - b * cu) * pow(2 * P + C - C * b, -1, n) % n

m1 = recover(n1, c1, c2, 256 - L // 2)   # floor(L/2) pad bytes for half 1
m2 = recover(n2, c3, c4, 256 - -(-L // 2))  # ceil(L/2) for half 2

tohex = lambda m: ('0' + hex(m)[2:]) if len(hex(m)[2:]) % 2 else hex(m)[2:]
print(bytes.fromhex(tohex(m1) + tohex(m2)).decode())
```

Running it prints the flag: `HTB{...}` (redacted).

## Why it worked

Rabin's security depends on plaintexts being independent and the modulus being hard to factor. Both assumptions are broken here: one coefficient shared across encryptions turned two unknowns into one, and the `p = 3*C*a + 2` construction planted that shared value as a visible factor of `n-4`. Encrypting both a message and a *deterministic transform of it* (its padding) under the same key is a textbook related-message setup — the algebraic relation between `m` and `pad(m)` is exactly what lets you eliminate the quadratic term and solve linearly.

## Fix / defense

- Derive any per-encryption coefficient or nonce freshly and independently — never reuse it across ciphertexts.
- Don't build primes with a public shared factor (`3*C*a + 2` leaks `C` straight into `n`).
- Use IND-CCA-secure padding (Rabin-OAEP) and never encrypt both a message and a known transform of it under the same modulus.
