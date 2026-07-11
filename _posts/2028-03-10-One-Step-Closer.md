---
layout: post
title: "One Step Closer"
date: 2028-03-10 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, rsa, franklin-reiter, related-message, polynomial-gcd]
description: "An RSA oracle that re-encrypts the flag under a fresh affine mask every call — but the same modulus. Two queries and a polynomial GCD are all it takes to peel the flag straight out with the Franklin-Reiter attack."
---

## Overview

One Step Closer is a Medium crypto challenge. A small Flask service exposes `/api/get_flag`, which each call returns a JSON blob:

```json
{ "ct": "...", "n": "...", "e": "...", "a": "...", "b": "..." }
```

where `ct = (a·flag + b)^e mod n`, with `e = 257`. The exponents `a` and `b` are freshly random every request — but the modulus `n` is generated once, at import time, so it's the same across every call. That single detail is the whole vulnerability.

## Why it breaks: related messages

Because `n` is fixed, repeated calls give you ciphertexts of messages that are all **affine functions of the same secret**: `m_i = a_i·flag + b_i`. Two ciphertexts of related plaintexts under the same modulus and small exponent is exactly the setup for the [Franklin–Reiter related-message attack](https://en.wikipedia.org/wiki/Coppersmith%27s_attack#Franklin%E2%80%93Reiter_related-message_attack).

You don't even need to derive the relation between the two messages. Just write both ciphertext equations as polynomials in the single unknown `flag`:

```
P1(x) = (a1·x + b1)^e − c1   ≡ 0 (mod n)
P2(x) = (a2·x + b2)^e − c2   ≡ 0 (mod n)
```

Both are satisfied by `x = flag`, so `gcd(P1, P2)` over `Z_n[x]` contains the factor `(x − flag)`. With `e = 257` the polynomials have 258 terms and the Euclidean GCD is a linear polynomial `g1·x + g0`, giving `flag = −g0 · g1⁻¹ mod n`.

## Solution

No Sage required — expand `(a·x + b)^e` with binomial coefficients (`coeff of xᵏ = C(e,k)·aᵏ·b^(e−k)`) and run a hand-rolled polynomial GCD modulo `n`.

Create `solve.py`:

```python
#!/usr/bin/env python3
import json, urllib.request, sys
from math import comb
from Crypto.Util.number import long_to_bytes

T = sys.argv[1]
def sample(): return json.loads(urllib.request.urlopen(f"http://{T}/api/get_flag", timeout=15).read())
s1, s2 = sample(), sample()
n = int(s1['n'], 16); e = int(s1['e'], 16)
c1, a1, b1 = int(s1['ct'], 16), int(s1['a'], 16), int(s1['b'], 16)
c2, a2, b2 = int(s2['ct'], 16), int(s2['a'], 16), int(s2['b'], 16)

inv = lambda a, n: pow(a % n, -1, n)          # NOT a recursive egcd (2048-bit -> RecursionError)
def norm(p):
    while len(p) > 1 and p[-1] == 0: p.pop()
    return p
def rem(A, B, n):
    A = [x % n for x in A]; norm(A); d = len(B) - 1; lb = inv(B[-1], n)
    while len(A) - 1 >= d and len(A) > 1:
        co = A[-1] * lb % n; s = len(A) - 1 - d
        for i in range(len(B)): A[s + i] = (A[s + i] - co * B[i]) % n
        norm(A)
    return [0] if (len(A) == 1 and d == 0) else A
def pgcd(A, B, n):
    A = [x % n for x in A]; norm(A); B = [x % n for x in B]; norm(B)
    while not (len(B) == 1 and B[0] == 0): A, B = B, rem(A, B, n)
    return A

ex = lambda a, b: [comb(e, k) * pow(a, k, n) % n * pow(b, e - k, n) % n for k in range(e + 1)]
P1 = ex(a1, b1); P1[0] = (P1[0] - c1) % n
P2 = ex(a2, b2); P2[0] = (P2[0] - c2) % n
g = pgcd(P1, P2, n)
print(long_to_bytes((-g[0] * inv(g[1], n)) % n).decode())
```

Two queries later:

```
HTB{...}
```

## Two implementation notes

- **Use `pow(x, -1, n)`, not a recursive extended GCD.** A recursive `egcd` on 2048-bit integers blows Python's recursion limit with a `RecursionError`. The built-in modular inverse is C-level and iterative.
- **A failing inverse is a bonus win.** If a leading coefficient ever isn't invertible mod `n`, then `gcd(coeff, n) > 1` — which factors `n` outright, giving an alternate route to the flag.

## Why it worked

RSA leaks nothing about a single message, but it is malleable across related messages: two encryptions of linearly-related plaintexts under one modulus form a solvable polynomial system, and a small public exponent keeps the GCD cheap. Randomizing the mask every call doesn't help when the attacker is handed `a`, `b`, and `n` and the modulus never rotates.

## Fix / defense

Never encrypt a secret directly with textbook RSA, and never re-encrypt the same plaintext under the same modulus with attacker-known transforms. Use OAEP padding (which randomizes each encryption and destroys the algebraic relation), and don't expose `a`/`b`/`n` in the first place. A fresh modulus per session would also break the two-sample requirement.
