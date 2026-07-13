---
layout: post
title: "quick maffs"
date: 2028-05-03 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, rsa, franklin-reiter, related-message, resultant, python-flint, cwe-327]
description: "Three flag chunks are RSA-encrypted under one modulus with a small secret exponent, and the sum of the plaintexts is leaked. That linear relation turns three hard RSA instances into a multi-message Franklin-Reiter attack: eliminate a variable with a resultant, GCD with the remaining power polynomial, and the flag falls out — no Sage required."
---

## Overview

quick maffs is a Hard HackTheBox Crypto challenge. A Sage script encrypts the flag, split into
three chunks, as `c_i = m_i^e mod N` under a single 2046-bit modulus with a small **secret**
prime exponent, and prints one extra value: `hint = m1 + m2 + m3`, the sum of the plaintexts.
That leaked linear relation is the whole game — it turns three individually-hard RSA instances
into a solvable [related-message attack](https://cwe.mitre.org/data/definitions/327.html).

## The technique

The challenge source:

```python
e = random_prime(2^10)        # small secret prime
N = p*q
pts = [bytes_to_long(i) for i in pts]
cts = [pow(i, e, N) for i in pts]
hint = sum(pts)               # the deliberate hook
print(f"{N},{cts},{hint}")
```

The obvious attacks don't apply: the ciphertexts are full ~N-size so each `m_i^e` **wraps**
modulo N (no integer e-th root), `N` is a proper RSA modulus (no factoring), and one ciphertext
alone is a hard instance. The `hint` is what makes it tractable.

Classic **Franklin-Reiter** recovers two messages that satisfy a known linear relation
`m2 = a·m1 + b`, via `gcd(x^e - c1, (a·x + b)^e - c2)` over `Z/N`, which collapses to a linear
factor `(x - m1)`. Here the relation binds all three chunks: `m3 = hint - m1 - m2`. We extend
the attack to three messages by first **eliminating a variable with a resultant**:

```
R(m1) = Res_{m2}( m2^e - c2 ,  (hint - m1 - m2)^e - c3 )     # univariate in m1
gcd( R(m1),  m1^e - c1 )  over Z/N   →  linear factor  →  m1
```

Repeat symmetrically for `m2`, then `m3 = hint - m1 - m2`. The exponent `e` turns out to be
**41** (brute-force the primes below 2¹⁰ if you'd rather not read it off).

## Solution

The reference approach solves the four-equation system `{m_i^e - c_i, sum - hint}` with a Gröbner
basis over `Zmod(N)` in Sage. This solver reproduces it without Sage using `python-flint`, whose
`fmpz_mod_mpoly.resultant` works over a composite modulus. The one trap: `fmpz_mod_poly.gcd`
refuses a composite modulus (*"gcd algorithm assumes that the modulus is prime"*), so the final
polynomial GCD is a hand-rolled Euclidean loop over `Z/N`.

```python
import json, math
from flint import fmpz_mod_mpoly_ctx, fmpz_mod_poly_ctx, Ordering
from Crypto.Util.number import long_to_bytes

N = <N>; c1, c2, c3 = <cts>; hint = <hint>
e = 41

ctx = fmpz_mod_mpoly_ctx.get(names=['m1', 'm2'], ordering=Ordering.lex, modulus=N)
m1, m2 = ctx.gens()

class Factor(Exception):
    def __init__(self, f): self.f = f

def poly_mod(a, b):
    a = [x % N for x in a]; b = [x % N for x in b]
    while len(a) > 1 and a[-1] % N == 0: a.pop()
    while len(b) > 1 and b[-1] % N == 0: b.pop()
    db = len(b) - 1
    g = math.gcd(b[db] % N, N)
    if g not in (1, N): raise Factor(g)          # non-unit leading coeff -> factor of N
    inv = pow(b[db], -1, N)
    while len(a) - 1 >= db and any(a):
        da = len(a) - 1
        coef = (a[da] * inv) % N
        for i in range(db + 1):
            a[da - db + i] = (a[da - db + i] - coef * b[i]) % N
        while len(a) > 1 and a[-1] % N == 0: a.pop()
    return a

def poly_gcd(a, b):
    while any(b): a, b = b, poly_mod(a, b)
    return a

def univ(poly, var):
    c = {mon[var]: int(v) for mon, v in poly.terms()}
    return [c.get(i, 0) for i in range(max(c) + 1)]

def recover(res_poly, var, power_c):
    g = poly_gcd(univ(res_poly, var), [(-power_c) % N] + [0]*(e-1) + [1])
    a1, a0 = g[1] % N, g[0] % N
    return (-a0 * pow(a1, -1, N)) % N

f3 = (hint - m1 - m2)**e - c3
M1 = recover((m2**e - c2).resultant(f3, 'm2'), 0, c1)   # eliminate m2 -> poly in m1
M2 = recover((m1**e - c1).resultant(f3, 'm1'), 1, c2)   # eliminate m1 -> poly in m2
M3 = (hint - M1 - M2) % N

print(b''.join(long_to_bytes(m) for m in (M1, M2, M3)))
```

Running it prints the flag in a couple of seconds:

```
HTB{...}
```

## Why it worked

Textbook RSA is deterministic and algebraically malleable, so a single leaked *relation* between
plaintexts is enough to recover them without the private key. The message sizes force `m_i^e` to
wrap mod N — which kills the trivial e-th-root shortcut and is precisely why the author had to
hand over the sum "so the chall isn't unsolvable." The resultant does the heavy lifting of turning
a three-unknown system into a univariate polynomial whose GCD with `m_i^e - c_i` is linear.

## Fix / defense

Never use raw/textbook RSA for real messages, and never expose an algebraic relation between
plaintexts (a sum, a difference, a shared prefix). **OAEP** padding randomizes every encryption,
destroying the low-entropy/related-message structure this entire attack family depends on.
