---
layout: post
title: "Composition"
date: 2027-12-28 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, ecrsa, elliptic-curve, fermat-factorization, demytko, rsa, cwe-327]
---

A crypto challenge that "mashes two of the best cryptosystems together" — an elliptic curve defined over an RSA modulus. The pitch is that the composite construction is *unbreakable*. In practice it is only as strong as its weakest classical part, and the RSA modulus was generated with two primes sitting right next to each other. Once you Fermat-factor `n`, the whole elliptic-curve layer decrypts for free.

## Overview

The server builds an elliptic curve `y² = x³ + a·x + b` **modulo an RSA modulus `n = p·q`**, keeps a secret base point `g`, and publishes `A = e·g` (a scalar multiplication on the ring curve). The flag is AES-CBC encrypted under `md5(str(g.x))`. To recover the flag you have to recover `g.x`, i.e. invert the "ECRSA" encryption `A = e·g`. It prints only the ciphertext + IV, `n`, and the point `A` — but it will hand out one *extra* curve point if you answer `y` to "test the curve", and that generosity is fatal.

## The technique

Four design mistakes stack into a full break:

1. **Fermat-close primes.** `keygen` sets `q = next_prime(p)` and advances it only ~50 primes, so `p` and `q` are adjacent and `n ≈ p²`. Fermat's method (`a² − n = b²`, scanning `a` upward from `⌈√n⌉`) factors `n` in **zero iterations**.
2. **Deterministic exponent.** `e = next_prime(p >> bits/4)` is a pure function of `p`, so once you have `p` you recompute `e` for free — it is never printed.
3. **Curve recovery from two points.** The ciphertext point `A` and the bonus "test" point `R` both satisfy the Weierstrass equation mod `n`. Subtracting the two equations eliminates `b`:

   ```
   a = (Ay² − Ax³ − Ry² + Rx³) · (Ax − Rx)⁻¹   (mod n)
   b = Ay² − Ax³ − a·Ax                          (mod n)
   ```

   Handing out one extra point turns the hidden `(a, b)` into a solvable linear system.
4. **The ring curve splits (Demytko).** There is no single group order mod `n`, but by the Chinese Remainder Theorem the curve over `Z/n` splits into the two genuine curves `E(F_p)` and `E(F_q)`. On each prime field you compute the group order, invert `e` against it, and multiply `A` down to `g`. This is [CWE-327](https://cwe.mitre.org/data/definitions/327.html): a home-grown scheme whose security rested entirely on factoring hardness that bug #1 destroys.

## Solution

Everything is derived by running the solver — the flag is the output of the AES decryption, never copied from anywhere.

Connect once, answer `y` to collect the second point, and capture the ciphertext, IV, `n`, `A`, and `R`. Then run:

`solve.py`:

```python
#!/usr/bin/env python3
from hashlib import md5
from cypari2 import Pari
from sympy import isprime, nextprime, integer_nthroot
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# values captured from the live server
n  = N
Ax, Ay = AX, AY        # ciphertext point A = e*g
Rx, Ry = RX, RY        # bonus "test" point R
data_enc = bytes.fromhex("<flag_hex>")
iv       = bytes.fromhex("<iv_hex>")

# 1. Fermat factor (p, q are adjacent primes)
a0, ex = integer_nthroot(n, 2)
if not ex: a0 += 1
while True:
    b2 = a0*a0 - n
    r, ok = integer_nthroot(b2, 2)
    if ok:
        p, q = a0 + r, a0 - r
        break
    a0 += 1
assert p*q == n and isprime(p) and isprime(q)

# 2. e is deterministic in p
e = int(nextprime(p >> (n.bit_length() // 4)))

# 3. recover the secret curve (a, b) from A and R
a = ((pow(Ay,2,n) - pow(Ax,3,n) - pow(Ry,2,n) + pow(Rx,3,n)) * pow(Ax-Rx,-1,n)) % n
b = (pow(Ay,2,n) - pow(Ax,3,n) - a*Ax) % n

# 4. Demytko: solve the ECDLP per prime field, CRT the x-coordinates
pari = Pari()
pari.allocatemem(1 << 30)              # SEA overflows PARI's default 8MB stack
def recover_gx(pr):
    E = pari.ellinit([a % pr, b % pr], pr)
    order = int(pari.ellcard(E))       # SEA point counting, no Sage needed
    P = pari.ellmul(E, [Ax % pr, Ay % pr], pow(e, -1, order))
    return int(P[0]) % pr
gxp, gxq = recover_gx(p), recover_gx(q)
gx = (gxp * q * pow(q, -1, p) + gxq * p * pow(p, -1, q)) % n

# 5. AES key = md5(str(g.x))
key = md5(str(gx).encode()).digest()
print(unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(data_enc), 16).decode())
```

Running it prints `HTB{...}`.

**Tooling note (no Sage on Kali):** point counting over a 256-bit prime needs Schoof/SEA. `pip install cypari2` in a virtualenv ships a bundled PARI, so `pari.ellcard(pari.ellinit([a,b],p))` is a drop-in replacement for Sage's `EllipticCurve(GF(p),[a,b]).order()`. You must call `pari.allocatemem(1 << 30)` first or SEA overflows PARI's 8 MB default stack.

## Why it worked

An elliptic curve over `Z/n` is not a group — but the moment you factor `n`, the CRT isomorphism `Z/n ≅ F_p × F_q` turns it into two real curves you can compute on directly. The scheme's only hardness assumption was factoring `n`, and choosing `q = next_prime(p)` made `n` Fermat-weak, so every layer above it (the secret point, the exponent `e`, the AES key) unravels in seconds. Publishing a second point on the "secret" curve was the finishing touch — it removed the last unknown without any factoring at all.

## Fix / defense

- Generate `p` and `q` **independently** at full size and reject any pair with a small `|p − q|` (require the gap near `√n`) — never derive one prime from the other with `next_prime`.
- Choose the public exponent independently of the secret primes; deriving `e` from `p` leaks it the instant `n` is factored.
- Never publish a second point on a secret curve — one extra point makes the hidden coefficients a solvable linear system.
- Do not invent composite-modulus elliptic-curve/RSA hybrids. Use vetted primitives (X25519/ECDH on a standard curve, RSA-OAEP) where the hardness assumption is well studied, and never key a cipher off `md5(str(point.x))`.
