---
layout: post
title: "Lost Modulus Again"
date: 2027-12-26 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, rsa, coppersmith, franklin-reiter, short-pad, e3, lattice, cwe-780]
---

A textbook RSA challenge with `e = 3` where the author "lost" the modulus `n` — and then encrypts the flag twice with a fresh 16-byte random pad each time, as if that made it safe. Neither move is a defense: the modulus falls out of a GCD on two known plaintexts, and the twice-padded flag is broken by [Coppersmith's short-pad attack](https://cwe.mitre.org/data/definitions/780.html) plus Franklin-Reiter. No Sage needed — `fpylll` and `sympy` are enough.

## Overview

- **Category:** Crypto (Medium)
- **Given:** `challenge.py` + `output.txt`. RSA with `e = 3`, modulus never printed. Four ciphertexts:
  - `Flag1`, `Flag2` — the flag encrypted twice as `pt = flag || urandom(16)` (same secret, two different 128-bit random pads).
  - `msg1`, `msg2` — two fixed English sentences, encrypted directly (no pad). Their plaintext is hard-coded in `challenge.py`, so they are *known plaintext*.

## The technique

Two independent weaknesses stack.

**1 — Recover the hidden modulus by GCD.** If `m` is known and `c = m^e mod n`, then `m^e − c` is an exact multiple of `n`. With two known-plaintext pairs:

```
n = gcd(m1^3 − c_msg1,  m2^3 − c_msg2)
```

The result is `n` (or a tiny multiple — divide out prime factors below `10^5`). Hiding the modulus is worthless when any known plaintext exposes it.

**2 — Coppersmith short-pad + Franklin-Reiter.** Now we have `n`, `e = 3`, and two ciphertexts of the *same* secret flag with different additive pads:

```
m1 = flag·2^128 + r1     Flag1 = m1^3 mod n
m2 = flag·2^128 + r2     Flag2 = m2^3 mod n
```

`r1`, `r2` are unknown but *small* (128 bits) relative to `n` (2048 bits). Because the pad length `k = 128 < n_bits / e² = 2048/9 ≈ 227`, the short-pad attack applies: the resultant `Res_x(x^3 − Flag1, (x+y)^3 − Flag2)` is a degree-`e²` = 9 univariate polynomial in `y` whose small root is `Δ = r2 − r1` (`|Δ| < 2^128`). Recover `Δ` with a Howgrave-Graham lattice (LLL). Then, with the linear relation `m2 = m1 + Δ` known, Franklin-Reiter finishes it:

```
gcd(x^3 − Flag1,  (x+Δ)^3 − Flag2)  (mod n)  →  x − m1
flag = m1 >> 128
```

This is *not* the plain cube-root case of the original "Lost Modulus" (where `m^3 < n` so the ciphertext is an exact integer cube). Here the pad makes `m^3` wrap `n`, and the unknown is the pad *difference* between two ciphertexts — not a short suffix of one.

## Solution

The full self-contained solver — GCD modulus recovery, a Howgrave-Graham `small_roots` over the degree-9 resultant via `fpylll`, and a mod-`n` polynomial-GCD Franklin-Reiter finisher:

```python
#!/usr/bin/env python3
from Crypto.Util.number import long_to_bytes
from fpylll import IntegerMatrix, LLL
import sympy
from sympy import Symbol, Poly, ZZ, resultant
from math import gcd

HERE = "./"
MSG1 = b"Lost modulus had a serious falw in it , we fixed it in this version, This should be secure"
MSG2 = b"If you can't see the modulus you cannot break the rsa , even my primes are 1024 bits , right ?"

def load_outputs():
    vals = {}
    for line in open(HERE + "output.txt"):
        if ':' not in line:
            continue
        k, v = line.split(':', 1)
        vals[k.strip()] = int(v.strip(), 16)
    return vals

def recover_n(out):
    m1 = int.from_bytes(MSG1, 'big')
    m2 = int.from_bytes(MSG2, 'big')
    k = gcd(m1**3 - out['msg1'], m2**3 - out['msg2'])
    for p in range(2, 100000):
        while k % p == 0:
            k //= p
    return k

def small_roots(fcoeffs, N, X, m, t):
    x = Symbol('x')
    f = Poly(list(reversed(fcoeffs)), x, domain=ZZ)
    d = f.degree()
    polys = []
    for i in range(m):
        fi = f**i
        for j in range(d):
            polys.append((x**j * N**(m - i)) * fi.as_expr())
    fm = f**m
    for i in range(t):
        polys.append((x**i) * fm.as_expr())
    dim = len(polys)
    deg = d * m + t
    B = IntegerMatrix(dim, deg)
    for r, pe in enumerate(polys):
        pc = Poly(pe, x, domain=ZZ).all_coeffs()[::-1]
        for c in range(deg):
            coeff = pc[c] if c < len(pc) else 0
            B[r, c] = int(coeff) * (X**c)
    LLL.reduction(B)
    row = [B[0, c] for c in range(deg)]
    coeffs = [row[c] // (X**c) for c in range(deg)]
    g = Poly(list(reversed(coeffs)), x, domain=ZZ)
    roots = []
    for r in sympy.roots(g).keys():
        if r.is_integer:
            r = int(r)
            if abs(r) <= X and f.eval(r) % N == 0:
                roots.append(r)
    return roots

def poly_gcd_mod(a, b, n):
    def norm(p):
        while p and p[-1] % n == 0:
            p.pop()
        return p
    a = norm([c % n for c in a]); b = norm([c % n for c in b])
    while b:
        while len(a) >= len(b) and a:
            inv = pow(b[-1], -1, n)
            fac = (a[-1] * inv) % n
            shift = len(a) - len(b)
            for i in range(len(b)):
                a[shift + i] = (a[shift + i] - fac * b[i]) % n
            a = norm(a)
        a, b = b, a
    return a

def main():
    out = load_outputs()
    n = recover_n(out)
    C1, C2 = out['Flag1'], out['Flag2']
    x, y = sympy.symbols('x y')
    g1 = Poly(x**3 - C1, x)
    g2 = Poly((x + y)**3 - C2, x)
    hpoly = Poly(resultant(g1, g2), y)
    coeffs_hi = [int(c) % n for c in hpoly.all_coeffs()]
    lead_inv = pow(coeffs_hi[0], -1, n)
    coeffs_hi = [(c * lead_inv) % n for c in coeffs_hi]
    coeffs_lo = coeffs_hi[::-1]
    X = 1 << 129
    delta = None
    for m in (3, 4, 5):
        roots = small_roots(coeffs_lo, n, X, m=m, t=1)
        if roots:
            delta = roots[0]; break
    assert delta is not None
    for d in (delta, -delta):
        a = [(-C1) % n, 0, 0, 1]
        b = [(d**3 - C2) % n, (3 * d**2) % n, (3 * d) % n, 1]
        g = poly_gcd_mod(a[:], b[:], n)
        if len(g) == 2:
            m1 = (-g[0] * pow(g[1], -1, n)) % n
            flag = long_to_bytes(m1 >> 128)
            if b'HTB{' in flag:
                print(flag.decode()); return

if __name__ == '__main__':
    main()
```

Running it recovers the 2048-bit modulus, finds `Δ` at Coppersmith parameters `m=3, t=1` instantly, and prints the flag:

```
HTB{...}
```

## Why it worked

Raw (textbook) RSA is deterministic and algebraically malleable. A small exponent (`e = 3`) combined with a random pad *shorter* than `n / e²` bits leaves the ciphertext exposed to Coppersmith's short-pad attack — even when *two independent* random pads are used, because the pad difference is itself a small root recoverable by lattice reduction. And a hidden modulus is no obstacle at all: one known plaintext yields `n` via a single GCD. The flag itself admits both mistakes: `n3v3r_us3_sm0l_3xp_f0r_rs4` and `Pr3v3nt_Cub3_r00t_4tt4ck`.

## Fix / defense

- Use `e = 65537`, never `3`.
- Encrypt with a standardized randomized padding scheme (**RSA-OAEP**), not a raw byte suffix. OAEP's structure destroys the small-linear-offset relationship that Coppersmith and Franklin-Reiter rely on.
- Never treat secrecy of the modulus as a security property.
