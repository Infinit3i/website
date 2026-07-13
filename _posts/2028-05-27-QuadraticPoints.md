---
layout: post
title: "Quadratic Points"
date: 2028-05-27 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, elliptic-curve, ecdlp, pohlig-hellman, bsgs, crt, cwe-326]
description: "A 40-bit elliptic curve makes the discrete log a toy — each connection leaks the flag modulo a small order, and CRT across a handful of fresh reconnections rebuilds a flag far bigger than the field."
---

## Overview

Quadratic Points is a **Medium** HackTheBox **Crypto** challenge. A netcat service makes you clear a seven-round integer-quadratic puzzle, then hands you an elliptic-curve point multiplication `Gn = flag·G` over a tiny 40-bit prime field. Because the field is so small the discrete log is trivially breakable, but it only reveals the flag modulo a ~40-bit group order — so the real trick is reconnecting for fresh parameters and stitching the partial results together with the Chinese Remainder Theorem.

## The technique

The server has two stages.

**Stage 1 — an anti-automation gate.** Seven rounds each print a floating-point root `x` and demand integer coefficients `a, b, c` (each nonzero, `|·| ≤ 60`) of `a·x² + b·x + c = 0`. The check accepts any residual below `1e-13`. This is pure gatekeeping — no cryptography — and is trivially scriptable.

**Stage 2 — the actual weakness.** After the gate the server builds `E: y² = x³ + b·x + c` over `F_p` with `p = getPrime(40)`, picks a random base point `G`, and prints `G`, `Gn = flag·G`, and `p`. The coefficients `b, c` come from *your* last puzzle round.

The flaw is an [undersized elliptic-curve field](https://cwe.mitre.org/data/definitions/326.html): a 40-bit prime means the group order is only ~2⁴⁰, so the elliptic-curve discrete log falls in seconds to generic algorithms. Solving it yields `flag mod ord(G)` — about 34–40 bits. The flag itself is hundreds of bits (its text literally reads `l0ng_fl4g_f0r_CRT_purp0s3s`), so a single connection is not enough. Each **fresh connection** regenerates a new `p` and `G`, hence a new small order. Collecting `flag mod ord(Gᵢ)` from several connections and combining them with CRT recovers the full flag once the product of moduli exceeds it.

## Solution

No SageMath is needed — the whole break fits in a few dozen lines of pure Python:

1. **Solve the gate.** For each printed root `x`, brute `a, b ∈ [-60, 60]`, set `c = round(-(a·x² + b·x))`, and keep any triple with residual `< 1e-13`.
2. **Order of G.** BSGS over the Hasse interval `[1, p+1+2√p]` finds a multiple of the order; dividing out the prime factors that still annihilate `G` gives the exact `ord(G)`.
3. **Discrete log.** Pohlig–Hellman: for each prime power `qᵉ ‖ ord(G)`, project into the order-`qᵉ` subgroup and BSGS digit-by-digit, giving `flag ≡ r (mod qᵉ)`.
4. **Accumulate + CRT.** Keep the largest power of each distinct prime across connections, CRT them, and decode once the modulus passes the flag length.

The core of the solver:

```python
from math import isqrt
from sympy import factorint

class EC:
    def __init__(self, p, A, B): self.p, self.A, self.B = p, A % p, B % p
    def add(self, P, Q):
        if P is None: return Q
        if Q is None: return P
        p = self.p; x1, y1 = P; x2, y2 = Q
        if x1 == x2 and (y1 + y2) % p == 0: return None
        m = ((3*x1*x1 + self.A) * pow(2*y1, -1, p) if P == Q
             else (y2 - y1) * pow((x2 - x1) % p, -1, p)) % p
        x3 = (m*m - x1 - x2) % p
        return (x3, (m*(x1 - x3) - y1) % p)
    def mul(self, k, P):
        R = None; Q = P
        if k < 0: k = -k; Q = (Q[0], (-Q[1]) % self.p)
        while k:
            if k & 1: R = self.add(R, Q)
            Q = self.add(Q, Q); k >>= 1
        return R

def order_of(E, G):
    M = bsgs(E, G, None, E.p + 1 + 2*isqrt(E.p) + 1)   # multiple of ord via Hasse BSGS
    n = M
    for q in factorint(n):
        while n % q == 0 and E.mul(n // q, G) is None: n //= q
    return n

def ph_dlog(E, G, Y, n):                                # Pohlig-Hellman -> [(q^e, flag mod q^e)]
    out = []
    for q, e in factorint(n).items():
        qe = q**e; Gi = E.mul(n//qe, G); Yi = E.mul(n//qe, Y)
        x = 0; gamma = E.mul(q**(e-1), Gi)
        for k in range(e):
            h = E.mul(q**(e-1-k), E.add(Yi, E.mul(-x, Gi)))
            x += bsgs_sub(E, gamma, h, q) * (q**k)
        out.append((qe, x % qe))
    return out
```

The full `solve.py` connects, clears the seven gates, parses `G`/`Gn`/`p`, runs `order_of` + `ph_dlog`, and appends each `(qᵉ, residue)` to a `state.json`. A small driver loop respawns the challenge instance and re-runs until the CRT modulus overtakes the flag — about five connections (~650 bits) here — at which point it decodes to `HTB{...}`.

Two operational notes that cost real time:

- Run the solver with `python3 -u`. Buffered stdout is silently discarded when a `timeout` kills the process, which looks exactly like a hang.
- The challenge docker tended to drop after only ~2 connections, so persisting congruences to disk and driving *stop → start → wait-until-the-port-is-live → resume* is what makes the multi-connection CRT reliable.

## Why it worked

The root cause is an [inadequate encryption strength](https://cwe.mitre.org/data/definitions/326.html): a 40-bit field turns ECDLP into a BSGS/Pohlig–Hellman exercise that finishes in seconds. Compounding it, the *same constant secret* (the flag) is exposed modulo a freshly generated small order on every connection — precisely the structure CRT is built to invert. The quadratic gate adds friction but protects nothing.

## Fix / defense

Use a cryptographically sized field (≥256-bit prime) and a standard curve of near-prime order — never a 40-bit prime where the discrete log is a toy. Just as important, never let an attacker re-query one secret across independently generated small moduli; that is exactly the CRT setup that defeats per-connection reduction. In practice, reach for a vetted primitive such as X25519/Ed25519 instead of a hand-rolled `EllipticCurve(p, [a, b])` with attacker-influenced coefficients.
