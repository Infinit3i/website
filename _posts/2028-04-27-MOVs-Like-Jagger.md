---
layout: post
title: "MOVs Like Jagger"
date: 2028-04-27 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, elliptic-curve, ecdlp, pohlig-hellman, supersingular, ecdh, discrete-log]
description: "The challenge name dangles the MOV pairing attack in front of you, but the supersingular curve's order p+1 factors smooth — so plain Pohlig-Hellman recovers the private scalar on the curve directly, and the ECDH shared secret falls out with one scalar multiplication."
---

## Overview

MOVs Like Jagger is a Medium HackTheBox **Crypto** challenge (Cyber Apocalypse 2022). A Flask "navigation system" runs an ECDH handshake on a custom elliptic curve: it publishes two public points and hands over the flag only if you submit their shared secret point. The name baits you toward the MOV pairing attack, but the real key is that the curve's order is smooth, so a straight [Pohlig-Hellman](https://cwe.mitre.org/data/definitions/327.html) discrete-log solve does the job.

## The technique

The service exposes an elliptic curve `E: y^2 = x^3 - 35x + 98 mod p` with `p = 434252269029337012720086440207` and generator `G`. It holds two key pairs — `Q = nQ·G` (departed) and `P = nP·G` (present) — with private scalars chosen as `randint(1, 2^64)`. `GET /api/coordinates` leaks both public points, and `POST /api/get_flag` returns the flag only if the point you send equals `secret_point = P·nQ`, i.e. the ECDH shared secret `nQ·nP·G`.

Notice the curve order: `ec_order = p + 1` exactly, so `#E = p + 1` and the trace of Frobenius is zero — the curve is **supersingular**. Supersingular curves are the classic target of the MOV attack, which uses a pairing to move the elliptic-curve discrete log into `F_{p^2}`. That's the joke in the title. But you never need the pairing, because the first thing to do with any custom curve is factor its order:

```
p + 1 = 2^4 · 3 · 73 · 88591 · 3882601 · 360301137196997
```

That is *smooth* — the largest prime factor is only about 2^48.4. A smooth group order is exactly the precondition for Pohlig-Hellman to solve the discrete log directly on the curve.

## Solution

To recover `nQ = dlog_G(Q)`: for each prime-power factor `pk` of the order, project both points into the order-`pk` subgroup (multiply by the cofactor `order/pk`), solve the small discrete log there with baby-step/giant-step, and recombine with the Chinese Remainder Theorem. The only heavy factor is `360301137196997` — a BSGS over a ~3.6·10^14 subgroup is ~1.9·10^7 baby steps, which finishes in about 34 seconds using `gmpy2` for the field arithmetic. No Sage or PARI required. Then the shared secret is simply `secret = nQ·P`.

`solve.py` — affine EC point ops (`gmpy2.invert` for the slope), Pohlig-Hellman per subgroup, CRT, then one scalar multiplication:

```python
import sys, json, urllib.request
from math import isqrt
from gmpy2 import mpz, invert
from sympy import factorint

p = mpz(434252269029337012720086440207)
a = mpz(-35); b = mpz(98)
Gx = mpz(16378704336066569231287640165)
Gy = mpz(377857010369614774097663166640)
order = p + 1

def add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P; x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0: return None
    if x1 == x2 and y1 == y2:
        m = (3*x1*x1 + a) * invert(2*y1, p) % p
    else:
        m = (y2 - y1) * invert((x2 - x1) % p, p) % p
    x3 = (m*m - x1 - x2) % p
    return (x3, (m*(x1 - x3) - y1) % p)

def mul(k, P):
    R = None; Q = P; k = int(k) % order
    while k > 0:
        if k & 1: R = add(R, Q)
        Q = add(Q, Q); k >>= 1
    return R

def neg(P): return None if P is None else (P[0], (-P[1]) % p)

def bsgs(G, H, n):                       # H = x*G, x in [0, n)
    m = isqrt(int(n)) + 1
    table, cur = {}, None
    for j in range(m):
        table[cur] = j; cur = add(cur, G)
    fac, cur = neg(mul(m, G)), H
    for i in range(m + 1):
        if cur in table: return (i*m + table[cur]) % n
        cur = add(cur, fac)

def crt(res, mod):
    from functools import reduce
    N = reduce(lambda x, y: x*y, mod); x = 0
    for r, m in zip(res, mod):
        Ni = N // m
        x += r * Ni * int(invert(Ni % m, m))
    return x % N

base = sys.argv[1].rstrip('/')
c = json.loads(urllib.request.urlopen(base + "/api/coordinates").read())
Q = (mpz(int(c["departed_x"], 16)), mpz(int(c["departed_y"], 16)))
P = (mpz(int(c["present_x"], 16)),  mpz(int(c["present_y"], 16)))
G = (Gx, Gy)

res, mod = [], []
for q, e in factorint(order).items():
    pk = q**e
    res.append(bsgs(mul(order//pk, G), mul(order//pk, Q), pk)); mod.append(pk)
nQ = crt(res, mod)
assert mul(nQ, G) == Q
secret = mul(nQ, P)                       # = P*nQ = the ECDH shared secret
print("x", hex(int(secret[0]))); print("y", hex(int(secret[1])))
```

Run it against the live instance, then POST the secret point:

```sh
python3 solve.py http://<docker_ip>:<port>
curl -s -X POST http://<docker_ip>:<port>/api/get_flag \
  -H 'Content-Type: application/json' \
  -d '{"destination_x":"0x...","destination_y":"0x..."}'
```

The response returns the flag, `HTB{...}`.

## Why it worked

ECDH is only as strong as the elliptic-curve discrete-log problem underneath it, and that hardness requires the generator's group order to have a large prime factor. A supersingular curve with `#E = p + 1` is fragile — vulnerable to the MOV pairing transfer — and this particular instance's order also factored into primes no larger than 2^48. Pohlig-Hellman splits one hard 98-bit discrete log into a handful of trivial ones, and a single scalar multiplication reconstructs the shared secret the server was gatekeeping.

## Fix / defense

Use a standardized curve (P-256, Curve25519) whose order is a large prime, or has a small known cofactor with a large prime subgroup. Never roll a custom curve; if you must, verify the order is prime and that the curve is neither supersingular (`#E ≠ p + 1`) nor anomalous (`#E ≠ p`) — both classes have dedicated fast attacks. The general habit that beats this whole family: for any curve you're handed, factor `#E` before trusting it.
