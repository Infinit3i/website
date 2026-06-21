---
title: "Sugar Free Candies"
date: 2027-01-05 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, integer-equations, cube-root, no-modulus]
description: "A Very Easy Crypto challenge that splits the flag into three integer chunks and leaks a system of non-modular polynomial equations over the plain integers. Because each equation has one variable cubed while the rest are tiny corrections, the dominant cube term gives away each chunk to an exact integer cube root, and a short fixed-point iteration recovers the flag — no modulus, no factoring, no symbolic solver."
---

## Overview

Sugar Free Candies is a Very Easy Crypto challenge. The flag is cut into three equal byte-chunks `a`, `b`, `c` (each read as an integer with `bytes_to_long`), and `output.txt` leaks four numbers built from them — all **over the plain integers**, with no modulus anywhere. The lack of a modulus is the whole game: it means each leaked value is dominated by a single cube term, so a plain integer cube root hands you the answer.

## The technique

The generator does this:

```python
candies = [bytes_to_long(FLAG[i:i+step]) for i in range(0, len(FLAG), step)]
cnd1, cnd2, cnd3 = candies   # a, b, c
v1 = cnd1**3 + cnd3**2 + cnd2
v2 = cnd2**3 + cnd1**2 + cnd3
v3 = cnd3**3 + cnd2**2 + cnd1
v4 = cnd1 + cnd2 + cnd3
```

So the leak is the system:

```
v1 = a^3 + c^2 + b
v2 = b^3 + a^2 + c
v3 = c^3 + b^2 + a
v4 = a + b + c
```

Each chunk is about 21 bytes, i.e. on the order of `10^50`. That makes a cube term roughly `10^150`, while the square and linear corrections sit around `10^42` and `10^50` — utterly negligible next to the cube. Therefore `a` is essentially `cbrt(v1)`, `b` is `cbrt(v2)`, and `c` is `cbrt(v3)`. Plug rough values back in to subtract the small corrections, recompute the cube roots, and the system snaps to the exact integers in a couple of rounds. `v4 = a + b + c` is a free consistency check.

The one trap: `int(n ** (1/3))` is useless for a 150-digit `n` because a float only carries ~15 significant figures. You need an **exact integer cube root** (integer Newton). A symbolic solver is the wrong tool too — `sympy.nsolve`/`solve` just hangs on integers this large.

## Solution

`solve.py` — exact-integer cube root plus a fixed-point refinement:

```python
from Crypto.Util.number import long_to_bytes

v1 = 1181239096013650837744125294978177790419553719590172794906535790528758829840751110126012179328061375399196613652870424327167341710919767887891371258453
v2 = 2710472017687233737830986182523923794327361982506952801148259340657557362009893794103841036477555389231149721438246037558380601526471290201500759382599
v3 = 3448392481703214771250575110613977019995990789986191254013989726393898522179975576074870115491914882384518345287960772371387233225699632815814340359065
v4 = 396216122131701300135834622026808509913659513306193

def icbrt(n):
    if n <= 0: return 0
    x = 1 << ((n.bit_length() + 2) // 3)   # exact integer Newton, no floats
    while True:
        y = (2*x + n // (x*x)) // 3
        if y >= x: break
        x = y
    while x*x*x > n: x -= 1
    while (x+1)**3 <= n: x += 1
    return x

a, b, c = icbrt(v1), icbrt(v2), icbrt(v3)
for _ in range(100):
    a = icbrt(v1 - c*c - b)
    b = icbrt(v2 - a*a - c)
    c = icbrt(v3 - b*b - a)

assert a**3 + c**2 + b == v1
assert b**3 + a**2 + c == v2
assert c**3 + b**2 + a == v3
assert a + b + c == v4

print((long_to_bytes(a) + long_to_bytes(b) + long_to_bytes(c)).decode())
```

Running it verifies all four leaked values and prints the flag:

```
HTB{...}
```

## Why it worked

There is no modulus. A cryptosystem that hides a secret in `g^x mod p` is safe because the modular reduction destroys the magnitude relationship between input and output. Here the values are raw integers, so magnitude is preserved — and a sum of powers where one term is a cube of a 50-digit number is dominated entirely by that cube. The "encryption" is therefore invertible by elementary arithmetic: an integer cube root recovers each chunk up to a tiny correction that a fixed-point loop cleans up exactly.

## Fix / defense

Never expose secret material through reversible integer arithmetic. If a challenge wants to combine secret pieces, do it under a modulus large enough that magnitude information is lost (and ideally tied to a hard problem like discrete log or factoring), or use a proper KDF/encryption primitive. Leaking `a^3 + ...` over the integers is equivalent to publishing `a` itself.
