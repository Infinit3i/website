---
layout: post
title: "Copperbox"
date: 2028-04-26 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, lcg, coppersmith, lattice, lll, prng, small-roots]
description: "A linear congruential generator seeded with the flag publishes only the top bits of two output ratios. Because an LCG is linear, the two ratios collapse to one bilinear equation — linearize the product term and a single LLL reduction on the 48-bit truncations hands back the seed."
---

## Overview

Copperbox is a Medium HackTheBox Crypto challenge. You get two files — `source.py` and `output.txt` — and nothing else; it's entirely offline. The source seeds a linear congruential generator (LCG) with the flag, publishes two *ratios* of its outputs modulo a prime, but writes out only the high bits of each. The challenge name is the hint: **Copper**box → Coppersmith, i.e. a lattice small-roots attack. The path is to collapse the two truncated ratios into a single bilinear equation, linearize it, and recover the low bits with one LLL reduction.

## The technique

The generator is deliberately linear and has no modulus of its own:

```python
def lcg(x, a, b):
    while True:
        yield (x := a*x + b)         # pure linear recurrence
x = int.from_bytes(flag + secrets.token_bytes(30-len(flag)), 'big')   # seed = flag
h1 = next(gen) * pow(next(gen), -1, p) % p    # f1 / f2  mod p
h2 = next(gen) * pow(next(gen), -1, p) % p    # f3 / f4  mod p
# output.txt: hint1 = h1 >> 48 ,  hint2 = h2 >> 48
```

Only the top bits of `h1` and `h2` are published — the low 48 bits are truncated away. But truncating a *linear* generator doesn't hide its seed. Using `f2 = a·f1 + b`, `f3 = a·f2 + b`, `f4 = a·f3 + b`:

- `h1 = f1/f2` gives `f1 = -h1·b / (h1·a - 1)`
- `h2 = f3/f4` gives `f3 = -h2·b / (h2·a - 1)`
- and `f3 = a²·f1 + b·(a+1)`

Substituting and clearing denominators (the `b` cancels) collapses everything into one **bilinear** relation between the two ratios:

```
-a(a+1)·h1·h2 + a·h1 + (a²+a+1)·h2 - (a+1) ≡ 0   (mod p)
```

Write `h1 = c1 + r1` and `h2 = c2 + r2`, where `c = hint<<48` is known and `r1, r2 < 2^48` are the unknown low bits. The relation is bilinear in `(r1, r2)`. Treat the product `u = r1·r2` as its own variable and it becomes a single modular-**linear** equation:

```
A·u + B·r1 + C·r2 + D ≡ 0   (mod p),   u < 2^96,  r1,r2 < 2^48
```

The product of the bounds is `2^192`, far below `p ≈ 2^254`, so a plain LLL over the congruence's kernel lattice finds the small solution — `fpylll` alone, no Sage required.

## Solution

```python
#!/usr/bin/env python3
from fpylll import IntegerMatrix, LLL

p = 0x31337313373133731337313373133731337313373133731337313373133732ad
a = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
b = 0xdeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0de
hint1 = 71423363559670126636256015849609248068471254188780947659031431
hint2 = 60279909443976522334351660980145297750342536242395671298832176

T = 48
c1, c2 = hint1 << T, hint2 << T
A = (-a*(a+1)) % p
B = (-a*(a+1)*c2 + a) % p
C = (-a*(a+1)*c1 + (a*a+a+1)) % p
D = (-a*(a+1)*c1*c2 + a*c1 + (a*a+a+1)*c2 - (a+1)) % p

Ai = pow(A, -1, p)
c = 1 << 96
w = [c // (1<<96), c // (1<<T), c // (1<<T), c]
rows = [[(-Ai*B)%p,1,0,0], [(-Ai*C)%p,0,1,0], [(-Ai*D)%p,0,0,1], [p,0,0,0]]
M = IntegerMatrix(4, 4)
for i in range(4):
    for j in range(4):
        M[i, j] = rows[i][j] * w[j]
LLL.reduction(M)

for i in range(4):
    if abs(M[i, 3]) != w[3]:
        continue
    s = 1 if M[i, 3] > 0 else -1
    r1, r2 = s*M[i, 1]//w[1], s*M[i, 2]//w[2]
    if not (0 <= r1 < (1<<T) and 0 <= r2 < (1<<T)):
        continue
    if (A*r1*r2 + B*r1 + C*r2 + D) % p != 0:
        continue
    h1 = c1 + r1
    f1 = (-h1*b) % p * pow((h1*a - 1) % p, -1, p) % p
    x = (f1 - b) % p * pow(a, -1, p) % p
    raw = x.to_bytes(30, 'big')          # flag + 2 random padding bytes
    print(raw[:raw.find(b'}')+1].decode())
    break
```

Running it recovers `r1 = 43830429126143`, `r2 = 31877652973308`, reconstructs the seed, and the flag falls out of its high bytes:

```console
$ python3 solve.py
HTB{...}
```

## Why it worked

The design assumed that throwing away the low 48 bits of each ratio hid the seed. It doesn't. Linearity means the seed satisfies a low-degree equation in known quantities plus a handful of *small* unknowns, and small unknowns modulo a large prime are exactly what lattice reduction solves. The ratios `f1/f2` don't help the defender either — division is just multiplication by a modular inverse, so the linearity survives it. This is a textbook [use of a predictable RNG](https://cwe.mitre.org/data/definitions/1241.html): an LCG is not a cryptographic generator.

## Fix / defense

- Never publish raw or truncated outputs of an LCG / linear recurrence — LCGs are [not cryptographic PRNGs](https://cwe.mitre.org/data/definitions/338.html).
- Use a CSPRNG (`secrets` / `os.urandom`) for anything secret; don't derive a published value from a linear or affine function of the secret.
- If a value must be published, make it a one-way (hash/KDF) image of the secret, not an invertible transform.
- Don't rely on truncation to hide state — the dropped bits are a small unknown any lattice attack recovers.
