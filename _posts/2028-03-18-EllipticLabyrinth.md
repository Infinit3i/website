---
layout: post
title: "Elliptic Labyrinth"
date: 2028-03-18 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, elliptic-curve, coppersmith, lattice, cvp, lll, msb-leak, hidden-number-problem]
description: "An ECC service leaks the high bits of its secret curve parameters a and b, and hands out one on-curve point that ties them together. That is exactly enough to recover a and b in full with a linear-modular small-root — a plain closest-vector problem — and rebuild the AES key."
---

## Overview

Elliptic Labyrinth is a Medium crypto challenge. A random curve
`y² = x³ + ax + b (mod p)` (512-bit `p`, `p ≡ 3 mod 4`) is generated per
connection. The flag is AES-encrypted under a key derived from the secret
parameters `a` and `b`, and the service politely leaks the **high bits** of both,
plus a point that sits on the curve. Combine the point's exact relation with the
leaked bits and you recover `a` and `b` in full via a lattice small-root, then
rebuild the key.

## The technique

The server gives you three things:

```python
# a "lucky point" on the curve (p % 4 == 3, so this is a square root):
def gen_random_point(self):
    x = randint(2, p-2)
    return (x, pow(x**3 + a*x + b, (p+1)//4, p))

# option 1 — leaks p and the HIGH bits of a and b:
r = randint(p.bit_length()//3, 2*p.bit_length()//3)   # r ∈ [170, 341]
print({'p': hex(p), 'a': hex(a >> r), 'b': hex(b >> r)})

# option 2 — encrypts the flag with a key derived from a, b:
key = sha256(long_to_bytes(pow(a, b, p))).digest()[:16]
```

Because `p ≡ 3 (mod 4)`, `y = rhs^((p+1)/4)` is a square root of
`rhs = x³ + ax + b`, so the lucky point gives an **exact linear relation**:

```
a·x_p + b ≡ ±(y_p² − x_p³) (mod p)     # + if rhs is a QR, − otherwise
```

Now write the unknowns in terms of the leaked high bits:
`a = (aH<<r) + aL`, `b = (bH<<r) + bL` with `aL, bL < 2^r`. Substituting into the
relation collapses everything to a single congruence in two **small** unknowns:

```
aL·x_p + bL ≡ S (mod p),   S = (±y_p² − x_p³) − (aH<<r)·x_p − (bH<<r)
```

With `r ≈ 170`, `2^{2r} ≪ p`, so this has a unique tiny solution. It's a
[Coppersmith](https://en.wikipedia.org/wiki/Coppersmith_method)-style small-root
problem — but because the polynomial is *linear*, a plain **closest-vector
problem** (LLL + Babai) solves it directly, no full Coppersmith needed.

## Solution

```python
from fpylll import IntegerMatrix, LLL, CVP
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes

def cvp_small_root(xp, S, p):
    """smallest (aL, bL) with aL*xp + bL ≡ S (mod p)."""
    W = 1 << 700                                   # weight -> congruence matched exactly
    M = IntegerMatrix.from_matrix([
        [1, 0, (xp % p) * W],                      # aL basis
        [0, 1, 1 * W],                             # bL basis
        [0, 0, p * W],                             # modulus row
    ])
    LLL.reduction(M)
    cv = CVP.closest_vector(M, [0, 0, (S % p) * W])
    return cv[0], cv[1]                            # aL, bL

# read the lucky point (xp, yp); call option 1 ~40 times to collect (a>>r, b>>r)
samples.sort(key=lambda t: t[0].bit_length(), reverse=True)   # smallest r first
aH, bH = samples[0]
r_mean = p.bit_length() - aH.bit_length()

for r in range(r_mean - 8, r_mean + 9):            # exact r unknown -> small brute window
    for c in ((yp*yp - xp**3) % p, (-yp*yp - xp**3) % p):     # QR / non-QR sign
        S = (c - (aH << r) * xp - (bH << r)) % p
        aL, bL = cvp_small_root(xp, S, p)
        a, b = aL + (aH << r), bL + (bH << r)
        if consistent(a, b, samples, p):           # a>>ri == aHi and b>>ri == bHi for ALL samples
            key = sha256(long_to_bytes(pow(a, b, p))).digest()[:16]
            flag = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(enc), 16)
```

The correctness gate is **cross-sample consistency**: the recovered `(a, b)` must
reproduce *every* leaked `(a>>rᵢ, b>>rᵢ)` at the right shift `rᵢ`. That single
check pins the correct `r` and the correct QR/non-QR sign out of all the
candidates and rejects any bad CVP output. Running it:

```
[*] best aH bits=334 -> r~178
[+] recovered a,b at r=177
[+] FLAG: HTB{...}
```

> A couple of implementation gotchas: the interactive menu prints a `> ` prompt
> **with no trailing newline**, so the JSON reply lands on the same line — parse
> from the first `{`, don't `startswith("{")`. And `fpylll` lives in Kali's system
> `python3`, not necessarily in a fresh venv.
{: .prompt-tip }

## Why it worked

The `p ≡ 3 (mod 4)` square-root point hands you one exact linear equation in the
secrets for free. Leaking the most-significant bits of `a` and `b` shrinks the
unknowns to `< 2^r`, and with `2^{2r} ≪ p` the small-root is unique — a textbook
closest-vector problem that LLL solves in milliseconds. Once `a` and `b` are
known, `pow(a, b, p)` reproduces the AES key.

## Fix / defense

- **Never leak partial bits of secret key material.** MSB leaks are directly
  attackable by lattice small-root methods (Coppersmith, hidden-number problem).
- Don't derive a symmetric key from recoverable curve parameters — use a proper
  KDF over a full-entropy secret.
- Don't publish an on-curve point that pins an exact algebraic relation among the
  values you're trying to keep secret.
