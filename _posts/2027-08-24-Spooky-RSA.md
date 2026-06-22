---
title: "Spooky RSA"
date: 2027-08-24 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, rsa, gcd, factoring, cwe-320]
description: "An Easy Crypto challenge whose hand-rolled RSA scheme uses one of its own secret prime factors as the encryption base — which lets a single GCD factor the 2048-bit modulus with no factoring tool at all, then peel off the flag."
---

## Overview

Spooky RSA is an Easy Crypto challenge: you get the encryptor (`chall.py`) and its output (`out.txt`), nothing else — fully offline. The scheme looks RSA-ish but encrypts the flag twice under random exponents, and the fatal slip is that it uses one of `N`'s own secret prime factors as the encryption base. That single mistake means a [key-management error](https://cwe.mitre.org/data/definitions/320.html) collapses the whole thing: one `gcd` factors the modulus, and the flag falls out.

## The technique

The encryptor is short:

```python
from Crypto.Util.number import bytes_to_long, getStrongPrime
from random import randint

FLAG = b'HTB{????...}'

def key_gen(bits):
    p, q = getStrongPrime(bits), getStrongPrime(bits)
    N = p * q
    return N, (p, q)

def encrypt(m, N, f):
    e1, e2 = randint(2, N - 2), randint(2, N - 2)
    c1 = (pow(f, e1, N) + m) % N
    c2 = (pow(f, e2, N) + m) % N
    return (e1, c1), (e2, c2)

def main():
    N, priv = key_gen(1024)
    m = bytes_to_long(FLAG)
    (e1, c1), (e2, c2) = encrypt(m, N, priv[0])   # f = priv[0] = p
```

The bug is the last line: `encrypt(m, N, priv[0])` passes `priv[0]`, which is `p` — **one of the two secret prime factors of `N`** — as the encryption base `f`. A value that should never leave key generation is now baked into every ciphertext.

Because `N = p*q`, `p` divides `N`. For any exponent `e ≥ 1`, `pow(p, e, N)` is also a multiple of `p`. So both ciphertexts are "a multiple of `p`, plus the message":

```
c1 = (pow(p, e1, N) + m) mod N
c2 = (pow(p, e2, N) + m) mod N
```

Subtract them and the unknown message `m` cancels, leaving a difference of two `p`-multiples — itself a multiple of `p`. Since `N` is also a multiple of `p`, their GCD hands you the prime:

```
p = gcd((c1 - c2) mod N, N)
```

No FactorDB, no lattice, no RsaCtfTool — a single `gcd` factors a 2048-bit modulus. With `p` known (and `f = p`), the term `pow(f, e1, N)` is recomputable, so `m = (c1 - pow(f, e1, N)) mod N`.

## Solution

The whole solve is a few lines. Save it as `solve.py` next to the unzipped files:

```python
#!/usr/bin/env python3
import re
from math import gcd
from pathlib import Path
from Crypto.Util.number import long_to_bytes

txt = Path("files/crypto_spooky_rsa/out.txt").read_text()
N      = int(re.search(r"N = (\d+)", txt).group(1))
e1, c1 = map(int, re.search(r"\(e1, c1\) = \((\d+), (\d+)\)", txt).groups())
e2, c2 = map(int, re.search(r"\(e2, c2\) = \((\d+), (\d+)\)", txt).groups())

p = gcd((c1 - c2) % N, N)
assert 1 < p < N and N % p == 0
f = p

m = (c1 - pow(f, e1, N)) % N
print(long_to_bytes(m).decode())
```

Run it:

```bash
python3 solve.py
# HTB{...}
```

Out comes the flag — a nod to "custom beats textbook every time."

## Why it worked

RSA's security rests on `N` being hard to factor. The instant a secret factor of `N` is used inside any value the attacker receives, that assumption is void. Here two encryptions of the *same* message under different exponents made the message term cancel under subtraction, leaving a clean multiple of `p`; the GCD with `N` then peels the factor straight off. The general reflex for any custom modular scheme: when more than one output is exposed, test linear combinations of those outputs (differences, ratios) against `N` with `gcd`/`modinv` — look for a term that is a multiple of a factor, or any way the unknown plaintext cancels.

## Fix / defense

Never let a private prime, the private exponent, or any key-derived secret appear as the base or operand of a value you transmit. Real RSA encrypts with a fixed public exponent against the modulus only, with randomized padding:

```python
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
pub = RSA.construct((N, 65537))            # public exponent only; private factors never in play
ct  = PKCS1_OAEP.new(pub).encrypt(FLAG)    # randomized OAEP padding per encryption
```

Use a vetted library (PyCryptodome OAEP, `cryptography`) instead of hand-rolled `pow()+add` schemes. The moment the encryption path reaches for the private factors, the game is already lost.
