---
title: "Lost Modulus"
date: 2027-04-05 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, rsa, small-exponent, cube-root, cwe-780]
description: "An Easy Crypto challenge that dresses up a classic RSA mistake as a missing-key puzzle. The title insists you need to recover the lost modulus, but with a public exponent of 3 and a short flag the ciphertext never wrapped the modulus at all — it's just the plaintext cubed, so an integer cube root reads it straight back."
---

## Overview

**Lost Modulus** is an Easy Crypto challenge. The prompt — *"I encrypted a secret message with RSA but I lost the modulus. Can you help me recover it?"* — wants you to believe the puzzle is reconstructing the lost modulus `n`. It isn't. The encryption uses a public exponent `e = 3` on a short message, so the modular reduction never happens and the ciphertext is literally the plaintext cubed. Take the integer cube root and you have the flag — `n` is never needed. This is textbook [small public exponent / raw RSA without OAEP](https://cwe.mitre.org/data/definitions/780.html) ([CWE-780](https://cwe.mitre.org/data/definitions/780.html)).

## The technique

We're given two files: `challenge.py` and `output.txt` (the ciphertext as hex). The relevant part of the source:

```python
class RSA:
    def __init__(self):
        self.p = getPrime(512)
        self.q = getPrime(512)
        self.e = 3                 # small public exponent
        self.n = self.p * self.q   # ~1024-bit modulus
    def encrypt(self, data):
        pt = int(data.hex(), 16)
        ct = pow(pt, self.e, self.n)   # c = m^3 mod n
        return long_to_bytes(ct)

print('Flag:', crypto.encrypt(flag).hex())
```

RSA encryption is `c = m^e mod n`. The `mod n` only changes anything when `m^e >= n`. Here `e = 3` and `m` is just the flag (~40 bytes ⇒ ~320 bits), so `m^3` is roughly 960 bits while `n` is ~1024 bits. Because `m^3 < n`, **the reduction never fires** and the emitted "ciphertext" is exactly `m**3` as an ordinary integer. The plaintext is therefore the **exact integer cube root** of the ciphertext — no modulus, no factoring, no private key.

## Solution

`solve.py` reads the hex ciphertext, takes the exact integer cube root (binary search — never floats, which lose precision on a 960-bit number), verifies the root is a perfect cube, and prints the bytes:

```python
#!/usr/bin/env python3
from Crypto.Util.number import long_to_bytes

ct_hex = open("files/output.txt").read().split("Flag:")[1].strip()
ct = int(ct_hex, 16)

def iroot(x, k):                       # exact integer k-th root, no floats
    lo, hi = 0, 1 << ((x.bit_length() // k) + 2)
    while lo < hi:
        mid = (lo + hi) // 2
        if mid**k < x: lo = mid + 1
        else:          hi = mid
    return lo

m = iroot(ct, 3)
for cand in (m - 1, m, m + 1):         # pin the exact root, confirm perfect cube
    if cand**3 == ct:
        m = cand
        break
else:
    raise SystemExit("not a perfect cube — modular reduction DID occur")

print(long_to_bytes(m).decode())
```

```
$ python3 solve.py
HTB{...}
```

The recovered flag spells out the moral of the challenge: never use small exponents for RSA. A one-line equivalent is `gmpy2.iroot(c, 3)`.

## Why it worked

`e = 3` is a perfectly valid RSA exponent in theory, but it's catastrophic on a small, unpadded message: cubing a number that's smaller than the cube root of the modulus never reaches the modulus, so the operation is trivially invertible with arithmetic alone. The "lost modulus" framing is pure misdirection — `n` plays no role in breaking this.

If the cube root *isn't* exact (`m**3 != c`), the message did wrap the modulus, and you'd escalate to **Håstad's broadcast attack** (the same `m` under several moduli, recovered via CRT + integer `e`-th root) or **stereotyped-message Coppersmith** (a short unknown after a known prefix, which does need `n`).

## Fix / defense

- Use **RSA-OAEP** for encryption — randomized padding makes every ciphertext non-deterministic and destroys the small / low-entropy structure these attacks rely on.
- Use `e = 65537`, never `e = 3`, and never encrypt raw attacker-relevant data under textbook RSA.
- Prefer authenticated hybrid encryption (a vetted KEM/DEM) over hand-rolled RSA primitives.

```python
from Crypto.Cipher import PKCS1_OAEP
ct = PKCS1_OAEP.new(pubkey).encrypt(flag)   # e=65537, randomized padding
```
