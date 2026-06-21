---
title: "RsaCtfTool"
date: 2027-04-10 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, rsa, prime-power, factordb, aes, cwe-326]
description: "An Easy Crypto challenge whose RSA public key hides a fatal shortcut: the modulus is a prime cube, n = p^3. One distinct prime means the key falls in microseconds — take the integer cube root, build the totient as p^2(p-1), recover the private exponent, decrypt a wrapped AES key, and AES-ECB the flag."
---

## Overview

RsaCtfTool is an Easy HackTheBox **Crypto** challenge — download only, no instance. You get an RSA public key, an RSA-encrypted blob (`key`), and an AES-encrypted file (`flag.txt.aes`). The public modulus *looks* big (1535 bits), but it is a **prime power** `n = p^3` — only one unknown prime — so the whole thing collapses to an integer cube root.

```
challenge/pubkey.pem    # RSA public key:  e = 65537,  n is 1535-bit
challenge/key           # 384 hex chars = the RSA ciphertext c (a wrapped AES key)
challenge/flag.txt.aes  # 32 bytes of AES ciphertext + a trailing newline
```

## The technique

RSA is only hard when `n = p·q` is the product of **two distinct large primes**. Here the
modulus is a single prime raised to the third power:

```
n = p ** 3
```

[factordb](http://factordb.com) returns it as `status FF` with a single base — `[[p, 3]]`.
You don't even need the lookup: with only one unknown prime, `p` is the **exact integer cube
root** of `n`, recovered in microseconds regardless of bit length. The "huge modulus = safe"
intuition is wrong — it is *structure*, not size, that breaks this key. This is
[CWE-326](https://cwe.mitre.org/data/definitions/326.html) (inadequate encryption strength).

Once `p` is known, the totient is **not** `(p−1)(q−1)`. For a prime power:

```
φ(p^k) = p^(k−1)·(p−1)      →   k = 3:   φ = p²·(p−1)
```

so `d = e⁻¹ mod φ` and `m = c^d mod n`. The recovered `m` is a **16-byte AES-128 key** (its
first bytes spell ASCII `secretkey` — a deliberate "you got it" tell), and `flag.txt.aes` is
that file under **AES-128-ECB**.

## Solution

The full chain, from the public key to the flag:

```
factordb / integer cube root  →  p
φ = p²(p−1)                    →  d = inv(e, φ)
RSA-decrypt key               →  AES-128 key (b"secretkey...")
AES-128-ECB                   →  HTB{...}
```

Create `solve.py`:

```python
#!/usr/bin/env python3
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes
from Crypto.Cipher import AES

pub = RSA.import_key(open("challenge/pubkey.pem", "rb").read())
n, e = pub.n, pub.e

def icbrt(x):                                  # float cube root overflows on 1535-bit ints
    lo, hi = 0, 1 << ((x.bit_length() // 3) + 2)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        lo, hi = (mid, hi) if mid ** 3 <= x else (lo, mid - 1)
    return lo

p = icbrt(n)
assert p ** 3 == n                             # confirm it really is a prime cube

phi = p ** 2 * (p - 1)                          # phi(p^3) = p^2 (p-1), NOT (p-1)(q-1)
d = inverse(e, phi)

c = int(open("challenge/key").read().strip(), 16)
key = long_to_bytes(pow(c, d, n))               # 16-byte AES key, begins b"secretkey"

ct = open("challenge/flag.txt.aes", "rb").read().rstrip(b"\n")
print(AES.new(key, AES.MODE_ECB).decrypt(ct).decode())
```

```bash
python3 solve.py
# HTB{...}
```

## Why it worked

A prime-power modulus removes the second unknown that RSA's security depends on. With only one
prime, factoring degenerates into taking an integer root — instant at any size — and the
totient of `p^k` is the simple `p^(k−1)(p−1)`, so the private exponent drops out directly.
The wrapped AES key and ECB-encrypted flag are just packaging on top of that single fatal flaw.

## Fix / defense

```python
p, q = getPrime(1536), getPrime(1536)
assert p != q
n = p * q                                       # two DISTINCT large primes
pub = RSA.construct((n, 65537))
```

- Generate keys only with vetted libraries (`RSA.generate(3072)`); never hand-build `n`.
- Reject any modulus that is a perfect power — `iroot(n, k)` should be inexact for `k = 2..8`.
- Prefer modern KEMs (ML-KEM) or ECC over hand-rolled RSA parameters.
