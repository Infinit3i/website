---
layout: post
title: "HackTheBox Challenge: Space Pirates"
date: 2027-09-28 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, shamir-secret-sharing, secret-sharing, predictable-randomness, md5, aes-ecb, threshold-cryptography]
---

Space Pirates is an easy crypto challenge that looks like a textbook **Shamir Secret Sharing (SSS)** problem — a 10-of-18 threshold scheme over a prime field — but ships a fatal shortcut: the polynomial coefficients aren't independent randomness, they're a deterministic MD5 chain, and the challenge file hands you one of them. That one leak, plus a single share, collapses the whole 10-of-10 threshold down to a single linear equation.

## Overview

You're given `chall.py` (the scheme) and `msg.enc` (the published data). The secret is a Shamir polynomial's constant term, reused to seed an AES key that encrypts the flag. Because the higher coefficients are publicly recomputable and one is leaked, you can recover the secret from **one** share instead of the required ten, then replay the key seed to decrypt the flag. This is a textbook [use of insufficiently random values](https://cwe.mitre.org/data/definitions/330.html) ([CWE-330](https://cwe.mitre.org/data/definitions/330.html) / [CWE-338](https://cwe.mitre.org/data/definitions/338.html)).

## The technique

A secure SSS picks every coefficient `coeffs[1..k-1]` as **independent uniform randomness** — that's exactly what makes fewer than `k` shares reveal nothing about the secret. Space Pirates instead derives each coefficient from the previous one with MD5:

```python
def next_coeff(self, val):
    return int(md5(val.to_bytes(32, byteorder="big")).hexdigest(), 16)
# coeffs[i] = next_coeff(coeffs[i-1])
```

So if you know **any one** coefficient, every coefficient *after* it is a forward MD5 away. And `msg.enc` leaks `coeffs[1]` directly:

```
share: (21202245407317581090, 11086299714260406068)   # one share (x0, y0)
coefficient: 93526756371754197321930622219489764824    # this is coeffs[1]
secret message: 1aaad05f...                              # AES-ECB(flag)
```

From `coeffs[1]` you compute `coeffs[2] … coeffs[9]` yourself. The only coefficient you can't get this way is `coeffs[0]` — the secret — because MD5 doesn't run backwards. But a share is just the polynomial evaluated at `x0`:

```
y0 = coeffs[0] + coeffs[1]·x0 + coeffs[2]·x0² + … + coeffs[9]·x0⁹   (mod p)
```

Every term except `coeffs[0]` is now known, so it's one linear equation in one unknown:

```
secret = ( y0 − Σ_{i=1}^{9} coeffs[i]·x0^i )  mod p
```

The 10-of-18 threshold never mattered: nine of the ten coefficients were attacker-derivable, so a single share is enough.

## Solution

The recovered secret is reused as the AES key seed (`seed(secret); key = randbytes(16)`), so once we have it we replay that and decrypt `msg.enc` in AES-ECB mode.

Create `solve.py`:

```python
from hashlib import md5
from random import seed, randbytes
from Crypto.Cipher import AES

p = 92434467187580489687
k = 10
x0, y0 = (21202245407317581090, 11086299714260406068)
c1 = 93526756371754197321930622219489764824
enc = bytes.fromhex('1aaad05f...')  # full secret message hex from msg.enc

def nxt(v):
    return int(md5(v.to_bytes(32, 'big')).hexdigest(), 16)

# coeffs[1] is leaked; rebuild coeffs[2..k-1] forward via the md5 chain
coeffs = [None, c1]
for i in range(2, k):
    coeffs.append(nxt(coeffs[i - 1]))

# the single share gives one linear equation -> solve for coeffs[0] = secret
s = sum(coeffs[i] * pow(x0, i) for i in range(1, k)) % p
secret = (y0 - s) % p

# secret was reused as the AES key seed
seed(secret)
key = randbytes(16)
print(AES.new(key, AES.MODE_ECB).decrypt(enc))
```

Run it:

```bash
python3 solve.py
```

The decrypted message ends with the flag `HTB{...}`.

## Why it worked

Shamir Secret Sharing is information-theoretically secure **only** because, with fewer than `k` shares, the unknown coefficients are uniformly random — every candidate secret is equally likely. Deriving the coefficients from each other (or from the secret) destroys that independence: leak one link in the chain and the rest unravel deterministically, dropping the effective threshold from `k` to **1**. It's the same root cause as a fixed-seed or otherwise predictable PRNG — the "randomness" is reconstructable by anyone.

## Fix / defense

- Generate **every** non-constant SSS coefficient from independent CSPRNG output (`secrets.randbelow(p)`), never `coeffs[i] = H(coeffs[i-1])` and never derived from the secret.
- Never publish any coefficient alongside the shares.
- Don't reuse a recovered secret directly as a symmetric key seed — run it through a proper KDF, and keep the threshold meaningful so that fewer than `k` shares genuinely reveal nothing.
