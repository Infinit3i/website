---
layout: post
title: "Waiting List"
date: 2028-05-06 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, dsa, ecdsa, nonce-leak, hidden-number-problem, lll, lattice]
description: "A clinic booking service signs appointments with DSA over a prime field and helpfully publishes the low 7 bits of every nonce. Seven leaked bits across 200 signatures is a Hidden Number Problem — one LLL reduction recovers the private key, and a forged signature books the appointment that hands over the flag."
---

## Overview

Waiting List is a Hard HackTheBox **Crypto** challenge. A TCP service signs clinic appointments with a DSA-style scheme over a prime field, and its `sign()` routine leaks the low 7 bits of every per-signature nonce. You are handed 200 such signatures. The flag is revealed only for a signature on one specific appointment string — so the path is: recover the private key from the leaked nonce bits via a lattice, then forge that signature.

## The technique

The scheme is DSA over a multiplicative group `Z_n*` (generator `g = 5`, 256-bit prime `n`) — despite the class being called `ECDSA`, there is no elliptic curve involved:

```python
r = pow(g, k, n)                    # k is the per-signature nonce
s = (pow(k, -1, n) * (h + key*r)) % n
lsb = k % (2**7)                    # <-- leaks the low 7 bits of the nonce
```

A nonce must be uniform **and secret**. Publishing even 7 bits of each `k` turns every signature into a linear equation in two unknowns — the long-term `key` and the hidden high bits of that nonce. Collect enough of them and a lattice recovers the key. This is the **Hidden Number Problem (HNP)**, and it works identically whether the group is elliptic or a prime field — only the linear nonce relation matters.

## Solution

Rearranging `s = k^-1(h + key·r)` gives, for each signature `i`:

```
k_i = a_i + key·c_i (mod n)      a_i = s_i^-1·h_i,   c_i = s_i^-1·r_i
```

Split the nonce into its leaked low bits and unknown high part `k_i = lsb_i + 128·m_i` (with `m_i < n/128`, so `m_i` is small — about 249 bits). Substituting yields the HNP form where `m_i` is the small value and `key` is the hidden number:

```
m_i ≡ A_i + key·T_i (mod n)      A_i = 128^-1(a_i - lsb_i),   T_i = 128^-1·c_i
```

Build a `d+2` dimensional lattice. The load-bearing detail is **balancing the columns** so the short target vector `(128·m_0, …, 128·m_{d-1}, key, n)` has all coordinates the same magnitude (~`2^256`). Scale the data columns by `128` and put `n` in the constant column; without this the `key` coordinate dominates and LLL reduces straight past the answer.

`solve.py` — recovers the key from `signatures.txt`, verifies it, forges the gated message, and submits:

```python
from hashlib import sha1
from Crypto.Util.number import bytes_to_long, inverse
from fpylll import IntegerMatrix, LLL

n = 115792089210356248762697446949407573529996955224135760342422259061068512044369
g = 5

def recover_key(rows):
    d = len(rows)
    inv128 = inverse(1 << 7, n)
    A, T = [], []
    for h, r, s, lsb in rows:
        sinv = inverse(s, n)
        a, c = (sinv * h) % n, (sinv * r) % n
        A.append(inv128 * ((a - lsb) % n) % n)
        T.append(inv128 * c % n)
    S, dim = 1 << 7, d + 2
    M = IntegerMatrix(dim, dim)
    for i in range(d):
        M[i, i] = S * n
    for i in range(d):
        M[d, i], M[d+1, i] = S * T[i], S * A[i]
    M[d, d], M[d+1, d+1] = 1, n
    for row in LLL.reduction(M):
        if abs(row[d+1]) == n:
            for key in (row[d] % n, (-row[d]) % n):
                h, r, s, lsb = rows[0]
                k = (inverse(s, n) * (h + key*r)) % n
                if k % (1 << 7) == lsb and pow(g, k, n) == r:
                    return key

def trunc_h(pt):
    h = bin(bytes_to_long(sha1(pt).digest()))[2:]
    return int(h[:len(bin(n)[2:])], 2)

def forge(key, pt):
    h, k = trunc_h(pt), 12345678910111213
    r = pow(g, k, n)
    s = (inverse(k, n) * (h + key * r)) % n
    return r, s
```

Feeding the forged `{pt, r, s}` for `william;yarmouth;22-11-2021;09:00` back to the service returns:

```
Your appointment has been confirmed, congratulations!
Here is your flag: HTB{...}
```

The recovered key verified against all 200 provided signatures before forging.

## Why it worked

The DSA arithmetic is sound. The single fatal mistake is emitting bits derived from the secret nonce. Seven leaked bits sounds tiny, but with 200 signatures (far more than the ~40 minimum for a 7-bit leak on a 256-bit modulus) the private key collapses out of a single [LLL](https://cwe.mitre.org/data/definitions/330.html) reduction — an instance of a [predictable / insufficiently-random secret value](https://cwe.mitre.org/data/definitions/330.html).

## Fix / defense

- **Never emit anything derived from the nonce** — no LSBs, MSBs, counters, timestamps, or `len()`-based bounds. Generate `k` from a CSPRNG and keep it entirely secret.
- Prefer **deterministic nonces (RFC 6979)**, where `k` is a keyed hash of the message: no RNG bias and no leak surface.
- Treat *any* nonce exposure — leaked bits, reuse, or a bounded range — as full private-key compromise. Maps to [CWE-330](https://cwe.mitre.org/data/definitions/330.html) (insufficiently random values) / [CWE-338](https://cwe.mitre.org/data/definitions/338.html) (weak PRNG).
