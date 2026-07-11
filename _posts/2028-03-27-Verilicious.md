---
layout: post
title: "Verilicious"
date: 2028-03-27 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, rsa, bleichenbacher, pkcs1, lattice, lll, hidden-number-problem]
description: "An RSA PKCS#1 v1.5 padding oracle where the accepted multipliers are handed to you. Instead of replaying Bleichenbacher's thousands of queries, recast it as a Hidden Number Problem and recover the plaintext with a single LLL reduction."
---

## Overview

`source.py` RSA-encrypts the flag with PKCS#1 v1.5 padding (1024-bit key, `e=65537`) into
`enc_flag`, then asserts that for each `r` in a set `R` of 78 values,
`verify(r^e · enc_flag mod n)` is truthy. `verify` returns 1 exactly when its argument decrypts
to a PKCS#1 v1.5 **conforming** block (one starting `00 02`). We get `R`, `enc_flag`, and the
public key — a Bleichenbacher padding oracle whose accepted multipliers are already found for us.

## The technique

Because `r^e · enc_flag = (r·m)^e mod n` (where `m` is the padded flag), the assertion says: for
every `r ∈ R`, `r·m mod n` is conforming, i.e.

```
2B ≤ r·m mod n < 3B,   B = 2^(8·(k-2)) = 2^1008   (k = 128 bytes)
```

That's the exact state Bleichenbacher's attack works from. Replaying his interval-narrowing with
`R` in arbitrary order makes the interval set fragment and hang, so there's a cleaner route.

Since `m` is itself a real encryption, it's conforming too: `m = 2.5B + e₀` with `|e₀| < 0.5B`.
Substituting into each sample turns every unknown small — a **Hidden Number Problem**:

```
(2.5B + e₀)·rᵢ ≡ 2.5B + eᵢ   (mod n)
      e₀·rᵢ - eᵢ ≡ 2.5B·(1 - rᵢ)   (mod n),   |e₀|, |eᵢ| < 0.5B
```

## Solution

Build a lattice whose short vector is `(e₀, e₁, …, e_L, -T)` and LLL-reduce it (fpylll, no Sage):

```python
import re
from Crypto.PublicKey import RSA
from fpylll import IntegerMatrix, LLL

n = RSA.import_key(open("pubkey.pem").read()).n
k = (n.bit_length() + 7) // 8
B = 1 << (8 * (k - 2)); center = 5 * B // 2          # 2.5B (exact)
R = eval(re.search(r"R = (\[.*\])", open("output.txt").read(), re.DOTALL).group(1))
L = len(R)

c = [(center * (1 - r)) % n for r in R]; T = B // 2
dim = L + 2
M = IntegerMatrix(dim, dim); M[0, 0] = 1
for i, r in enumerate(R): M[0, 1 + i] = r
for i in range(L):        M[1 + i, 1 + i] = n
for i in range(L):        M[L + 1, 1 + i] = c[i]
M[L + 1, dim - 1] = T
LLL.reduction(M)

for row in range(dim):
    if abs(M[row, dim - 1]) != T: continue
    e0 = (-1 if M[row, dim - 1] == T else 1) * M[row, 0]
    for m in (center + e0, center - e0):
        if 2 * B <= m < 3 * B:
            raw = m.to_bytes(k, "big")
            if raw[:2] == b"\x00\x02":
                print(raw[raw.index(b"\x00", 2) + 1:])   # HTB{...}
```

It runs in seconds and prints the flag `HTB{...}` (redacted here). The flag itself points at the
state of the art — `eprint.iacr.org/2023/032`, the "PKCS#1 v1.5 as an HNP" lattice treatment.

## Why it worked

A padding oracle leaks that `r·m mod n` lands in a narrow known band for each accepted `r`. Enough
such constraints over-determine `m`, and because the deviations from each band's centre are small
relative to `n`, LLL finds them directly — no thousands of interactive queries, no fragile interval
bookkeeping.

## Fix / defense

- Don't use RSA PKCS#1 v1.5 encryption; use OAEP, which exposes no padding-check oracle.
- Never surface any signal (error, timing, or explicit boolean) of whether an RSA decryption's
  padding was valid — a sentinel-based constant-time decrypt still leaks if the caller branches on
  the result.
