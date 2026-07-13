---
layout: post
title: "Twin Oracles"
date: 2028-05-13 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, rsa, lsb-oracle, parity-oracle, blum-blum-shub, prng, binary-search]
description: "An RSA service answers one bit about any decryption you ask for — but a coin decides whether it's the parity bit or the top-half bit. The coin is a Blum-Blum-Shub generator with a public modulus and a 15-bit seed, so you can brute it, predict every flip, and fuse the two oracles into a single clean RSA decryption oracle."
---

## Overview

Twin Oracles is a Hard HackTheBox **Crypto** challenge. An RSA-1024 service will tell you a single bit about the decryption of any ciphertext you submit — but each query a "Chaos Relic" flips a coin to decide whether you get the **parity** bit (`dec(c) % 2`) or the **half** bit (`dec(c) > n/2`). The relic is a Blum-Blum-Shub PRNG whose modulus is printed at startup, so the coin is fully predictable. Predict it, fuse the two oracles into one, and a textbook [LSB oracle](https://cwe.mitre.org/data/definitions/203.html) binary search recovers the flag.

## The technique

Option 1 leaks `n` and `c_flag = FLAG^e mod n`. Option 2 decrypts your ciphertext and returns one bit, chosen by the relic:

```python
class ChaosRelic:                       # Blum-Blum-Shub
    def __init__(self):
        self.M = getPrime(8) * getPrime(8)   # < 65535, PRINTED at startup
        self.x = getPrime(15)                # secret 15-bit seed
    def get_bit(self):
        self.x = pow(self.x, 2, self.M)
        return self.x % 2

# relic bit 0 -> FateSeerWhisper = dec(c) % 2          (parity oracle)
# relic bit 1 -> HighSeerVision  = int(dec(c) > n//2)  (half oracle)
```

You never see the relic bit, and you get 1500 queries per connection.

## Solution

**Step 1 — recover the relic seed.** `M` is public and tiny, so the only unknown is the 15-bit seed (~1700 candidates). Calibrate with a known plaintext whose two oracles disagree: `c = E(3)` decrypts to `3`, so parity is `1` but half is `0`.

```
response == 1  ->  parity fired  ->  relic bit was 0
response == 0  ->  half fired    ->  relic bit was 1
```

Collect ~64 relic bits, then brute the seed offline:

```python
for x0 in range(1 << 14, 1 << 15):
    x = x0; ok = True
    for b in observed:
        x = pow(x, 2, M)
        if x % 2 != b: ok = False; break
    if ok: candidates.append(x0)   # one survivor -> full future trajectory
```

**Step 2 — fuse two oracles into one binary search.** Let `m_k = 2^k · FLAG mod n`. The two oracles are the same comparison bit one doubling apart:

```
half(E(m_i))       = [m_i > n/2]                       = b_i
parity(E(m_{i+1})) = (2·m_i mod n) % 2 = [m_i > n/2]   = b_i
```

So pick the multiplier to match the oracle the relic is about to use:

```
predicted relic bit 1 (half):   submit E(FLAG·2^i)     -> b_i
predicted relic bit 0 (parity): submit E(FLAG·2^{i+1}) -> b_i
```

Every query yields `b_i` regardless of which oracle answers. Feed the bits into standard interval narrowing:

```python
from fractions import Fraction
lo, hi = Fraction(0), Fraction(n)
for i in range(n.bit_length()):
    b = b_i(i)
    mid = (lo + hi) / 2
    if b == 1: lo = mid
    else:      hi = mid
FLAG = int(hi)
```

**Step 3 — pipeline the queries.** The attack ciphertexts depend only on the *predicted* relic bits, never on the responses, so send them all up front and read the answers in bulk. Round-tripping ~1024 times drops the instance connection partway; batching finishes in seconds.

```python
for c in submits:            # all precomputed offline
    io.sendline(b"2"); io.sendline(format(c, "x").encode())
answers = [recv_answer() for _ in submits]
```

## Why it worked

A "random" oracle selector is only random if you can't predict it — and a Blum-Blum-Shub generator with a **published modulus** and a 15-bit seed has a state you can brute in a heartbeat. Once the coin is predictable, the twin oracle is a single RSA decryption oracle. RSA's parity and half oracles are the same bit shifted by one doubling, so scaling the ciphertext converts between them for free, and one leaked bit per query over ~`log2(n)` queries is enough to reconstruct the whole plaintext.

## Fix / defense

- Never expose a decryption oracle: don't return any function of `dec(c)` for attacker-chosen `c`. Use OAEP and reject malformed plaintexts silently.
- Don't drive security-relevant randomness from a PRNG whose parameters you publish — use a CSPRNG with a secret, high-entropy seed.
- Rate-limiting the oracle doesn't save you here: a single bit per query, ~1024 queries, recovers the message.
