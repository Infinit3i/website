---
layout: post
title: "baby quick maffs"
date: 2027-07-12 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, rabin, related-messages-attack, cwe-327, number-theory, modular-arithmetic]
---

## Overview

baby quick maffs is an HTB Crypto challenge (Easy) built around a custom Rabin cryptosystem variant. The description hints at Rabin's security proof — it holds against chosen-plaintext attacks as long as factoring is hard — but the implementation encrypts algebraically related plaintexts under the same modulus. That leaks enough to recover the flag with a single modular inverse, no factoring required. This is a classic [use of a broken or risky cryptographic algorithm (CWE-327)](https://cwe.mitre.org/data/definitions/327.html) in the form of a **related-messages attack**.

---

## Source Analysis

`source.py` partitions the flag integer `m` into chunks and Rabin-encrypts each one:

```python
def partition_message(m, N):
    m1 = randint(1, N)
    parts = []
    remainder = 0
    while sum(parts) < m:
        if sum(parts) + m1 < m:
            parts.append(m1)
        else:
            remainder = m - sum(parts)
            parts.append(m1 + remainder)
    return (parts, remainder)

def encode(message, N):
    m = bytes_to_long(message)
    parts, remainder = partition_message(m, N)
    ciphers = [pow(c, 2, N) for c in parts]
    return (ciphers, remainder)
```

`output.txt` contains three values:

- `N` — the Rabin modulus (p × q, not factored)
- `remainder` — the leftover from the partition loop
- `ciphers` — a list of three Rabin ciphertexts

The output for this challenge has **two identical ciphertexts** and one different one. That's the tell.

---

## The Technique

Tracing the partition loop with three output ciphers reveals the chunk structure:

| Iteration | Condition | Chunk appended |
|---|---|---|
| 1 | `0 + m1 < m` | `m1` |
| 2 | `m1 + m1 < m` | `m1` |
| 3 | `2·m1 + m1 ≥ m` | `m1 + remainder` where `remainder = m − 2·m1` |

So the three chunks are `[m1, m1, m1 + r]` where `r = m − 2·m1`, and Rabin-encrypting gives:

```
c0 = m1²          mod N   (ciphers[0] == ciphers[1], same chunk)
c2 = (m1 + r)²   mod N   (ciphers[2], different)
```

Both `r` and `N` are in the output file. Expanding the difference of squares:

```
c2 − c0 = (m1 + r)² − m1²  =  r² + 2·r·m1   (mod N)
```

Isolating `m1`:

```
m1 = (c2 − c0 − r²) · modinverse(2·r, N)   mod N
```

Recovering the flag:

```
m = 2·m1 + r
flag = long_to_bytes(m)
```

One modular inverse. No factoring. No oracle.

---

## Solution

`solve.py`:

```python
#!/usr/bin/env python3
from Crypto.Util.number import long_to_bytes

N = 6083782486455360611313889289556658208725888944237734041722591252756006664878102248734673207367745303402874595854966731263105387801996693270011840173939423
r = 1081087287982224274239399953615475281184099226198643053396569433856757255106426461817760194704250226883807897800355728788149068771546876055268915238961343
ciphers = [
    5408283916250636369066846815501131861319520431106165986129813106223074286810632222888292034380612581416458756909119954039579666773680866532576166358987272,
    5408283916250636369066846815501131861319520431106165986129813106223074286810632222888292034380612581416458756909119954039579666773680866532576166358987272,
    5598555010250184271123226314796180406367795504188162611960100902143581636125416986623404842897202277277978566659455918773104687212096435095590205751904580,
]

c0, c2 = ciphers[0], ciphers[2]
m1 = ((c2 - c0 - r*r) * pow(2*r, -1, N)) % N
m  = (2 * m1 + r) % N
print(long_to_bytes(m).decode())
```

Running it yields the flag (`HTB{...}`).

---

## Why It Worked

Rabin's security proof requires each plaintext to be independently and uniformly random before squaring. The partition scheme here reuses the same random value `m1` in multiple chunks, then outputs the offset `r = m − 2·m1` directly. That's a linear equation with one unknown (`m1`) and one known coefficient (`2·r`) modulo `N`. As long as `gcd(2·r, N) = 1` — which holds unless `r` happens to share a factor with `p` or `q` — the inverse exists and the equation solves in O(1).

The Rabin/RSA squaring operation is [homomorphic](https://cwe.mitre.org/data/definitions/327.html): `(m1+r)² − m1² ≡ r² + 2·r·m1`, so the offset between two related squares leaks a linear function of the shared random value. This is the textbook Franklin–Reiter related-message attack, generalized to Rabin.

---

## Fix / Defense

- **Use OAEP or PKCS#1 v1.5 padding.** These bind independent randomness to each encryption, so even if the underlying plaintexts are related, the padded values are not. `Crypto.Cipher.PKCS1_OAEP` in Python is one import away.
- **Never partition a message into chunks that share a common random addend.** Each chunk must be independently and uniformly sampled before squaring.
- **Prefer modern hybrid encryption** (RSA/OAEP + AES-GCM) over raw Rabin squaring. Rabin is provably CPA-secure, but "CPA-secure" does not mean "safe when you encrypt related messages."
