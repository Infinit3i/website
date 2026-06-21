---
title: "TwoForOne"
date: 2027-04-07 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, rsa, common-modulus, cwe-323]
description: "An Easy Crypto challenge: Alice sends the same message to Bob twice, encrypted under two RSA public keys that share one modulus but use different exponents. Because the moduli are identical and the exponents are coprime, the plaintext falls out of the extended Euclidean algorithm — no factoring and no private key required."
---

## Overview

TwoForOne is an Easy HackTheBox Crypto challenge. You get two RSA public keys
and two base64 ciphertexts of the *same* message. The keys share an identical
modulus `n` but use different public exponents — the textbook setup for the
**RSA common-modulus attack**, which recovers the plaintext without factoring
`n` and without either private key.

## The technique

The prompt — *"Alice sent two times the same message to Bob"* — is the whole
hint. Reading the two keys:

```
key1: n = 2508035685…0433687   e = 65537
key2: n = 2508035685…0433687   e = 343223   # SAME n
```

Same modulus, two different exponents, one plaintext. That is a
[common-modulus / key-reuse weakness](https://cwe.mitre.org/data/definitions/323.html)
([CWE-323](https://cwe.mitre.org/data/definitions/323.html)). With

```
c1 = m^e1 mod n
c2 = m^e2 mod n
```

and `gcd(e1, e2) == 1`, the Extended Euclidean Algorithm yields integers
`a, b` such that `a*e1 + b*e2 = 1`. Then:

```
c1^a * c2^b = m^(a*e1) * m^(b*e2) = m^(a*e1 + b*e2) = m^1 = m   (mod n)
```

One of `a, b` is always negative, so that ciphertext is replaced by its modular
inverse before exponentiation (Python's three-argument `pow` accepts a negative
exponent directly).

## Solution

Always diff the two moduli first — once they match, the attack is mechanical.
The ciphertexts are base64, so decode them before converting to integers.

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, base64
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes

d = sys.argv[1] if len(sys.argv) > 1 else "."
k1 = RSA.importKey(open(f"{d}/key1.pem", "rb").read())
k2 = RSA.importKey(open(f"{d}/key2.pem", "rb").read())
assert k1.n == k2.n
n, e1, e2 = k1.n, k1.e, k2.e
c1 = int.from_bytes(base64.b64decode(open(f"{d}/message1", "rb").read()), "big")
c2 = int.from_bytes(base64.b64decode(open(f"{d}/message2", "rb").read()), "big")

def egcd(x, y):
    if y == 0:
        return (x, 1, 0)
    g, p, q = egcd(y, x % y)
    return (g, q, p - (x // y) * q)

g, a, b = egcd(e1, e2)
assert g == 1

def powmod(c, x, n):
    if x < 0:
        c = pow(c, -1, n); x = -x
    return pow(c, x, n)

m = (powmod(c1, a, n) * powmod(c2, b, n)) % n
print(long_to_bytes(m).decode(errors="replace"))
```

Run it against the unzipped challenge files:

```bash
python3 solve.py ./files
```

It prints the flag, `HTB{...}`.

## Why it worked

RSA's security rests on factoring `n` being hard, but the common-modulus attack
sidesteps factoring entirely: it only uses the exponent relationship. Reusing a
modulus across keys is independently catastrophic — any single holder of a
private key can factor `n` from their own `d` and recover everyone else's key
too. Here we did not even need a private key; the exponent algebra alone
returned the plaintext.

## Fix / defense

- **Never reuse a modulus across keypairs.** Every RSA key gets its own freshly
  generated `n`.
- **Don't encrypt the same plaintext under multiple keys.** Use a random
  per-message session key.
- **Use RSA-OAEP**, so identical plaintexts produce unrelated ciphertexts and
  the deterministic structure these attacks rely on disappears.
