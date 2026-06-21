---
title: "Gonna-Lift-Em-All"
date: 2027-01-03 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, elgamal, discrete-log, modular-inverse]
description: "A Very Easy Crypto challenge that ships a textbook ElGamal encryptor with one wrong operator: the ephemeral component is built with multiplication (g*y) instead of exponentiation (g^y). The discrete-log assumption only protects g^y, so a single modular inverse recovers the nonce and decrypts the flag — no DLP, no factoring, no oracle."
---

## Overview

Gonna-Lift-Em-All is a Very Easy [Crypto](https://app.hackthebox.com/challenges) challenge. You get the source of an ElGamal encryptor and a single ciphertext with its public parameters. The encryption looks like textbook ElGamal, but one operator is wrong — the ephemeral component uses **multiplication where it should use exponentiation** — and that single typo collapses the whole scheme to grade-school algebra.

## The technique

ElGamal public-key encryption rests on the [Discrete Logarithm Problem](https://cwe.mitre.org/data/definitions/327.html): given `g`, `p`, and `h = g^x mod p`, recovering the private exponent `x` is infeasible. A correct encryption of a message `m` picks a random nonce `y` and produces:

```
c1 = g^y mod p          # exponentiation — protected by the DLP
s  = h^y mod p          # shared secret = g^(xy)
c2 = m * s mod p
```

This challenge's `encrypt()` had exactly one thing wrong:

```python
def encrypt(pubkey):
    p, g, h = pubkey
    m = bytes_to_long(FLAG)
    y = random.randint(2, p - 2)
    s = pow(h, y, p)
    return (g * y % p, m * s % p)   # c1 = g*y  (multiplication, not g^y)
```

`c1 = g*y mod p` is a **linear product**, not an exponentiation. The DLP only protects `g^y`; a plain product is trivially reversible. So the secret nonce `y` falls out with a single modular inverse, and from there decryption is the standard ElGamal arithmetic:

```
y = c1 * g^{-1} mod p     # recover the ephemeral nonce
s = h^y mod p             # rebuild the shared secret g^(xy)
m = c2 * s^{-1} mod p     # recover the plaintext
```

## Solution

The published parameters (`p`, `g`, `h`) plus the ciphertext `(c1, c2)` are everything we need. Create `solve.py`:

```python
#!/usr/bin/env python3
from Crypto.Util.number import long_to_bytes, inverse

# p, g, h, c1, c2 read verbatim from out.txt (1024-bit values truncated here)
p  = 1639249209942302536379018181884320161682442717396123298575891261133427622801...
g  = 9740767385126814618480426738611529621310653560290873883757310980803322418774...
h  = 7771801879117000288817915415260102060832587957130098985489551063161695391373...
c1 = 8319488766672243530894531642993984166810998519486051888274330989533233052523...
c2 = 4698013982782387270979787652535971856549510554282633505529619589899354971749...

y = c1 * inverse(g, p) % p     # recover ephemeral nonce from g*y
s = pow(h, y, p)               # shared secret h^y = g^(xy)
m = c2 * inverse(s, p) % p     # plaintext
print(long_to_bytes(m).decode())
```

```bash
python3 solve.py
# HTB{...}
```

The flag value is redacted here — and it literally names the lesson: *"the multiplicative group is a dangerous place to be."*

## Why it worked

The entire security argument of ElGamal is that `g^y` is one-way. Replacing `pow(g, y, p)` with `g * y % p` swaps that one-way function for a bijective linear map, so the ciphertext component you publish (`c1`) directly reveals the nonce. Everything downstream — the shared secret `s`, then the message `m` — is ordinary modular arithmetic once `y` is known. This is the generic crypto-implementation failure ([CWE-327](https://cwe.mitre.org/data/definitions/327.html)): a one-way primitive silently downgraded to a reversible one means the secret is recoverable by inversion.

## Fix / defense

- Use a vetted library (PyCryptodome, `cryptography`) for ElGamal/DH — never hand-roll modexp.
- The ephemeral component **must** be `c1 = pow(g, y, p)` — exponentiation, never multiplication.
- Ship known-answer test vectors so an operator swap (`g*y` vs `g^y`) fails CI immediately.
- Prefer authenticated, misuse-resistant schemes (libsodium sealed boxes) over textbook ElGamal.
