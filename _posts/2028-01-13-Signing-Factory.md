---
layout: post
title: "Signing Factory"
date: 2028-01-13 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, rsa, signature-forgery, knuth-hash]
---

## Overview

Signing Factory is a Medium **Crypto** challenge: an RSA token-signing server that "fixed
all previous attacks" by hashing the username before signing it. Logging in as
`System_Administrator` reveals the flag, and that requires a valid RSA signature of the
admin username's hash. We never learn the private key — instead we abuse RSA's
[multiplicative homomorphism](https://cwe.mitre.org/data/definitions/347.html) to forge
the exact signature we need from signatures of other messages.

## The scheme

```python
hash_var = lambda k: (((k % g) * g) >> 32)          # g = 2654435761 (golden ratio)
def sign(u):    return pow(hash_var(u), d, n)        # RSA sign of the hash
def verify(recomputed, token): return recomputed == pow(token, e, n)
# admin login needs: token^e == hash_var(admin)  AND  numeric_username == admin
# registration signs any alphanumeric username but blocks numeric_username % g == admin % g
```

`hash_var` is **Knuth multiplicative hashing** — `floor(0.618 · (k mod g))`. Two useful
observations:

1. It is **non-injective** (`g < 2³²`), so different residues can collide to the same
   hash. But admin's residue turns out to be a *singleton* (no adjacent collision), so you
   can't register a username that hashes to `hash_var(admin)` directly — and registration
   blocks the admin residue anyway.
2. `hash_var(admin)` is a small integer, and small integers **factor**.

## Forging the admin signature

`hash_var(admin) = 1115247629 = 67 × 16645487`. Both factors are small enough to be
reachable hash values from *non-admin* usernames. So:

```
sign(67) · sign(16645487)  ≡  (67 · 16645487)^d  =  hash_var(admin)^d   (mod n)
```

That product **is** a valid admin token — no private key needed. (In general,
`∏ sign(pᵢ)^{eᵢ}` over `factorint(target)`.)

We still need `n` for the modular product — and the server leaks it. Option `[2]` is a
"captcha": for each prime-power factor of `hash_var(n)` it prints `(unknown · rnd) % g`
with `rnd` shown, so `unknown = out · rnd⁻¹ (mod g)`, and the product of the unknowns is
`hash_var(n)`. Submit that and the server hands over `(e, n)`.

To sign a specific value `p`, register a username whose hash is `p`: find a residue
`x` with `floor(0.618·x) == p` (and `x ≠ admin % g`), then meet-in-the-middle a 6-byte
alphanumeric string whose big-endian integer is `x (mod g)`.

## Solution

```python
from sympy import factorint
from Crypto.Util.number import bytes_to_long, inverse

g = 2654435761
target = ((bytes_to_long(b'System_Administrator') % g) * g) >> 32   # 67 * 16645487

# 1. recover n from the option-2 equations:  unknown = out * inverse(rnd, g) % g
hn = 1
for rnd, out in equations:
    hn *= (out * inverse(rnd, g)) % g            # product == hash_var(n)
# submit hn -> server returns (e, n)

# 2. sign(p) for each factor via a collision username, then combine
S = 1
for p, m in factorint(target).items():
    S = (S * pow(sign_value(p), m, n)) % n        # == target^d mod n
assert pow(S, e, n) == target

# 3. log in as System_Administrator with token S -> flag
```

Running it end-to-end recovers `n`, signs `67` and `16645487`, combines them, and logs in:

```console
[+] recovered n (2048 bits) e=65537
[+] signed 67
[+] signed 16645487
[+] forged admin sig ok
FLAG: HTB{...}
```

## Why it worked

Textbook (unpadded) RSA signatures are homomorphic: `sign(a)·sign(b) = sign(a·b)`.
Hashing the message before signing doesn't help when the hash of the privileged message
is a *composite* small integer — you just build its signature out of the signatures of
its factors. Hiding the modulus didn't help either, because a side feature leaked it.

## Fix / defense

Sign `H(m)` under a real scheme — **RSA-PSS** or full-domain hashing — never raw
`m^d`/`hash(m)^d`. A padded, collision-resistant, full-domain hash destroys the
multiplicative structure the forgery depends on.
