---
title: "Optimus Prime"
date: 2027-04-12 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, rsa, shared-prime, gcd, cwe-326]
description: "An Easy Crypto challenge whose access panel hands you a fresh 4095-bit RSA modulus on every single connection — and quietly reuses one of its two primes each time. Connect twice, take the GCD of the two moduli, and Euclid factors a key no one could ever factor head-on."
---

## Overview

Optimus Prime is an Easy HackTheBox **Crypto** challenge — a container-based `nc` service styled as a Transformer control panel. Its "access panel" prints a 4095-bit RSA public key and an RSA-encrypted login password, then asks you to type the password back. The modulus is far too large to factor, but it changes on every connection while reusing one secret prime — a [use of a broken/risky key generation scheme](https://cwe.mitre.org/data/definitions/326.html) that collapses instantly to Euclid's GCD.

## The technique

Connecting to the service shows a four-item menu. Options 1–3 are decoys (status fluff, random "Serial IDs", and a register option gated behind login). Option **4 — "Enter to the access panel"** is the whole challenge. On *every* connection it prints:

```
PUBLIC KEY: <a 4095-bit integer N>
ENCRYPTED PASSWORD: <a 4095-bit integer c>
The private key has been sent to your email. Please use it to proceed:
```

So it is textbook RSA with `e = 65537`: `N` is the modulus, `c` is the login password encrypted under it. Type the right password at the prompt and the panel grants access — and prints the flag.

`N` is 4095 bits, which is unfactorable head-on. But reconnect and you get a **different** `N` every time. That is the tell. The key generator fixes one prime `p` and only regenerates the second prime `q` per session:

```
N_1 = p * q_1
N_2 = p * q_2     # same p
```

Two integers that share a factor surrender it to Euclid's algorithm in microseconds — no factoring of the giant modulus required:

```
gcd(N_1, N_2) = p
```

This is distinct from the RSA common-modulus attack, where the modulus is *byte-for-byte identical* across two ciphertexts with different exponents. Here the moduli **differ** but **share one prime** — so always GCD the moduli first.

## Solution

Collect two moduli from two connections, GCD them for the shared prime, then it is plain RSA: `q = N/p`, `phi = (p-1)(q-1)`, `d = e⁻¹ mod phi`, decrypt, and send the password back on the same socket that issued it.

`solve.py`:

```python
from pwn import *
from math import gcd

HOST, PORT = "<rhost>", "<port>"
E = 65537

def get_panel(r):
    r.recvuntil(b"option: "); r.sendline(b"4")
    r.recvuntil(b"PUBLIC KEY: ");          N = int(r.recvline().strip())
    r.recvuntil(b"ENCRYPTED PASSWORD: ");  c = int(r.recvline().strip())
    return N, c

# 1) Two connections -> shared prime via gcd
r1 = remote(HOST, PORT); N1, _  = get_panel(r1)
r2 = remote(HOST, PORT); N2, c2 = get_panel(r2)
p = gcd(N1, N2)                       # = the reused prime, instantly

# 2) Factor N2, derive d, decrypt THIS session's password
q  = N2 // p
d  = pow(E, -1, (p - 1) * (q - 1))
m  = pow(c2, d, N2)
pw = m.to_bytes((m.bit_length() + 7) // 8, "big")

# 3) Hand the password back on the SAME connection that issued c2
r2.recvuntil(b"proceed: "); r2.sendline(pw)
print(r2.recvrepeat(3).decode())     # ACCESS GRANTED: HTB{...}
```

Running it:

```
ACCESS GRANTED: HTB{...}
```

The decrypted password changes per session (different `c` under different `N`), so you must decrypt and reply on the **same** socket that handed you that `c` — which is why the script keeps `r2` open and answers its prompt directly. The flag name itself nods to the man behind the GCD: *Euclid*.

## Why it worked

The fatal mistake is server-side key generation that does not draw both primes fresh. Sharing a prime across keys means any two public moduli betray that prime to a single GCD — a 4095-bit "unbreakable" modulus falls in microseconds. This is not just a CTF gimmick: Bernstein's **batch-GCD** famously factored roughly 0.2% of real-world TLS and SSH keys whose primes collided because of low-entropy randomness at boot.

## Fix / defense

```python
# both primes fresh from a properly seeded CSPRNG, per key
p = getPrime(2048)
q = getPrime(2048)      # never a fixed or pooled prime
n = p * q
```

- Seed key generation with sufficient entropy; never generate keys before the entropy pool is ready.
- Use a vetted library's `RSA.generate(n)` per key — never hand-roll a "static prime, fresh q" scheme.
- Run a batch-GCD self-audit across all issued moduli to catch accidental prime collisions early.
