---
layout: post
title: "Colliding Heritage"
date: 2028-03-08 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, schnorr, md5, hash-collision, nonce-reuse, signature-forgery]
description: "A Schnorr signature whose per-message nonce is derived with MD5. Two MD5-colliding messages reuse the nonce, that leaks the private key, and the key forges the one signature the server refuses to make."
---

## Overview

Colliding Heritage is a Medium crypto challenge built on a home-grown "MD5chnorr"
signature. The server signs messages for you but refuses the one message you need, and
prints the flag only when you present a *valid* signature for it. The path there:
derive the nonce with a broken hash, force a **nonce collision** with a public MD5
collision pair, recover the private key, and forge the signature.

## The technique

The scheme is Schnorr over a 128-bit safe prime `p = 2q+1`, `g = 3`, private key `x`,
public key `y = g^x mod p`, with `H(m) = md5(m) mod q`. Signing derives the nonce
**deterministically from the message and the secret**:

```python
k = H(msg + long_to_bytes(x))
r = pow(g, k, p) % q
e = H(long_to_bytes(r) + msg)
s = (k - x*e) % q
```

Deterministic nonces (RFC 6979) are safe *only with a collision-resistant hash*. MD5 is
not. Because MD5 is Merkle–Damgård, any identical-prefix, **equal-length** collision pair
`M1 ≠ M2` with `md5(M1) == md5(M2)` also satisfies `md5(M1‖x) == md5(M2‖x)` — the collision
survives appending the secret suffix `x`. So signing `M1` and `M2` uses the **same nonce
k**, and [nonce reuse](https://cwe.mitre.org/data/definitions/347.html) in Schnorr leaks
the key:

```
s1 = k - x·e1        s2 = k - x·e2
x = (s1 - s2) · (e2 - e1)⁻¹ mod q
```

I used the classic **Wang 128-byte MD5 collision pair** — equal length, same digest, and
neither half contains the blocked message — so no `fastcoll`/`hashclash` run was needed.

## Solution

The server offers three operations and blocks `Sign` on `I am the left hand`, so the plan
is `Sign(M1)`, `Sign(M2)`, then forge and `Verify(target)` — exactly three.

Create `solve.py`:

```python
#!/usr/bin/python3
import sys, re
from hashlib import md5
from pwn import remote, context
from Crypto.Util.number import long_to_bytes, bytes_to_long

context.log_level = "error"
HOST, PORT = sys.argv[1], int(sys.argv[2])
TARGET = b"I am the left hand"

# Wang et al. MD5 collision pair (128 bytes each, identical MD5)
M1 = bytes.fromhex(
 "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89"
 "55ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b"
 "d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0"
 "e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70")
M2 = bytes.fromhex(
 "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89"
 "55ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b"
 "d8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0"
 "e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70")
assert md5(M1).digest() == md5(M2).digest() and M1 != M2

io = remote(HOST, PORT)
def readint(tag):
    io.recvuntil(tag); return int(io.recvline().strip())
g, y, p = readint(b"g:"), readint(b"y:"), readint(b"p:")
q = (p - 1) // 2

def sign(msg):
    io.recvuntil(b"> "); io.sendline(b"S")
    io.recvuntil(b"message> "); io.sendline(msg.hex().encode())
    line = io.recvline_contains(b"Signature").decode()
    s, e = re.search(r"\((\d+),\s*(\d+)\)", line).groups()
    return int(s), int(e)

s1, e1 = sign(M1)
s2, e2 = sign(M2)                       # same nonce k
x = (s1 - s2) * pow(e2 - e1, -1, q) % q
assert pow(g, x, p) == y

def H(m): return bytes_to_long(md5(m).digest()) % q
k = H(TARGET + long_to_bytes(x))        # re-run the real sign() locally
r = pow(g, k, p) % q
e = H(long_to_bytes(r) + TARGET)
s = (k - x * e) % q

io.recvuntil(b"> "); io.sendline(b"V")
io.recvuntil(b"message> "); io.sendline(TARGET.hex().encode())
io.recvuntil(b"s> "); io.sendline(str(s).encode())
io.recvuntil(b"e> "); io.sendline(str(e).encode())
print(io.recvall(timeout=5).decode())
```

```bash
python3 solve.py <host> <port>
```

The two signatures come back with the same underlying nonce, `x` drops straight out of the
linear equation (verified against `y`), the forged signature validates, and the server
returns the flag:

```
HTB{...}
```

## Why it worked

The nonce was a deterministic function of the message under a collision-broken hash, so
two attacker-chosen colliding messages collapsed to a single nonce. Schnorr — like DSA and
ECDSA — reveals the private key the instant a nonce is reused across two signatures. Once
`x` is known, the signer's substring blocklist is meaningless: you sign anything you want.

## Fix / defense

- Derive nonces via **RFC 6979 with SHA-256/512**, never MD5/SHA-1; or use a per-signature
  CSPRNG nonce, or a scheme like **Ed25519** that binds the nonce to `SHA-512(key ‖ msg)`.
- Never let attacker-influenced messages flow into `k = H(msg ‖ secret)` with a weak `H` —
  collisions transfer through the appended secret.
- Treat signer-side content filters as non-security; key recovery bypasses them entirely.
