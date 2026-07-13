---
layout: post
title: "Vitrium Stash"
date: 2028-05-13 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, dsa, signature-forgery, lattice, cvp, cwe-347]
description: "A DSA panel forgets to hash the message before signing, so anyone with the public key can existentially forge a signature — and a lattice fits a real admin:true JSON to the forged value."
---

## Overview

Vitrium Stash is a **Hard** HackTheBox **Crypto** challenge. A storage panel signs account records with DSA and hands over the stash coordinates to anyone who submits a valid signature over a message with `admin: true`. The panel only ever signs `admin: false`, so the whole challenge is to produce a valid signature for a privileged message without the private key. The break: the server signs the **raw message integer**, not its hash, which enables a textbook existential forgery. A [Closest Vector Problem](https://cwe.mitre.org/data/definitions/347.html) then converts the forged value into a syntactically valid admin JSON.

## The technique

Standard DSA signs `H(message)`. This server signs the message bytes directly and does every operation modulo `q`:

```python
def sign(message):
    m = bytes_to_long(message)          # NO hash
    k = randbelow(p)
    r = pow(g, k, p) % q
    s = (inverse(k, q) * (m + x*r)) % q
    return r, s
```

Because the message is never hashed and verification only depends on `m mod q`, the signature scheme has no [improper verification of cryptographic signature](https://cwe.mitre.org/data/definitions/347.html) protection — an attacker with only the public key `y = g^x mod p` can forge (HAC Note 11.66). Pick random `u, v` with `v` invertible mod `q`:

```
r = (g^u · y^v mod p) mod q
s = r · v⁻¹ mod q
m ≡ u · s   (mod q)
```

Verification recovers `u1 = m·s⁻¹ = u` and `u2 = r·s⁻¹ = v`, so `g^u1·y^u2 = g^u·y^v`, which reduces back to `r`. The signature is valid and the private key `x` was never needed.

The catch: `m` is an **output** of the forgery, not something we choose. But verification only checks `m mod q`, and we author the message we submit. So the task becomes: craft an `admin:true` JSON whose `bytes_to_long` is congruent to the forged `m` modulo `q`.

The server reads the message with `input().encode()`, so the pad bytes must be printable ASCII (UTF-8/JSON safe). Writing `m` as raw big-endian bytes fails — a value below `2^224` has zero high bytes (control characters), and bytes `0x80`–`0xff` are invalid UTF-8. Instead, model each pad byte as `0x4f + eᵢ` and solve

```
Σ eᵢ · wᵢ ≡ Rr  (mod q),   small eᵢ,   wᵢ = 256^{position} mod q
```

for a **small** integer vector — a Closest Vector Problem on the kernel lattice `{ z : Σ zᵢ wᵢ ≡ 0 (mod q) }`. With 40 pad bytes (~260 bits of freedom over a 224-bit `q`), an exact `fpylll` CVP returns `|eᵢ| ≤ 31`, comfortably inside the printable range `[-47, 47]`.

## Solution

Query option `0` for the public key, forge, then submit `(r, s, message)` to option `2`.

Create `padsolve.py` (the CVP pad-fitter):

```python
from Crypto.Util.number import bytes_to_long, inverse
from fpylll import IntegerMatrix, LLL, CVP

ALO, AHI = 0x20, 0x7e
CENTER = (ALO + AHI) // 2
EMIN, EMAX = ALO - CENTER, AHI - CENTER

def solve_pad(prefix, suffix, target, q, N=40):
    off = len(suffix)
    w = [pow(256, (N - 1 - i) + off, q) for i in range(N)]
    base = (bytes_to_long(prefix) * pow(256, N + off, q)
            + CENTER * sum(w) + bytes_to_long(suffix)) % q
    Rr = (target - base) % q
    inv0 = inverse(w[0], q)
    B = IntegerMatrix(N, N)
    B[0, 0] = q
    for i in range(1, N):
        B[i, 0] = (-w[i] * inv0) % q
        B[i, i] = 1
    LLL.reduction(B)
    c = [0] * N
    c[0] = Rr * inv0 % q
    closest = CVP.closest_vector(B, c)
    e = [c[i] - closest[i] for i in range(N)]
    if not all(EMIN <= ev <= EMAX for ev in e):
        return None
    pad = bytes(CENTER + ev for ev in e)
    msg = prefix + pad + suffix
    if bytes_to_long(msg) % q != target % q:
        return None
    if any(b == 0x22 or b == 0x5c or b < 0x20 or b > 0x7e for b in pad):
        return None
    return msg
```

Create `solve.py` (forge + submit):

```python
import socket, json, sys, random
from Crypto.Util.number import bytes_to_long, inverse
from padsolve import solve_pad

HOST, PORT = sys.argv[1], int(sys.argv[2])
s = socket.socket(); s.settimeout(15); s.connect((HOST, PORT))

def recv_until(tok=b"> "):
    buf = b""
    while tok not in buf:
        d = s.recv(4096)
        if not d: break
        buf += d
    return buf

recv_until(); s.sendall(b"0\n")
pk = json.loads([l for l in recv_until().split(b"\n") if l.strip().startswith(b"{")][0])
p, q, g, y = pk["p"], pk["q"], pk["g"], pk["y"]

def forge():
    v = random.randrange(2, q); u = random.randrange(2, q)
    r = pow(g, u, p) * pow(y, v, p) % p % q
    s_ = r * inverse(v, q) % q
    return r, s_, u * s_ % q

suffix = b'"}'
msg = r = sig = None
for _ in range(200):
    r, sig, m = forge()
    for fl in range(1, 40):
        prefix = b'{"admin": true, "z": "' + b'x' * fl + b' '
        cand = solve_pad(prefix, suffix, m, q)
        if cand is not None:
            msg = cand; break
    if msg is not None: break

s.sendall(b"2\n"); recv_until(b"r > "); s.sendall(str(r).encode() + b"\n")
recv_until(b"s > "); s.sendall(str(sig).encode() + b"\n")
recv_until(b"message > "); s.sendall(msg + b"\n")
print(recv_until(b"\n").decode(errors="replace"))
```

Run it against the instance and the panel prints the stash coordinates:

```
Hello admin! Here are the coordinates to your vitalium stash: HTB{...}
```

## Why it worked

Skipping the hash strips the signature of preimage resistance. Verification collapses to an equation over `m mod q`, and the HAC existential forgery produces valid `(r, s)` pairs for attacker-derived residues using only the public key. Because we also control the exact message bytes, a lattice reduction bridges the gap from "some forged residue" to "a well-formed message that says `admin: true`."

## Fix / defense

Hash the message before signing and verifying (`m = SHA-256(message)`) — a preimage-resistant hash makes it infeasible to craft a message matching a forged residue. Sign a canonical, server-built structure and bind privileged claims inside the signed data rather than over attacker-tunable raw bytes, and prefer vetted signature libraries that hash and enforce the DSA rules for you. This is [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html).
