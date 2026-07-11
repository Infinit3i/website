---
layout: post
title: "Curveware"
date: 2028-04-15 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, ecdsa, secp256r1, hidden-number-problem, lattice, lll, fpylll, nonce-leak, ransomware, cwe-330, cwe-323]
description: "A ransomware signs every file it encrypts with a custom ECDSA-like scheme, then leaks 40 bits of each signing nonce in the file extension and reuses the AES key as the signing private key — turning a partial-nonce Hidden Number Problem into full file recovery with one LLL reduction."
---

## Overview

Curveware is a Hard HackTheBox Crypto challenge. You are handed a Windows PE ransomware (built on `libecc` and `tiny-AES-c`) and a folder of files it encrypted, each renamed `<name>.vlny<10 hex>`. Decompiling the sample shows it does two things to every file: it encrypts the contents with AES-CBC, and it *signs* the result with a home-grown ECDSA-like scheme on `secp256r1`. Two design mistakes — a 40-bit nonce leak baked into the filename, and reuse of the AES key as the signing private key — let you recover the key with a single lattice reduction and decrypt the flag. The weakness class is [CWE-330](https://cwe.mitre.org/data/definitions/330.html) (insufficiently random / partially disclosed values) compounded by [CWE-323](https://cwe.mitre.org/data/definitions/323.html) (reusing one key across two purposes).

## The technique

Each encrypted file is laid out as:

```
[ 64-byte signature r||s ] [ AES-CBC ciphertext ] [ 16-byte IV ]
```

The decompiled `sign_data` implements a custom signature over `secp256r1`:

```
k = SHA256(plaintext)        # the per-file nonce
h = SHA256(ciphertext)
r = h - (G*k).x   (mod q)
s = x^-1 * (k - r) (mod q)   # x is the signing private key
```

Two fatal choices make this trivially breakable:

1. **The AES encryption key *is* the signing private key `x`.** Recover `x` from the signatures and you also hold the decryption key — a [CWE-323](https://cwe.mitre.org/data/definitions/323.html) key-reuse-across-roles failure.
2. **The `.vlny<10 hex>` extension is the last 5 bytes of the nonce `k`.** That leaks the low 40 bits of a value that must remain entirely secret — a partial-nonce disclosure, [CWE-330](https://cwe.mitre.org/data/definitions/330.html).

Writing each nonce as `k_i = 2^40 * A_i + L_i` (with `L_i` the leaked low 40 bits and `A_i` the 216 unknown high bits) and substituting into the `s` relation rearranges to:

```
A_i - x*(2^-40 * s_i) + 2^-40 * (L_i - r_i) = 0   (mod q)
```

That is exactly the **Hidden Number Problem**: many equations in one shared secret `x` with small unknowns `A_i`. With 18 signed files as samples, an LLL reduction recovers the `A_i` and hence `x`.

## Solution

The official solver uses SageMath's rational lattice. Kali has no Sage, so the trick is that **LLL is invariant under scaling the whole basis by a constant** — multiply the rational matrix by `kW = next_prime(2^216)` to clear denominators and run it as an *integer* lattice through `fpylll`. The shortest nonzero row's entries are then the `A_i` directly.

```python
#!/usr/bin/env python3
# Curveware (HTB Business CTF 2025, crypto, Hard) — partial-nonce HNP + LLL private-key recovery.
#
# Ransomware signs each encrypted file with a custom ECDSA-like scheme on secp256r1:
#   r = h - [G*k].x   (mod q)      h = SHA256(ciphertext)
#   s = x^-1 * (k - r) (mod q)      x = AES key = signing private key, k = SHA256(plaintext) = nonce
# The .vlny<10hex> extension leaks the LOW 40 bits (last 5 bytes) of the nonce k.
# Rearranged:  A_i - x*(2^-40 s_i) + 2^-40 (L_i - r_i) = 0 (mod q), with k_i = 2^40 A_i + L_i, A_i ~216 bits.
# 18 samples -> HNP lattice -> LLL -> recover x -> AES-CBC decrypt.
import os, glob
from fpylll import IntegerMatrix, LLL
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

REPO = '/home/kali/htb/chal-curveware/files/crypto_curveware/business-ctf-2025-dev'
q = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
LS = 16**10                       # 2^40 : leaked low bits scale

R, S, LEAKS = [], [], []
for root, _, files in os.walk(REPO):
    for f in files:
        if '.vlny' not in f:
            continue
        sig = open(os.path.join(root, f), 'rb').read()[:0x40]
        R.append(int(sig[0x00:0x20].hex(), 16))
        S.append(int(sig[0x20:0x40].hex(), 16))
        LEAKS.append(int(f.split('.vlny')[1], 16))

nsamp = len(LEAKS)
print(f'[+] samples: {nsamp}')

inv_ls = pow(LS, -1, q)
# Rational writeup lattice scaled by kW (~2^216) => integer, LLL-invariant.
# rows: n x n diag(q); row (s_i*inv_ls mod q); row ((r_i-L_i)*inv_ls mod q). shortest row -> (A_i).
rows = []
for i in range(nsamp):
    rows.append([q if j == i else 0 for j in range(nsamp)])
rows.append([(S[i] * inv_ls) % q for i in range(nsamp)])
rows.append([((R[i] - LEAKS[i]) * inv_ls) % q for i in range(nsamp)])

M = IntegerMatrix.from_matrix(rows)
LLL.reduction(M)

x = None
for r in range(M.nrows):
    a0 = M[r][0]
    if a0 == 0:
        continue
    A0 = abs(a0)
    k0 = LS * A0 + LEAKS[0]
    cand = (pow(S[0], -1, q) * (k0 - R[0])) % q
    # verify against another sample's leaked low bits
    ok = True
    for i in range(min(nsamp, 6)):
        ki = (S[i] * cand + R[i]) % q
        if ki % LS != LEAKS[i]:
            ok = False
            break
    if ok:
        x = cand
        break

if x is None:
    raise SystemExit('[-] key recovery failed')
print(f'[+] private key x = {x:064x}')

key = x.to_bytes(32, 'big')
data = open(glob.glob(f'{REPO}/crypto/curveware/flag.txt*')[0], 'rb').read()
enc, iv = data[0x40:-0x10], data[-0x10:]
flag = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(enc), 16)
print('[+] FLAG:', flag.decode())
```

Running it recovers the private key, verifies it against 6 samples' leaked bits, and AES-CBC-decrypts the flag file — printing `HTB{...}` (redacted here).

## Why it worked

Any partial exposure of an (EC)DSA nonce is fatal: the signing equation is linear in the unknown private key and the unknown nonce bits, so a lattice recovers the key from a handful of signatures — 40 bits out of 256 (~15%) is far more than enough. The nonce must be treated as exactly as secret as the private key. The second blunder — deriving the nonce from an observable and reusing the symmetric key as the asymmetric secret — is what escalated a signature break into full plaintext recovery.

## Fix / defense

- Generate signing nonces from a CSPRNG (or deterministically per RFC 6979) and **never** leak any bits of them — the filename tag here should have been random or omitted entirely.
- **Never reuse one secret across cryptographic roles.** A file-encryption key and a signing key must be independent, so that compromising one does not hand over the other.
