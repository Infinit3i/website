---
layout: post
title: "Hash the Filesystem"
date: 2028-04-05 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, aes-ctr, bit-flipping, python-hash, second-preimage, cwe-353, cwe-330]
description: "A file server that names files by hash(passphrase) and hands out AES-CTR identity tokens. Two bugs chain: CTR without a MAC lets you bit-flip your token to become admin, and CPython's tuple hash is deterministic and invertible, so you forge a passphrase that matches admin's filename and read the flag."
---

## Overview

Hash the Filesystem is a Hard HackTheBox Crypto challenge. A "secret file server" stores each uploaded file under a name derived from `hash(passphrase)` and gives every connecting user an AES-CTR-encrypted identity token. The flag lives in the admin's files. Two independent weaknesses chain to read them: the token uses a stream cipher with no integrity, and the filename hash uses CPython's non-cryptographic, deterministic, **invertible** tuple hash. Neither is one-way, and together they collapse the whole authorization model. This is [CWE-353](https://cwe.mitre.org/data/definitions/353.html) (missing integrity check) plus [CWE-330](https://cwe.mitre.org/data/definitions/330.html) (predictable value used as a capability).

## The technique

The server (`server.py`) exposes upload / list / download. Every operation decrypts your token to read `token['username']` and then indexes `file_record[username]`. To read the admin's files you need two things: make the server believe you are `admin`, and supply a passphrase whose filename-hash matches one of admin's filenames.

**Bug 1 — AES-CTR is malleable.** CTR is a stream cipher: `ciphertext = plaintext XOR keystream`. The token plaintext is `json.dumps({"username": user, ...})`, and the prefix `{"username": "` is a fixed 14 bytes, so the plaintext at the username offset is fully known. Recover the keystream there and re-target it — no key required. Because CTR flips are surgical (unlike CBC bit-flipping, there is no sacrificial garbled block), the rest of the token stays valid JSON.

**Bug 2 — CPython's tuple/int hash is deterministic and invertible.** `PYTHONHASHSEED` randomizes only `str`/`bytes` hashing; `hash(int)` and `hash(tuple)` are reproducible across runs and machines. The xxHash-based `tuplehash` (Objects/tupleobject.c, Python 3.8+) is a chain of operations that are all invertible mod 2^64 — multiply by odd primes, rotate, add. So a filename `hex(hash(tuple(passphrase)))` is a second-preimage you can compute offline.

## Solution

The solve forges an admin token, lists admin's filenames, inverts the hash for one of them, and downloads it.

Reimplement and invert the tuple hash (verified byte-for-byte against the real `hash()`):

```python
MASK = (1 << 64) - 1
P1 = 11400714785074694791
P2 = 14029467366897019727
P5 = 2870177450012600261
PHASH = (1 << 61) - 1
rotl = lambda x, r=31: ((x << r) | (x >> (64 - r))) & MASK
rotr = lambda x, r=31: ((x >> r) | (x << (64 - r))) & MASK
IP1, IP2 = pow(P1, -1, 1 << 64), pow(P2, -1, 1 << 64)

def int_hash(n):
    s = 1 if n >= 0 else -1
    h = (abs(n) % PHASH) * s
    return -2 if h == -1 else h

def find_passphrase(target_signed):
    target_u = target_signed & MASK
    final_add = (2 ^ (P5 ^ 3527539)) & MASK
    for el1 in range(4096):
        acc1 = (rotl((P5 + (int_hash(el1) & MASK) * P2) & MASK) * P1) & MASK
        pre = rotr((((target_u - final_add) & MASK) * IP1) & MASK)
        lane2 = ((pre - acc1) * IP2) & MASK
        s = lane2 - (1 << 64) if lane2 >= (1 << 63) else lane2
        if abs(s) < PHASH and s != -1:
            return [el1, s]
```

Drive the server: forge the admin token by bit-flipping the username field, then download.

```python
USER = "aaaaa"              # same length as "admin"
off = 14                    # len('{"username": "')
forged = bytearray(ct)      # ct = token ciphertext from the server
target = b"admin"
for i in range(len(USER)):
    ks = ct[off + i] ^ ord(USER[i])
    forged[off + i] = ks ^ target[i]
# option 2 with forged token -> admin filenames
# for each filename: find_passphrase(int(fname,16)) -> passphrase
# option 3 with forged token + passphrase -> file content -> HTB{...}
```

Running the full `solve.py` against the live instance lists five admin files, inverts each hash to a two-element passphrase, and one of them returns the flag:

```
HTB{...}
```

Flag value redacted.

## Why it worked

The developer treated `hash()` as a one-way, unguessable filename generator and raw AES-CTR as a tamper-proof identity token. Neither assumption holds. Integer and tuple hashing in CPython is a deterministic, algebraically invertible mixing function — not a cryptographic digest — so the filename is a computable second-preimage. And CTR without a MAC lets an attacker rewrite any known-plaintext byte of the token. Identity was carried in a client-decryptable, malleable blob, and the "unguessable" capability was a reversible hash; either bug alone breaks the model.

## Fix / defense

- **Token integrity:** use authenticated encryption (AES-GCM / ChaCha20-Poly1305) or Encrypt-then-MAC, and verify before trusting any decrypted field. Raw CTR/CBC handed to a client is attacker-writable.
- **Never use `hash()` as a security primitive.** Use `secrets.token_hex()` for opaque filenames, or a keyed MAC (`hmac.new(server_key, passphrase, sha256)`) when the name must derive from input.
- **Authorize server-side.** Access control must not depend on a client-decryptable username field or on knowledge of an "unguessable" identifier.
