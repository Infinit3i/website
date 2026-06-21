---
title: "CryptOfTheUndead"
date: 2026-11-30 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, chacha20, stream-cipher, hardcoded-key, cwe-321]
description: "A Very Easy Reversing challenge: a native tool zombifies files with ChaCha20 keyed by a string baked into .rodata. Recover the key statically and decrypt is free, because a stream cipher decrypts with the exact same call it used to encrypt."
---

## Overview

`CryptOfTheUndead` is a Very Easy HackTheBox **Reversing** challenge. You get a small x86-64 ELF called `crypt` and a 34-byte file `flag.txt.undead`. The tool "zombifies" files by encrypting them and renaming them to `*.undead`; the goal is to bring the flag back from the dead. The whole solve is recognizing that `crypt` runs stock ChaCha20 with a key hard-coded in the binary, reading that key out of `.rodata`, and re-running the cipher — because a stream cipher's decrypt is byte-for-byte the same operation as its encrypt.

## The technique

`strings` and the symbol table give the scheme away immediately:

```
chacha20_init_context   chacha20_xor   encrypt_buf   "expand 32-byte k"
```

That `expand 32-byte k` constant is the ChaCha sigma — this is textbook ChaCha20 (RFC 8439). ChaCha20 is a **stream cipher**: it derives a keystream purely from `(key, nonce, counter)` and XORs it with the data. XOR is its own inverse, so:

```
plaintext = ciphertext XOR keystream(key, nonce, counter)
```

Decryption is *the same call* as encryption with the *same* parameters. There is nothing to break — we only need the key, nonce, and counter, all of which are fixed inside the binary. This is [a hard-coded cryptographic key (CWE-321)](https://cwe.mitre.org/data/definitions/321.html): static analysis recovers it in seconds and the "encryption" provides no confidentiality at all.

Disassembling the relevant functions (`objdump -d -Mintel ./crypt`) shows `main` calling `encrypt_buf(buf, len, ptr=0x20c0)`, and `encrypt_buf` setting up the cipher like this:

```nasm
encrypt_buf:
    xor    ecx,ecx                          ; counter = 0
    ...
    mov    QWORD PTR [rsp+0xcc],0x0          ; 12-byte nonce buffer = 0
    mov    DWORD PTR [rsp+0xd4],0x0
    lea    rdx,[rsp+0xcc]                    ; nonce  -> zeroed buffer
    mov    rsi,rdx_arg                       ; key    -> 0x20c0
    call   chacha20_init_context             ; (ctx, key, nonce, counter)
    call   chacha20_xor
```

So the counter is `0`, the nonce is 12 zero bytes, and the key is the 32 bytes the third argument points at — `0x20c0` in `.rodata`. Dumping that address:

```
0x20c0:  42 52 41 41 41 41 41 41 ...  "BRAAAAAAAA...AAAINS!!"
```

The key is the 32-byte string `BRAAAAAAAAAAAAAAAAAAAAAAAAAINS!!` (a fitting `BRAINS!!` for a zombie challenge).

## Solution

With the parameters recovered, decryption is a one-liner using PyCryptodome (12-byte nonce → IETF variant, initial counter 0):

```python
from Crypto.Cipher import ChaCha20
c = ChaCha20.new(key=b"BRAAAAAAAAAAAAAAAAAAAAAAAAAINS!!", nonce=b"\x00" * 12)
print(c.decrypt(open("flag.txt.undead", "rb").read()))
# -> HTB{...}
```

For environments without PyCryptodome, a self-contained RFC 8439 ChaCha20 keystream-XOR proves the point with no dependencies:

```python
import struct, sys

def rotl32(v, c): return ((v << c) & 0xffffffff) | (v >> (32 - c))

def quarter(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = rotl32(s[b] ^ s[c], 7)

def chacha20_block(key, counter, nonce):
    const = b"expand 32-byte k"
    state = list(struct.unpack("<4I", const)) + list(struct.unpack("<8I", key))
    state += [counter] + list(struct.unpack("<3I", nonce))
    work = state[:]
    for _ in range(10):
        quarter(work, 0, 4, 8, 12); quarter(work, 1, 5, 9, 13)
        quarter(work, 2, 6, 10, 14); quarter(work, 3, 7, 11, 15)
        quarter(work, 0, 5, 10, 15); quarter(work, 1, 6, 11, 12)
        quarter(work, 2, 7, 8, 13); quarter(work, 3, 4, 9, 14)
    out = [(work[i] + state[i]) & 0xffffffff for i in range(16)]
    return struct.pack("<16I", *out)

def chacha20_xor(key, nonce, data, counter=0):
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = chacha20_block(key, counter + i // 64, nonce)
        out += bytes(a ^ b for a, b in zip(data[i:i+64], ks))
    return bytes(out)

KEY, NONCE = b"BRAAAAAAAAAAAAAAAAAAAAAAAAAINS!!", b"\x00" * 12
ct = open(sys.argv[1] if len(sys.argv) > 1 else "flag.txt.undead", "rb").read()
print(chacha20_xor(KEY, NONCE, ct).decode(errors="replace"))
```

Running either against `flag.txt.undead` prints `HTB{...}`.

## Why it worked

The author treated a strong, modern cipher as if it provided secrecy on its own. But ChaCha20's security rests entirely on the secrecy of the key (and a unique nonce per message) — and here the key is a constant string compiled straight into the binary, with a fixed all-zero nonce and counter. Anyone holding the tool can read those values out of `.rodata` and decrypt every `*.undead` file it ever produced. Because a stream cipher's decrypt is the identical XOR operation as its encrypt, there is no separate "crack" step at all.

A second, quieter consequence: the fixed `(key, nonce)` pair means **every** file is encrypted under the **same keystream**. Even without ever recovering the key, two files (or one file plus any known plaintext) XOR together to cancel the keystream and leak each other's contents — the classic keystream-reuse break.

## Fix / defense

- Never hard-code keys or nonces in a binary ([CWE-321](https://cwe.mitre.org/data/definitions/321.html)). Derive the key from a user secret with a KDF (Argon2/scrypt/PBKDF2), or hold it in a key store the static analyst cannot read.
- Use a fresh, random nonce per message and prepend it to the ciphertext — reusing a nonce under one key destroys stream-cipher confidentiality.
- Prefer an authenticated construction (ChaCha20-Poly1305 / AES-GCM) so ciphertexts are tamper-evident as well as confidential.
