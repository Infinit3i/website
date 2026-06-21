---
title: "Baby Crypt"
date: 2027-05-03 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, xor, known-plaintext, crib, objdump]
description: "An Easy Reversing challenge: a 64-bit ELF reads a 3-byte key, XORs an embedded ciphertext with it, and prints the result unconditionally. Because the flag starts HTB{ and XOR is its own inverse, the key falls straight out of a known-plaintext crib — recover w0w and the flag decrypts."
---

## Overview

**Baby Crypt** is an Easy Reversing challenge. You're given a single 64-bit ELF
that prompts for a key, XORs a hard-coded secret with it, and prints whatever
comes out. There's no check on the key — so this isn't a password puzzle, it's a
[known-plaintext attack](https://cwe.mitre.org/data/definitions/327.html) on a
short repeating-key XOR, solved instantly with the `HTB{` crib.

## The technique

The whole program is one function. Disassembled with `objdump -d -M intel`, `main`
does the following:

1. Prints `Give me the key and I'll give you the flag: `.
2. `malloc(4)` then `fgets(key, 4, stdin)` — reads a **3-byte** key.
3. Loads a **26-byte ciphertext** onto the stack as four `movabs` immediates
   (little-endian qwords plus a trailing word):
   `0x6f0547480c35643f`, `0x28130304026f0446`, `0x05000f4358280e52`, `0x4d56`.
4. Loops `i = 0..25` doing `ct[i] ^= key[i % 3]`, in place. The
   `imul rax, rax, 0x55555556` / `shr rax, 0x20` idiom is just the compiler
   computing `i / 3` (hence `i % 3`) without a `div`.
5. `printf("%s", ct)` — **unconditionally**.

Because the output prints no matter what key you supply, and every HTB flag starts
with `HTB{`, the key is recoverable directly. XOR is its own inverse, so:

```
key[i] = ct[i] XOR known[i]   for the first keylen (= 3) bytes
```

`ct[0..2] = 3f 64 35` and `"HTB"[0..2] = 48 54 42`, giving key bytes
`77 30 77` = `w0w`.

## Solution

Rebuild the ciphertext from the `movabs` constants, crib on `HTB{` to recover the
key, then decrypt.

Create `solve.py`:

```python
#!/usr/bin/env python3
import struct

qwords = [0x6f0547480c35643f, 0x28130304026f0446, 0x05000f4358280e52]
ct = b"".join(struct.pack("<Q", q) for q in qwords) + struct.pack("<H", 0x4d56)

known = b"HTB{"
key = bytes(ct[i] ^ known[i] for i in range(3))   # -> b"w0w"
print("recovered key:", key.decode())

flag = bytes(ct[i] ^ key[i % 3] for i in range(len(ct)))
print("flag:", flag.decode())
```

```bash
python3 solve.py
```

The same value is confirmed by running the real binary with the recovered key
(it prints the flag because the routine is symmetric):

```bash
printf 'w0w' | ./baby_crypt
```

```
Give me the key and I'll give you the flag: HTB{...}
```

## Why it worked

XOR is symmetric (`p ^ k ^ k = p`), so the same routine that "encrypts" also
decrypts, and one known plaintext byte yields exactly one key byte. The key (3
bytes) is shorter than the secret (26 bytes), so it repeats — and every key byte
is recoverable from just the first three ciphertext bytes via the `HTB{` prefix.
The program never authenticates the key, so the gate is decorative.

## Fix / defense

Repeating-key (Vigenère-style) XOR is not encryption — see
[CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html).
To actually protect a secret with a passphrase:

- Derive the key with a slow KDF (`scrypt` / `argon2` / PBKDF2) and a random salt.
- Use an **authenticated** cipher (AES-GCM, ChaCha20-Poly1305) so a wrong key
  fails to decrypt instead of leaking the plaintext.
- Never make the keystream shorter than the message, and never reuse it.
