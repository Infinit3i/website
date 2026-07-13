---
layout: post
title: "RetoRetro"
date: 2028-05-25 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, aes, md5, atari-2600, crackme, key-oracle]
description: "A crackme byte-checks MD5(input) then reuses that same digest as its AES key — so the checks leak the key. Decrypt offline and the blob is an Atari 2600 ROM whose upside-down sprite font spells the flag."
---

## Overview

RetoRetro is a **Medium** HackTheBox **Reversing** challenge. You get a stripped x86-64 binary linked against OpenSSL 1.1 that asks for an 80s console name and a 4-character cheatcode, then hands you a "ROM". The whole solve hinges on one mistake: the program validates `MD5(your_input)` byte-by-byte against hard-coded constants, and then reuses that exact digest as an AES-128 key. Because the checks reveal every byte of the digest, you recover the key without ever inverting MD5, decrypt the embedded blob, and discover it's a real Atari 2600 cartridge whose sprite font draws the flag.

## The technique

`fcn.00001205` computes `MD5(input)` into a 16-byte buffer and then compares individual digest bytes to constants — some directly (`digest[0]==0xe7`), some lightly obfuscated (`0xff - digest[12] == 0xfe`, `digest[0] ^ digest[15] == 0x23`, `digest[9] + digest[10] == 0x76`). Solving all 16 constraints reconstructs the whole target digest. You **cannot** invert MD5 to find the console name (a rockyou + rules run misses it), and you don't need to: the same 16-byte buffer at `0x5150` is passed straight into `AES_set_decrypt_key(key, 0x80, ...)`. **The validated digest is the AES-128 key.** This is a [use of a hard-coded / oracle-leaked cryptographic key](https://cwe.mitre.org/data/definitions/321.html) — the equality check is itself an oracle for the key material.

## Solution

Reconstruct the digest from the byte-checks:

```
e7 d5 28 42 cb e4 30 40 63 0b 6b 1e 01 09 3b c4
```

The ciphertext is 0x1000 bytes in `.data` at vaddr `0x40c0` (file offset `0x30c0`). AES-128-ECB decrypt with the recovered key — the result is a valid 4 KB Atari 2600 cart (it ends in `0xff` padding and a `56 f1 56 f1` reset/IRQ vector, i.e. `$F156`, mapping into `$F000–$FFFF`).

The final gate is the cheatcode **`6507`** — the MOS 6507, the 2600's CPU — XORed with a keystream (effective key `0x34`); it only patches a handful of ROM bytes, so the flag lives in the statically-decrypted font. The front of the ROM is a sprite/character table. Two retro quirks matter: glyphs are **9 bytes** each (8 pixel rows + a blank separator), and they are stored **upside-down**, because 2600 display kernels decrement the scanline counter. Reverse each glyph's bytes, draw MSB-left, and the tiles spell the flag.

Create `solve.py`:

```python
from Crypto.Cipher import AES
from PIL import Image

KEY = bytes.fromhex("e7d52842cbe43040630b6b1e01093bc4")   # digest recovered from the checks
data = open("RetoRetro", "rb").read()
ct   = data[0x30c0:0x30c0 + 0x1000]
rom  = AES.new(KEY, AES.MODE_ECB).decrypt(ct)             # a 4 KB Atari 2600 cart

glyphs = [rom[i*9:i*9+9] for i in range(len(rom)//9)]     # 9 bytes each, upside-down
img = Image.new("1", (len(glyphs)*10, 9)); px = img.load()
for i, g in enumerate(glyphs):
    g = bytes(reversed(g))                                # flip: kernels count scanlines down
    for r in range(9):
        for c in range(8):
            if (g[r] >> (7-c)) & 1: px[i*10 + c, r] = 1
img.resize((len(glyphs)*60, 54)).convert("L").save("flag_render.png")
```

Open `flag_render.png` and read the glyphs left to right: `HTB{...}` followed by a decorative face. (Ground-truth alternative: run the binary under gdb, break right after the `MD5` call, overwrite the 16-byte digest buffer with the constants, feed the cheatcode `6507`, and it prints the exact ROM hex. On Kali, which ships OpenSSL 3, preload a spare `libcrypto.so.1.1` via `LD_LIBRARY_PATH`.)

## Why it worked

The author hid the key behind an MD5 "password" check, but a byte-by-byte digest comparison against literals leaks the entire digest — and that digest was reused verbatim as the AES key, collapsing "reverse the check" into "read the constants". Everything after is retro-platform literacy: recognizing a 4 KB blob as a 2600 cart and knowing its sprite fonts are 9 rows tall and drawn bottom-up.

## Fix / defense

Never reuse a validation digest as a cryptographic key — keep authentication and key derivation separate. Derive keys with a real salted KDF (PBKDF2 / scrypt / Argon2) over a secret that is never checked byte-by-byte, and don't ship the ciphertext alongside a check that reveals the key. Obfuscation-by-platform (upside-down 9-byte 2600 glyphs) only slows an analyst who knows the platform; it is not a security control.
