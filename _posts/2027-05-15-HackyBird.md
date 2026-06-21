---
title: "HackyBird"
date: 2027-05-15 09:00:00 -0500
categories: [HackTheBox, Challenges, GamePwn]
tags: [hackthebox, challenge, gamepwn, reversing, aes, crc32, anti-tamper, unicorn, utf-16]
description: "An Easy GamePwn challenge: a Flappy-Bird clone hides its flag as AES-256-CBC ciphertext whose key embeds a CRC32 of its own .text (anti-tamper). Recover it fully statically from the file — no game, no Cheat Engine."
---

## Overview

**HackyBird** is an Easy HackTheBox **GamePwn** challenge — a native Windows
Flappy-Bird clone. The intended path is classic game-hacking: run the game, use
Cheat Engine to set your score past the win threshold, and the flag pops on
screen. We solved it **fully statically** instead — no Windows, no Wine, no
display — by reversing the flag-decode routine and reproducing it in Python. The
flag is **AES-256-CBC** ciphertext whose key embeds a **CRC32 of the program's own
code section** as an anti-tamper measure.

## The technique

When the in-game score passes 999, the win-scene's render routine decrypts an
embedded blob into the flag. The AES-256 key is **built at runtime**:

```
key (32 bytes) = score_LE(2)  ||  CRC32(.text)_LE(4)  ||  26 hardcoded bytes
IV  (16 bytes) = an inline constant block
ct  (64 bytes) = a blob in .sdata
cipher         = AES-256-CBC
```

The CRC32 over the `.text` section is the trick: if you *patch* the executable
(e.g. NOP the score check), `.text` changes, the CRC changes, the key changes, and
the flag decrypts to garbage. That is why the intended solution edits the score in
**memory** rather than on disk. The weakness is that a self-checksum is no secret
at all — it is trivially reproduced offline, so the whole scheme is a textbook
[reliance on a client-side protection mechanism](https://cwe.mitre.org/data/definitions/693.html).

Two details cost the most time:

1. **The win check is `score > 999`**, so the value stored into the key is
   **1000**, not the "999" a quick read suggests (the displayed counter is one
   behind the stored value).
2. **The flag is UTF-16LE** — `48 00 54 00 42 00 7B 00` = `HTB{`. Every other byte
   is `0x00`, so `strings`, an ASCII `HTB{` search, and "is this printable?"
   heuristics all miss it.

## Solution

The binary has **no `.reloc` section and DYNAMICBASE off**, so it always loads at
its preferred base — the loaded `.text` equals the on-disk `.text`. That means the
runtime CRC is computable straight from the file (poly `0xEDB88320`, the standard
`zlib.crc32`, over `[BaseOfCode, BaseOfCode + SizeOfCode)`).

Create `solve.py`:

```python
import struct, zlib
from Crypto.Cipher import AES

raw = open("HackyBird.exe", "rb").read()

crc   = zlib.crc32(raw[0x400:0x400 + 0x10800]) & 0xffffffff   # CRC32(.text)
score = 1000                                                  # first value > 999
const = b"".join(struct.pack("<I", v) for v in
                 (0x991ed411, 0x5ee4b694, 0x9d3a39ce,
                  0x4b10c5e8, 0xfafe8842, 0xfc8e82a3)) + struct.pack("<H", 0x97f0)
iv    = b"".join(struct.pack("<I", v) for v in
                 (0xfc651c99, 0x4dbe388d, 0x2faf25c2, 0x947a780b))
ct    = raw[0x18200:0x18200 + 64]                             # .sdata blob

key = struct.pack("<H", score) + struct.pack("<I", crc) + const
pt  = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
pt  = pt[:-pt[-1]]                                            # strip PKCS#7
print(pt.decode("utf-16-le"))                                # HTB{...}
```

```bash
python3 solve.py
# HTB{...}
```

If you would rather not trust that the software cipher is "standard AES", emulate
the binary's **own** decrypt function with Unicorn: map the PE, point the `this`
register at the ciphertext buffer, push the key and IV pointers, run to a sentinel
return, and read the decrypted bytes back out. Doing that produced a
**byte-identical** result to pycryptodome, confirming both the key layout and the
cipher.

## Why it worked

A win state that *decrypts* a flag (instead of comparing one) means the key is
assembled somewhere — following the score into the decoder reveals the
`score || CRC32(.text) || const` construction. Because the binary carries no
relocations and loads at a fixed base, the "anti-tamper" CRC is fully
deterministic from the unmodified file, so the entire key can be rebuilt offline.

## Fix / defense

Self-checksums only slow attackers down; an offline analyst reproduces them in
seconds. Anything that must stay secret — a flag, a license key — cannot ship
inside the client alongside a locally-derivable key. The achievement should be
proven to a **server** that holds the secret and returns the reward, so the
client never has the means to mint it.
