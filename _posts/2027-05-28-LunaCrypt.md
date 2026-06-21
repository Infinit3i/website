---
title: "LunaCrypt"
date: 2027-05-28 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, reversible-cipher, encoding, xor, key-leak]
description: "An Easy Crypto challenge: a homemade per-byte cipher applies a random subset of invertible transforms — then writes the operation mask right next to each ciphertext byte. Because the cipher ships its own key and every step is reversible, decryption is just undoing the selected transforms in reverse order."
---

## Overview

LunaCrypt is an Easy [Crypto](https://cwe.mitre.org/data/definitions/656.html) challenge that hands us a Python encoder (`LunaCrypt.py`) and its output (`output.txt`). The "cipher" looks busy — random nibble-swaps, negations, and XORs chosen per byte — but it makes one fatal mistake: it writes the *operation mask* that selected those transforms into the output file, right alongside each ciphertext byte. The key travels with the ciphertext, and every transform is invertible, so there is no secret left to recover.

## The technique

For each plaintext byte the encoder calls `GenerateFlag()`, which rolls a random bitmask choosing which transforms to apply. The byte is then passed through the selected transforms in a **fixed order**, and the output records two numbers per byte: the ciphered byte, and the mask lightly disguised as `mask ^ 0x4A`.

The transforms and their meaning:

| Bit | Name | Encrypt | Inverse |
|-----|------|---------|---------|
| `0x40` | SWAP | `out = ((LSB^0xB)<<4) \| (MSB^0xD)` (MSB/LSB = original nibbles) | hi-nibble `^0xB` → LSB, lo-nibble `^0xD` → MSB |
| `0x02` | NEGATE | `255 - c` | `255 - c` (self-inverse) |
| `0x08` | XOR6B | `c ^ 0x6B` | `c ^ 0x6B` (self-inverse) |
| `0x10` | XOR3E | `c ^ 0x3E` | `c ^ 0x3E` (self-inverse) |

Encryption order is `SWAP → NEGATE → XOR6B → XOR3E`. Since each operation is a bijection, decryption simply recovers the mask (`flag ^ 0x4A`) and undoes the selected transforms **in reverse**: `XOR3E → XOR6B → NEGATE → SWAP`.

## Solution

`output.txt` is space-separated `cipher_byte flag_byte` pairs. The solver below reads each pair, recovers the mask, and inverts the cipher byte-by-byte.

Create `solve.py`:

```python
FL_NEGATE, FL_XORBY6B, FL_XORBY3E, FL_SWAPBYTES = 0x02, 0x08, 0x10, 0x40

def un_swap(c):
    hn, ln = (c >> 4) & 0xF, c & 0xF
    return (((ln ^ 0xD) << 4) | (hn ^ 0xB)) & 0xFF   # ln->MSB, hn->LSB

nums  = list(map(int, open("output.txt").read().split()))
pairs = [(nums[i], nums[i + 1]) for i in range(0, len(nums), 2)]

out = []
for cipher, stored_flag in pairs:
    flag, c = stored_flag ^ 0x4A, cipher
    if flag & FL_XORBY3E:   c ^= 0x3E
    if flag & FL_XORBY6B:   c ^= 0x6B
    if flag & FL_NEGATE:    c = 255 - c
    if flag & FL_SWAPBYTES: c = un_swap(c)
    out.append(c & 0xFF)

print(bytes(out).decode("latin-1"))
```

Run it against the provided output:

```bash
python3 solve.py
HTB{...}
```

## Why it worked

A keyed cipher is only as strong as the secrecy of its key. LunaCrypt transmits the per-byte operation mask in the same file as the ciphertext (only obscured by a constant XOR), and every transform it uses is reversible. That makes the scheme an **encoding**, not encryption — anyone with the output can read the transform table from the source, peel off the `^0x4A`, and invert each byte. The random per-byte transform selection adds visual noise but zero confidentiality.

## Fix / defense

Use an authenticated, keyed primitive — AES-GCM or ChaCha20-Poly1305 — with a key that **never appears in the output**. Never transmit the operation/selection key alongside the ciphertext; that mask *is* the secret. Randomly choosing among invertible byte operations is obfuscation, and obfuscation is not encryption ([CWE-656](https://cwe.mitre.org/data/definitions/656.html)).
