---
title: "Encryption Bot"
date: 2027-05-12 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, base64, custom-alphabet, encoding, ghidra, radare2]
description: "An Easy Reversing challenge: a binary that 'encrypts' a 27-char string is really base64 over a reordered alphabet. Recover the alphabet from the disassembly and the encrypted flag decodes in three lines."
---

## Overview

**Encryption Bot** is an Easy HackTheBox **Reversing** challenge. You get `chall` — a stripped 64-bit
ELF that prompts for text and "encrypts" it — and `flag.enc`, a 36-character blob. There is no key
anywhere, which is the tell: the "encryption" is reversible obfuscation. Reading the disassembly shows
it's **base64 with a shuffled alphabet**, so decoding `flag.enc` is a three-line script.

## The technique

A custom encoder that takes no key is just an encoding. The binary's pipeline, recovered from the
disassembly, is exactly base64's 6-bit packing:

1. **Length gate** — the input must be exactly `0x1b` = **27** bytes, otherwise it prints
   *"I'm encrypt only specific length of character."* and exits. So the plaintext flag is 27 bytes.
2. **Byte → bits** — each input byte is broken into 8 bits and written **most-significant-bit first**
   as ASCII `'0'`/`'1'` to a scratch file `data.dat`. 27 bytes → 216 bits.
3. **Bits → custom base64** — the 216-bit stream is regrouped **6 bits at a time** (the per-bit weight
   helper just returns `2^n`, i.e. each group is read MSB-first), and every 6-bit value `0..61` indexes
   a hard-coded alphabet and is printed. 216 / 6 = **36** output characters — exactly the size of
   `flag.enc`.

The only "secret" is the alphabet, and it's built right there in the function from `movabs`
immediates on the stack. Decode the little-endian quadwords and you get:

```
RSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQabcdefghijklmnopqrstuvwxyz
```

That's standard base62 (`0-9A-Za-z`) but **rotated** — uppercase `R..Z`, then digits, then `A..Q`,
then lowercase. Once you know it's plain 6-bit packing over this table, the cipher is fully defined.

## Solution

The encrypted flag is `9W8TLp4k7t0vJW7n3VvMCpWq9WzT3C8pZ9Wz`. Invert the pipeline: each character maps
to its index in the custom alphabet (a 6-bit value), concatenate all 36 groups MSB-first into a
216-bit stream, then re-split into 8-bit bytes.

Create `solve.py`:

```python
ALPHABET = "RSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQabcdefghijklmnopqrstuvwxyz"
enc = open("flag.enc").read().strip()
bits = "".join(format(ALPHABET.index(c), "06b") for c in enc)
flag = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits) - len(bits) % 8, 8))
print(flag.decode())
```

```bash
python3 solve.py
# HTB{...}
```

The flag value is redacted here. **Confirmation:** feeding the recovered plaintext back into the
binary reproduces `flag.enc` byte-for-byte:

```bash
printf 'HTB{...}' | ./chall   # prints 9W8TLp4k7t0vJW7n3VvMCpWq9WzT3C8pZ9Wz
```

## Why it worked

Encoding is not encryption. With no key, every transformation in the binary is invertible, and the
disassembly hands you the two things you need: the **bit order** (the 8-bit and 6-bit loops) and the
**alphabet** (the `movabs` constants). The 27-byte input, 36-char output, and 6-bit grouping all point
straight at base64, so recovering the table is the whole job.

## Fix / defense

- Treat custom encoders as obfuscation, never as confidentiality — anyone who reads the binary
  recovers the scheme. This is [home-grown cryptography](https://cwe.mitre.org/data/definitions/327.html)
  (CWE-327): a reordered-alphabet base64 protects nothing.
- For real secrecy use a vetted authenticated cipher (AES-GCM, ChaCha20-Poly1305) with a key the
  attacker does not possess. The entire challenge hinges on there being no key at all.
- Reversing tip: when you see per-byte bit loops feeding a 6-at-a-time grouping plus a stack- or
  `.rodata`-built character table, assume "base64 variant" and lift the alphabet from the constants
  instead of tracing the arithmetic.
