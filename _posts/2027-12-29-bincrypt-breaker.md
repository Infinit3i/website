---
layout: post
title: "BinCrypt Breaker"
date: 2027-12-29 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, xor, packer, obfuscation, invertible-cipher, cwe-656]
---

A reversing challenge that ships an "encrypted binary" and a small program that decrypts and runs it. Both the packer and the flag check are built entirely from reversible operations, so nothing here is really encrypted — read the constants out of the disassembly and run everything backwards.

## Overview

You get two files: `checker` (an ELF, **not stripped**) and `file.bin` (raw data). `checker` de-obfuscates `file.bin` into a real executable and runs it in-process. That hidden executable is a flag checker: it prompts for the flag, pushes it through a chain of transforms, and compares the result to a constant. The path to the flag is (1) unpack the hidden binary, then (2) invert the checker's transforms. Both layers rely only on [security through obscurity](https://cwe.mitre.org/data/definitions/656.html) — every operation is a bijection, so no brute force or emulation is needed.

## The technique

**Layer 1 — a constant single-byte XOR packer.** `file.bin` starts `d4 ee e7 ed …` and is full of `0xab` bytes. A valid ELF starts with the magic `\x7fELF` (`7f 45 4c 46`), and XORing the first four bytes with `0xab` gives exactly that:

```
d4^ab=7f   ee^ab=45   e7^ab=4c   ed^ab=46   ->  "\x7fELF"
ab^ab=00                                     (the padding decrypts to NUL)
```

The `decrypt` function in `checker` confirms it — it reads `file.bin` a byte at a time and runs a single `xor al, 0xab`, writing the plaintext to an anonymous file descriptor it then executes via `/proc/self/fd/%d` (so the real logic never lands on disk). The key is a literal in the binary; the `/proc/self/fd` trick only hides the payload from a naive `strings file.bin`.

**Layer 2 — a fully invertible flag checker.** The recovered ELF validates a 28-character inner flag (`scanf("%28s")`, `strlen == 0x1c`). The check function does, in order:

1. **whole transform** — four byte swaps: `(0,12) (14,26) (4,8) (20,23)`. Swaps are self-inverse, and these are disjoint.
2. **split** — `A = s[0:14]`, `B = s[14:28]`.
3. **half transform** on each half with a key (`A` with 2, `B` with 3): apply a fixed 14-element permutation `P = [9,12,2,10,4,1,6,3,8,5,7,11,0,13]` **eight times** (`new[j] = old[P[j]]`), then XOR six positions `Q = [2,4,6,8,11,13]` by the key.
4. **compare** `A' + B'` against a constant sitting in plaintext in `.rodata`: `RV{r15]_vcP3o]L_tazmfSTaa3s0`.

Every stage is a bijection, so we invert each in reverse order — and the comparison constant living in `.rodata` is the tell that the whole thing is reversible.

## Solution

Recover the hidden ELF with one line:

```bash
python3 -c "open('recovered','wb').write(bytes(b^0xab for b in open('file.bin','rb').read()))"
file recovered   # ELF 64-bit LSB pie executable ...
```

Then invert the checker. `solve.py` lifts the permutation table, XOR keys, and swap indices straight from the disassembly and runs the pipeline backwards, re-running the forward path as an `assert` self-check:

```python
#!/usr/bin/env python3
TARGET = "RV{r15]_vcP3o]L_tazmfSTaa3s0"          # rodata @0x2008
P = [9, 12, 2, 10, 4, 1, 6, 3, 8, 5, 7, 11, 0, 13]  # permutation, new[j]=old[P[j]]
Q = [2, 4, 6, 8, 11, 13]                            # positions XORed by key
SWAPS = [(0, 12), (14, 26), (4, 8), (20, 23)]

def half(s, key):
    s = list(s)
    for _ in range(8):
        s = [s[P[j]] for j in range(14)]
    for k in Q:
        s[k] ^= key
    return s

def inv_half(out, key):
    s = list(out)
    for k in Q:                       # XOR is its own inverse
        s[k] ^= key
    for _ in range(8):                # undo permutation: old[P[j]] = new[j]
        old = [0] * 14
        for j in range(14):
            old[P[j]] = s[j]
        s = old
    return s

def apply_swaps(s):
    s = list(s)
    for i, j in SWAPS:
        s[i], s[j] = s[j], s[i]
    return s

t = [ord(c) for c in TARGET]
A = inv_half(t[0:14], 2)
B = inv_half(t[14:28], 3)
inner = bytes(apply_swaps(A + B)).decode()        # whole transform is self-inverse

# self-check: forward path must reproduce TARGET
fwd = apply_swaps([ord(c) for c in inner])
assert bytes(half(fwd[0:14], 2) + half(fwd[14:28], 3)).decode() == TARGET

print("FLAG : HTB{" + inner + "}")
```

Finally, verify live against the actual binary — the recovered checker (and the original `checker`, which decrypts `file.bin` itself) accepts it:

```bash
echo cRyPto_r3V_15_aLways_aWeS0m3 | ./recovered   # Correct flag
echo cRyPto_r3V_15_aLways_aWeS0m3 | ./checker      # Correct flag
```

Flag: `HTB{...}` (redacted).

## Why it worked

Neither layer is one-way. The packer's key is a constant in the dropper, and the blob announces itself — key-byte padding plus the `\x7fELF` prefix. The flag checker composes only permutations, XORs, and swaps, all of which are invertible, and it keeps the comparison target as plaintext in `.rodata`. So recovering the input is pure arithmetic: read the constants and reverse the pipeline.

## Fix / defense

Obfuscation is not encryption. A flag/license gate must compare a **one-way** function of the input — e.g. `SHA-256(input)` against a stored digest, or an authenticated KDF — so the target constant cannot be inverted back to the input. And never ship the de-obfuscation key (`0xab`) in the same binary that carries the ciphertext; a constant XOR key next to the blob is equivalent to shipping the plaintext.
