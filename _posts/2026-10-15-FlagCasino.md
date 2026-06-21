---
title: "FlagCasino"
date: 2026-10-15 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, prng, srand, rand, ctypes, crackme]
description: "A Very Easy Reversing challenge: a crackme seeds glibc's srand() with each character you type and checks rand() against a hardcoded table. Because rand() is fully determined by its seed and the seed is a single byte, you can brute all 256 seeds, invert the rand-to-seed map, and read the flag straight out of the table."
---

## Overview

`FlagCasino` is a Very Easy HackTheBox **Reversing** challenge. You get one ELF, `casino`,
that asks for input 30 times — get all 30 characters right and you win, and those 30
characters are the flag. The check rests on a broken assumption: that you cannot predict the
output of C's [`rand()`](https://cwe.mitre.org/data/definitions/338.html). You can — it is a
pure function of its seed, and here the seed is just one byte.

## The technique

The binary is not stripped, so the functions name themselves: `main`, `check`, `banner`.
Disassembling `main` shows a loop that runs 30 times. Each round does exactly this:

```nasm
scanf("%c", &c)            ; read ONE byte
movsx eax, al             ; sign-extend the byte to int
srand(eax)                ; seed glibc's PRNG with that char
rand()                    ; draw one number
cmp eax, [check + i*4]    ; compare to a hardcoded int array (.data, 0x4080)
jne  INCORRECT            ; wrong char -> exit
```

So for position `i`, the program seeds `srand()` with the character you typed and checks
whether the next `rand()` equals a precomputed value `check[i]`. Since `rand()` is completely
deterministic and the seed is a single byte, the input space per position is only **256
possibilities** — so instead of guessing characters we run the same PRNG ourselves, build a
reverse `rand() -> seed` map, and look up each `check[i]` to read the flag character directly.

## Solution

First dump the `check[]` array from `.data` (vaddr `0x4080`, 30 little-endian int32s):

```bash
objdump -s -j .data casino
```

Then run the same glibc PRNG over every possible seed byte via `ctypes` and invert the map.

Create `solve.py`:

```python
#!/usr/bin/env python3
from ctypes import CDLL, c_int
libc = CDLL("libc.so.6")
libc.rand.restype = c_int
check = [0x244b28be,0x0af77805,0x110dfc17,0x07afc3a1,
0x6afec533,0x4ed659a2,0x33c5d4b0,0x286582b8,
0x43383720,0x055a14fc,0x19195f9f,0x43383720,
0x19195f9f,0x747c9c5e,0x0f3da237,0x615ab299,
0x6afec533,0x43383720,0x0f3da237,0x6afec533,
0x615ab299,0x286582b8,0x055a14fc,0x3ae44994,
0x06d7dfe9,0x4ed659a2,0x0ccd4acd,0x57d8ed64,
0x615ab299,0x22e9bc2a]
lut = {}
for b in range(256):
    seed = b - 256 if b >= 128 else b   # movsx al -> signed char
    libc.srand(seed)
    lut.setdefault(libc.rand() & 0xffffffff, b)
print(''.join(chr(lut.get(t, ord('?'))) for t in check))
```

```bash
python3 solve.py
# HTB{...}
```

It prints the flag with no interaction with the binary at all.

## Why it worked

A non-cryptographic PRNG (`rand()`) was used as if it were a one-way function. It is not:
given the seed you can always reproduce the output, and given the output plus a tiny seed
space you can invert it. Seeding from a single user-supplied byte shrank the per-position
search to 256, so replaying the same math and reading the answer out of the comparison table
recovers every flag character instantly.

## Fix / defense

Never use `rand()`/`srand()` for anything security-relevant, and never let a secret be a
small brute-forceable seed.

```c
/* don't: predictable PRNG, tiny seed space */
srand(input_char);
if (rand() == expected) ...

/* do: a real CSPRNG, secret never derived from a guessable seed */
unsigned char buf[32];
getrandom(buf, sizeof(buf), 0);   /* or OpenSSL RAND_bytes() */
```
