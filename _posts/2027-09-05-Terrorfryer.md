---
title: "Terrorfryer"
date: 2027-09-05 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, fisher-yates, prng, rand_r, crackme, cwe-338, cwe-330]
description: "A crackme 'fries' your input with a Fisher-Yates shuffle seeded from a hardcoded constant, then compares it to a fixed string. A fixed-seed shuffle is just a fixed permutation — replay the swaps backwards and the flag falls out."
---

## Overview

`Terrorfryer` is an Easy HackTheBox **Reversing** challenge. You get a single 64-bit
ELF, `fryer`, that asks for "your recipe for frying", scrambles whatever you type, and
only prints `Correct recipe - enjoy your meal!` when the scramble matches a hidden
target. The scramble looks one-way, but it is a [Fisher-Yates shuffle](https://cwe.mitre.org/data/definitions/338.html)
driven by a PRNG seeded from a **hardcoded constant** ([CWE-338](https://cwe.mitre.org/data/definitions/338.html) /
[CWE-330](https://cwe.mitre.org/data/definitions/330.html)) — which makes it a fixed,
fully invertible permutation. Recover the swap schedule once and run it backwards to
read out the flag.

## The technique

The binary is small — `objdump -d` shows just `fryer` and `main`.

`main` reads input, calls `fryer(buf)` to transform it in place, then `strcmp`'s the
result against a fixed string `desired` baked into `.rodata`:

```
fgets(buf, 0x40, stdin); strip newline;
fryer(buf);
strcmp(desired, buf) == 0 ? "Correct" : "wrong"
```

`fryer` is a textbook **Fisher-Yates shuffle** with a seeded PRNG:

```
seed = 0x13377331            ; constant, set once behind an init flag
for i in 0 .. len-2:
    r = rand_r(&seed)        ; glibc rand_r
    j = i + (r % (len - i))
    swap buf[i], buf[j]
```

Two observations collapse the whole challenge:

- **The seed is a constant (`0x13377331`).** `rand_r` is deterministic, so the random
  sequence — and therefore the entire swap schedule — is identical for any input of a
  given length. Nothing here is actually random.
- **A shuffle is a permutation.** It only moves bytes around; it never changes them. So
  `len(desired) == len(flag)`, and applying the same swaps *in reverse order* to
  `desired` reconstructs the original input.

`desired` lives at virtual address `0x20a0`. In a PIE the `.rodata` virtual address
equals its file offset, so you can slice it straight out of the binary — 48 bytes:

```
1_n3}f3br9Ty{_6_rHnf01fg_14rlbtB60tuarun0c_tr1y3
```

## Solution

Reimplement glibc's `rand_r` byte-for-byte in Python (a three-round LCG), build the
`(i, j)` swap list for `len = 48`, then apply those swaps in reverse to `desired`.

Create `solve.py`:

```python
#!/usr/bin/env python3
from pathlib import Path

MASK = 0xFFFFFFFF
def rand_r(state):                      # glibc rand_r, byte-for-byte
    n = state[0]
    n = (n * 1103515245 + 12345) & MASK
    res = (n // 65536) % 2048
    n = (n * 1103515245 + 12345) & MASK
    res = (res << 10) ^ ((n // 65536) % 1024)
    n = (n * 1103515245 + 12345) & MASK
    res = (res << 10) ^ ((n // 65536) % 1024)
    state[0] = n
    return res

d = Path("files/rev_terrorfryer/fryer").read_bytes()
desired = d[0x20a0:0x20d1]
desired = desired[:desired.find(b"\x00")]      # .rodata: vaddr == file offset in a PIE
n = len(desired)                                # 48

state = [0x13377331]
swaps = []
for i in range(n - 1):                          # i = 0 .. n-2
    r = rand_r(state)
    j = i + (r % (n - i))
    swaps.append((i, j))

buf = bytearray(desired)
for i, j in reversed(swaps):                    # undo the shuffle
    buf[i], buf[j] = buf[j], buf[i]

print(buf.decode())
```

Run it, then sanity-check the recovered string against the real binary:

```bash
python3 solve.py
# HTB{...}
python3 solve.py | ./fryer
# Correct recipe - enjoy your meal!
```

The binary confirms the recovered input, so the flag is live-derived, not guessed.

## Why it worked

The "frying" looked irreversible, but a shuffle with a **fixed seed** is fully
deterministic, and a permutation is trivially invertible in O(n). Recovering the swap
schedule once (`rand_r` reimplemented in Python) lets you run the transformation
backwards with no brute force and no dynamic instrumentation.

## Fix / defense

- Don't gate a secret on a reversible, seed-fixed transform — a permutation leaks the
  full multiset of characters in the secret and is invertible.
- If you need unpredictability, seed a CSPRNG from a real entropy source
  (`getrandom(2)` / `/dev/urandom`), never a constant compiled into the binary
  ([CWE-338](https://cwe.mitre.org/data/definitions/338.html) /
  [CWE-330](https://cwe.mitre.org/data/definitions/330.html)).
- For an actual secret check, compare a salted KDF hash (`argon2` / `scrypt`) of the
  input rather than a recoverable transform of the secret itself.
