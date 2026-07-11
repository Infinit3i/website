---
layout: post
title: "Hexecution"
date: 2028-03-31 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, custom-vm, emulator, permutation, static-analysis]
description: "A crackme built as a custom instruction set plus an emulator. It looks like you have to reverse a whole VM — but the flag check is just a keyless byte shuffle against a string sitting in the program, so you invert it on paper."
---

## Overview

Hexecution is a HackTheBox Reversing challenge (Hard). You get two files: `cook`, a stripped x86-64 ELF, and `recipe.asm`, a program written in a made-up assembly language with cooking-themed opcodes. `cook` is an **emulator** for that instruction set. It *looks* like you need to reverse an entire virtual machine, but the acceptance test turns out to be a **fixed, keyless byte permutation** of your input compared to a constant that is written into the program itself. Once you see that, you never run the VM — you read the target string and the shuffle order out of the assembly and run the shuffle backwards.

## The technique

The interpreter's strings tell you the shape of the problem: `Enter the flag: `, `Wrong!`, and `Nice! The flag is HTB{YOUR_INPUT} :)`. That last one is a **literal template** — the binary just wraps whatever you typed in `HTB{...}`. So the moment your input is accepted, your input *is* the flag content.

Decoding the custom opcodes (registers are named after food groups; `CARBO` acts as a memory pointer):

| Opcode | Meaning |
|---|---|
| `BOIL r, imm` | `r = imm` (mov) |
| `AES256 b` | write byte `b` to `mem[ptr]` |
| `SPELL 1` / `SPELL 0` | print / read stdin |
| `GOODBYE d, PROTEIN` | load `mem[idx] -> d` |
| `WINDOW r` | store `r -> mem[ptr]` |
| `QUICKMAFFS idx` | set the working index |
| `LADDER` | append to the output buffer |
| `PEPEFROG a, b` | compare buffers → Nice!/Wrong! |

Two `AES256` byte-runs build strings in memory: the first spells `"Enter the flag: "`, the second lays down the **comparison target** at `mem 0x40`. Your 32-byte input lands at `mem 0x14`. The program then reorders your bytes and compares against that target. Crucially, **nothing operates on the byte values** — it only moves bytes between positions. That makes the whole check a permutation, which is trivially invertible.

The reorder is two composed stages:

1. **Per group of 4 bytes**, a fixed shuffle: input `[a,b,c,d]` → `[c,b,d,a]` (position `0<-2, 1<-1, 2<-3, 3<-0`).
2. **A global reorder** `output[k] = grouped[order[k]]`, where `order` is exactly the sequence of `QUICKMAFFS` indices that appear right before each `WINDOW PROTEIN`.

## Solution

Parse the target and the reorder table straight from `recipe.asm`, invert both stages, then feed the recovered bytes back to `cook` to confirm.

One gotcha worth stating: **`cook` takes the recipe as its argument and reads the flag from stdin** — `./cook <yourinputfile>` prints nothing. Correct usage is `./cook recipe.asm` with the candidate piped in.

Create `solve.py`:

```python
import subprocess

lines = [l.strip() for l in open("recipe.asm")]

# 1) target string = the AES256 byte run right after "BOIL CARBO, 0x40"
aes, grab = [], False
for l in lines:
    if l == "BOIL CARBO, 0x40": grab, aes = True, []; continue
    if grab and l.startswith("AES256"): aes.append(int(l.split()[1], 16))
    elif grab: break
target = bytes(aes)

# 2) global reorder table = QUICKMAFFS indices before each WINDOW PROTEIN
order = [int(lines[i].split()[1], 16) - 0x14
         for i in range(len(lines) - 1)
         if lines[i].startswith("QUICKMAFFS") and lines[i+1] == "WINDOW PROTEIN"]

# invert stage 2
B = [0]*32
for k, idx in enumerate(order): B[idx] = target[k]

# invert stage 1 (per group [c,b,d,a] came from [a,b,c,d])
I = [0]*32
for g in range(8):
    c, b, d, a = B[4*g:4*g+4]
    I[4*g:4*g+4] = [a, b, c, d]
inp = bytes(I)

# 3) live-verify against the real emulator
out = subprocess.run(["./cook", "recipe.asm"], input=inp, capture_output=True).stdout
assert b"Nice!" in out
print("HTB{" + inp.decode() + "}")
```

Running it recovers the accepted input, `cook` prints `Nice!`, and the flag is `HTB{...}` (the recovered string reads "Custom ISA and Emulation are Fun" in leetspeak).

## Why it worked

The protection here is pure obscurity. A bespoke VM with renamed opcodes looks intimidating, but the acceptance test is a **keyless permutation with the expected answer stored right next to the comparison**. There is no secret and no value-dependent math, so the entire solve is static parsing plus inversion — no dynamic analysis, no brute force, no emulation.

## Fix / defense

- Never gate a secret behind a reversible, keyless transform. Use a **keyed one-way function** (HMAC or a KDF) so the check reveals nothing and cannot be inverted.
- Don't embed the expected answer as a plaintext constant beside the comparison.
- If obfuscation is genuinely the goal, make the check depend on the byte *values* (arithmetic or crypto) and key it with data that isn't shipped in the artifact — a permutation network on its own buys nothing.

The general lesson for any custom-VM crackme: before reversing the whole machine, ask whether the check touches byte *values* or only *positions*. If only positions, it's a permutation — read the constant and the index map, and run it backwards.
