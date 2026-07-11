---
layout: post
title: "PTRACE_NOPEEKING"
date: 2028-01-20 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, ptrace, anti-debug, ud2, sigill, static-analysis]
---

## Overview

PTRACE_NOPEEKING is a Medium **Reversing** challenge. You get a single stripped x86-64 ELF that refuses to be debugged: it forks a second process and the two **ptrace each other**, so `gdb`/`strace` can't attach, and feeding it a wrong flag makes the whole thing deadlock. The intended lesson is that all of that is theatre — the per-character validation data sits in `.data` in plain sight, so the clean solve is to **never run the binary** and invert the check statically.

## The technique

The binary implements a mutual — "debug-each-other" — [ptrace](https://cwe.mitre.org/data/definitions/656.html) VM:

- Two forked processes each call `ptrace(PTRACE_TRACEME)`/attach to the other. A Linux process can only have **one** tracer, so no external debugger can attach. That's the "NO PEEKING".
- The debuggee runs the illegal instruction `ud2`, which raises `SIGILL`. The peer traps that signal and reads the **two bytes following `ud2`** as an opcode — `IN` (0x494e), `CE` (0x4543), `GC` (0x4743), `UO` (0x4f55), `RS` (0x5253) — each selecting a micro-op: read input, encrypt a char, move data, or compare.
- `nanosleep` + a stream of `putchar('.')` pad the run so single-stepping is agony, and wrong input **deadlocks** the ptrace pair — which kills any dynamic brute-force idea (~15 s per attempt, and it hangs).

The weakness: the check is **position-local** and the comparison constants are plaintext in `.data`. Each input char `c` at 0-based position `i` is transformed to

```
enc = (0x2C * i) ^ ((c - (i + 1) + 26) & 0xff)
```

and compared against a per-position target pulled from one of two arrays, chosen by a `whose_turn[]` selector array. Since that's a bijection in `c`, it inverts directly.

## Solution

Dump the data section and read out the three arrays:

```bash
objdump -s -j .data ./nopeeking
```

That reveals `whose_turn[27]` at `0x202020`, array **A** (13 bytes) at `0x2020a0`, and array **B** (14 bytes) at `0x2020e0` (each target is the low byte of a 4-byte int). Then invert the transform per position — anchoring on the known `HTB{` prefix to confirm the array alignment:

Create `solve.py`:

```python
import struct
D = open("nopeeking", "rb").read()          # .data vaddr 0x202000 == file offset 0x2000
u32  = lambda va: struct.unpack_from("<I", D, 0x2000 + va - 0x202000)[0]
barr = lambda va, n: list(D[0x2000 + va - 0x202000 : 0x2000 + va - 0x202000 + n*4 : 4])

whose = [u32(0x202020 + 4*i) for i in range(27)]
A = barr(0x2020a0, whose.count(0))           # targets where whose_turn == 0
B = barr(0x2020e0, whose.count(1))           # targets where whose_turn == 1

ai = bi = 0
flag = ""
for i in range(27):
    if whose[i] == 0:
        enc = A[ai]; ai += 1
    else:
        enc = B[bi]; bi += 1
    flag += chr(((enc ^ (0x2C * i)) + i - 25) & 0xff)
print(flag)                                  # HTB{...}
```

```bash
python3 solve.py
```

The recovered 27-char string is the flag (`HTB{...}` — redacted here). No ptrace, no gdb, no emulation.

## Why it worked

Anti-debugging is obfuscation, not protection. `PTRACE_TRACEME`, mutual tracing, `ud2` traps, and sleep padding only cost the analyst *time* — the validation targets and the arithmetic that produces them both ship in the binary's readable sections. Once you read the transform off `.text` and the target arrays off `.data`, the whole runtime defense is irrelevant.

## Fix / defense

Never gate a secret on anti-debug tricks — a process the analyst controls can be un-traced, patched, or simply not run. If a local check is unavoidable, **derive the comparison key from tamper-evident state** — a CRC of the `.text` segment, or the ptrace/attach result folded into the transform — so a static read of the arrays (or a flipped branch) decrypts to garbage. Better still, authenticate secrets server-side against a salted hash; a local-only check that ships its own validation data is always invertible.
