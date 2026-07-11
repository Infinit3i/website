---
layout: post
title: "Curse Breaker"
date: 2028-02-24 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, seccomp, bpf, syscall, obfuscation]
description: "A reversing challenge where the flag check isn't in the disassembled code at all — it lives inside a seccomp-BPF filter that KILLs the process on wrong bytes. Dump the sock_filter[] array, decode the running-difference gadget, and the comparison constants reconstruct the flag."
---

## Overview

Curse Breaker is a Medium reversing challenge whose twist is *where* the flag check lives: not in the C you disassemble, but inside a **seccomp-BPF filter**. The program feeds your input bytes into a syscall as arguments; the kernel filter kills the process the moment a byte is wrong, and only a fully-correct "magic word" survives to the success message. Break the curse = read the BPF.

## The technique

`main` reads the magic word with `fgets`, installs a seccomp filter, then walks the input in 5-byte groups. For each group `i` it fires:

```c
syscall(600, i, b0, b1, b2, b3, b4);   // 600 = 0x258 — a nonexistent syscall number
```

The five group bytes become the syscall's arguments. The seccomp filter allows every *other* syscall (so `printf`/`fgets` work), but for number `600` it inspects `seccomp_data.args[]` and returns `SECCOMP_RET_KILL` on any wrong byte. Reach the end of the loop without being killed and it prints `Free at last!`. The flag **is** the input, and the filter's comparison constants **are** the flag.

`install_filter` copies a 144-instruction `sock_filter[]` array out of `.rodata` (address `0x2060`, taken by the `lea` right before the `rep movs`). Each instruction is an 8-byte struct `{u16 code, u8 jt, u8 jf, u32 k}` — extract them straight from the ELF and decode classic BPF:

- `arch == AUDIT_ARCH_X86_64` and `nr == 600` gates (other syscalls → `ALLOW`),
- dispatch on `args[0]` (the group index `i`) into one of four blocks,
- each block validates its 5 bytes with a **running-difference** state machine using scratch memory `M[0]`:

```
X = 0
for each byte:
    A = byte - X
    if A != k:  KILL
    X = A            # carry the delta forward
```

The `k` values are the obfuscated flag. Inverting the recurrence gives:

```
byte[0] = k[0]
byte[j] = (k[j] + k[j-1]) & 0xff
```

Four constrained groups = 20 bytes = the whole flag; the fifth group is unconstrained because the flag ends first.

## Solution

`solve.py` pulls the delta constants from the decoded filter and rebuilds the input, then confirms live against the binary:

```python
groups = [                                   # k deltas from the BPF jeq checks
    [0x48,0x0c,0x36,0x45,0x2e],
    [0x65,0xfffffffe,0x65,0xffffffcb,0xa2],
    [0x70,0xffffffbd,0xa4,0xffffffc0,0x74],
    [0x62,0x10,0x24,0xfffffffd,0x80],
]
s32 = lambda x: x - (1 << 32) if x & 0x80000000 else x
flag = b""
for g in groups:
    prev = 0
    for k in g:
        b = (s32(k) + prev) & 0xff
        flag += bytes([b]); prev = s32(k)
print(flag.decode())            # pipe into ./breaker -> "Say the magic word: Free at last!"
```

Feeding the reconstructed string back into `breaker` prints `Free at last!` — the flag `HTB{...}` (redacted), confirmed by the real filter.

> Tip: `seccomp-tools dump ./breaker` gives the same filter listing instantly if it's installed (`gem install seccomp-tools`). On a stock Kali box without it, the ~30-line Python ELF + BPF decoder above works entirely offline — don't get blocked waiting on the gem.

## Why it worked

The author moved the byte comparisons out of the code path and into a kernel BPF program, betting the solver wouldn't dump it. But seccomp is an allow/deny mechanism, not a black box: the `sock_filter[]` array is right there in `.rodata`, and once decoded the "encryption" is just a running sum of the delta constants — invertible by hand.

## Fix / defense

Never treat a seccomp filter as a place to hide secrets. A BPF program is fully readable from any binary, so every constant it compares against is recoverable with `seccomp-tools` or a few lines of struct-unpacking. Obfuscation that relies on "it's in the kernel filter" provides no real protection.
