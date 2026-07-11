---
layout: post
title: "Metagaming"
date: 2028-03-14 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, cpp, template-metaprogramming, constexpr, z3, vm, smt]
description: "A crackme with no binary — just a C++ file whose flag check runs a 466-instruction register VM entirely at compile time via template metaprogramming. Reimplement the opcodes in z3 and let the solver invert the whole machine."
---

## Overview

Metagaming is a Medium reversing challenge, and it ships no binary — only `main.cpp`. The
name is the hint: *metagaming* = **template metaprogramming**. The flag check runs entirely at
**compile time**. A class template executes a ~466-instruction register VM over a
`static constexpr std::array<uint32_t, 15>`, and a `static_assert` gates compilation on the
final register values. Put the right 40-character flag in the source and it compiles; anything
else trips the assert with *"Ah! Your flag is invalid."*

## The technique

`program_t<flag, insn_t...>` is a template parameterised by the flag and a long list of
`insn_t(opcode, op0, op1)` instructions. A fold-expression runs them at compile time, and the
result is checked against constants:

```cpp
static_assert(program::registers[0] == 0x3ee88722 && ...
           && program::registers[14] == 0x0, "Ah! Your flag is invalid.");
```

`execute_one` is a small `if constexpr` ladder — a tiny instruction set over fifteen 32-bit
registers: load a flag byte, set/xor/or/and/add/sub/mul by an immediate or another register,
rotate left/right, shift left, move, zero. The first block packs the flag four bytes at a time,
little-endian, into `R0..R9`; a long block then mixes the registers with add/sub/xor/mul/rotate;
and a final `R0^=R1; R1^=R2; … ; R9^=R10` chain folds everything together. (Those `R10..R13`
"scratch" registers aren't decoys — the last XOR pulls `R10` back into the answer.)

The key observation: **the final register state is a pure, deterministic function of the 40
input bytes.** You don't have to understand the mixing — you only have to transcribe what each
opcode does and hand the whole thing to an SMT solver.

## Solution

Model the 40 flag bytes as symbolic `BitVec`s, reimplement every opcode as the equivalent z3
operation, run the parsed instruction stream symbolically, assert the final registers equal the
targets, and solve:

```python
import re, sys
from z3 import *

src   = open("main.cpp").read()
insns = [(int(a), int(b), int(c)) for a, b, c in
         re.findall(r"insn_t\((\d+),\s*(\d+),\s*(\d+)\)", src)]
targets = {int(i): int(v, 16) for i, v in
           re.findall(r"registers\[(\d+)\]\s*==\s*(0x[0-9a-fA-F]+)", src)}

N = 40
c = [BitVec(f"c{i}", 8) for i in range(N)]
s = Solver()
LEGAL = [ord(x) for x in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_"]
for x in c: s.add(Or([x == v for v in LEGAL]))
for i, ch in enumerate("HTB{"): s.add(c[i] == ord(ch))
s.add(c[N - 1] == ord('}'))

R = [BitVecVal(0, 32) for _ in range(15)]
for op, a, b in insns:
    if   op == 0:  R[a] = ZeroExt(24, c[b])
    elif op == 1:  R[a] = BitVecVal(b, 32)
    elif op == 2:  R[a] = R[a] ^ b
    elif op == 3:  R[a] = R[a] ^ R[b]
    elif op == 4:  R[a] = R[a] | b
    elif op == 5:  R[a] = R[a] | R[b]
    elif op == 6:  R[a] = R[a] & b
    elif op == 7:  R[a] = R[a] & R[b]
    elif op == 8:  R[a] = R[a] + b
    elif op == 9:  R[a] = R[a] + R[b]
    elif op == 10: R[a] = R[a] - b
    elif op == 11: R[a] = R[a] - R[b]
    elif op == 12: R[a] = R[a] * b
    elif op == 13: R[a] = R[a] * R[b]
    elif op == 16: R[a] = RotateRight(R[a], b)
    elif op == 17: R[a] = RotateRight(R[a], R[b])
    elif op == 18: R[a] = RotateLeft(R[a], b)
    elif op == 19: R[a] = RotateLeft(R[a], R[b])
    elif op == 20: R[a] = R[b]
    elif op == 21: R[a] = BitVecVal(0, 32)
    elif op == 24: R[a] = R[a] << b
for idx, want in targets.items():
    s.add(R[idx] == BitVecVal(want, 32))

s.check()
print("".join(chr(s.model()[x].as_long()) for x in c))   # HTB{...}
```

The model is exact: `BitVec(32)` gives free mod-2³² wrap for +/−/×/xor, the only shifts are
`<<` by immediates `< 32`, and rotations are cyclic mod 32 so z3's `RotateLeft/RotateRight`
match `std::rotl/rotr` for any amount. z3 returns the flag in a second or two; I confirmed it by
replaying the instructions through an independent concrete Python VM — all 15 registers matched.

## Why it worked

Hosting the check in compile-time templates changes only *where* the computation happens, not
*what* it is — it's still a fixed, side-effect-free function from 40 bytes to 15 words, which is
exactly the shape an SMT solver inverts. You transcribe the opcodes; the solver does the
thinking. The one trap — the "scratch" registers that feed the final XOR — disappears the moment
you model the whole machine instead of just the visibly-flag-derived registers.

## Fix / defense

- A compile-time (or any source-visible) VM raises reading effort but adds no cryptographic
  strength; an invertible / SMT-solvable transform is solvable regardless of the language
  feature hosting it.
- To actually resist a solver you need a genuine one-way step — a real hash/KDF over the input
  compared against a stored digest — not more register shuffling.
