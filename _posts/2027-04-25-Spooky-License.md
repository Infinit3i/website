---
title: "Spooky License"
date: 2027-04-25 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, crackme, z3, keygen, smt]
description: "An Easy Reversing keygen-me. A stripped 64-bit ELF accepts a 32-character license and validates it with a long chain of cmp checks, each relating a few input bytes by addition, subtraction, and multiplication on 8-bit registers. There is no stored key — the relations over-determine the license — so the clean solve is to model every byte as an 8-bit z3 BitVec, transcribe each comparison as a constraint, and let an SMT solver recover the one valid license."
---

## Overview

**Spooky License** is an Easy Reversing challenge: a stripped x86-64 ELF that takes a license string and prints either `License Correct` or `License Invalid`. It is a classic [keygen-me](https://cwe.mitre.org/data/definitions/656.html) — there is no key stored anywhere to dump with `strings`. Instead the valid license is *defined* by a system of arithmetic relations the binary checks at runtime, which makes it a perfect fit for an SMT solver. The flag is the valid license itself.

## The technique

Running the binary shows the shape of the problem:

```bash
./spookylicence AAAA-BBBB-CCCC
Invalid License Format
```

Disassembling `main` in radare2 (`aaa; s main; pdf`) reveals three gates:

1. `argc == 2` — a license argument is required.
2. `strlen(license) == 0x20` — exactly **32 characters**, else "Invalid License Format".
3. A long chain of `cmp` blocks. Each block computes a small expression from a few license bytes and compares it — as an **8-bit register** (`cmp dl, al`), so everything is **mod 256** — to another byte. Any single mismatch jumps to "License Invalid"; passing all of them prints "License Correct".

A representative block:

```asm
add rax, 0x1d ; movzx eax, byte [rax]   ; edx = s[0x1d]
add rax, 5    ; ... sub ecx, s[3]       ; ecx = s[5] - s[3]
add eax, 0x46                            ; al  = s[5] - s[3] + 0x46
cmp dl, al                               ; require s[0x1d] == s[5] - s[3] + 0x46
jne <fail>
```

There are about 32 of these relations — additions, subtractions, and `imul` products, plus a couple of absolute anchors like `s[9] == 0x70`. Together they over-determine the 32 bytes, which is exactly the right shape for a constraint solver.

## Solution

Transcribe every `cmp` block into a constraint over 8-bit BitVecs (so the mod-256 wraparound is automatic), pin the bytes to printable ASCII, seed the `HTB{` … `}` flag shape, solve, and then run the real binary on the result to confirm the flag is genuine.

Create `solve.py`:

```python
import subprocess, sys
from z3 import BitVec, Solver, sat

BIN = "./spookylicence"
s = [BitVec(f"s{i}", 8) for i in range(32)]
S = Solver()

for c in s:
    S.add(c >= 0x20, c <= 0x7e)
S.add(s[0] == ord('H'), s[1] == ord('T'), s[2] == ord('B'), s[3] == ord('{'), s[0x1f] == ord('}'))

S.add(s[0x1d] == s[5] - s[3] + 0x46)
S.add(s[2] + s[0x16] == s[0xd] + 0x7b)
S.add(s[0xc] + s[4] == s[5] + 0x1c)
S.add(s[0x19] * s[0x17] == s[0] + s[0x11] + 0x17)
S.add(s[0x1b] * s[1] == s[5] + s[0x16] - 0x15)
S.add(s[9] * s[0xd] == s[0x1c] * s[3] - 9)
S.add(s[9] == 0x70)
S.add(s[0x13] + s[0x15] == s[6] - 0x80)
S.add(s[0x10] == s[0xf] - s[0xb] + 0x30)
S.add(s[7] * s[0x1b] == s[1] * s[0xd] + 0x2d)
S.add(s[0xd] == s[0x12] + s[0xd] - 0x65)
S.add(s[0x14] - s[8] == s[9] + 0x7c)
S.add(s[0x1f] == s[8] - s[0x1f] - 0x79)
S.add(s[0x14] * s[0x1f] == s[0x14] + 4)
S.add(s[0x18] - s[0x11] == s[0x15] + s[8] - 0x17)
S.add(s[7] + s[5] == s[5] + s[0x1d] + 0x2c)
S.add(s[0xc] * s[0xa] == s[1] - s[0xb] - 0x24)
S.add(s[0x1f] * s[0] == s[0x1a] - 0x1b)
S.add(s[1] + s[0x14] == s[0xa] - 0x7d)
S.add(s[0x12] == s[0x1b] + s[0xe] + 2)
S.add(s[0x1e] * s[0xb] == s[0x15] + 0x44)
S.add(s[5] * s[0x13] == s[1] - 0x2c)
S.add(s[0xd] - s[0x1a] == s[0x15] - 0x7f)
S.add(s[0x17] == s[0x1d] - s[0] + 0x58)
S.add(s[0x13] == s[8] * s[0xd] - 0x17)
S.add(s[6] + s[0x16] == s[3] + 0x53)
S.add(s[0xc] == s[0x1a] + s[7] - 0x72)
S.add(s[0x10] == s[0x12] - s[5] + 0x33)
S.add(s[0x1e] - s[8] == s[0x1d] - 0x4d)
S.add(s[0x14] - s[0xb] == s[3] - 0x4c)
S.add(s[0x10] - s[7] == s[0x11] + 0x66)
S.add(s[1] + s[0x15] == s[0xb] + s[0x12] + 0x2b)

if S.check() != sat:
    print("UNSAT"); sys.exit(1)
m = S.model()
lic = "".join(chr(m[s[i]].as_long()) for i in range(32))
out = subprocess.run([BIN, lic], capture_output=True, text=True).stdout.strip()
print("license:", lic, "->", out)
```

Run it:

```bash
python3 solve.py
license: HTB{...} -> License Correct
```

z3 returns a single satisfying model, and the binary confirms it by printing `License Correct`. The valid license is the flag.

## Why it worked

The license validator is **fully transparent**: every accept/reject decision is a deterministic arithmetic relation on the input bytes — no server, no crypto, no secret. That reduces the "keygen-me" to a constraint system. Modelling each byte as an 8-bit BitVec captures the mod-256 register comparisons for free, and pinning printable ASCII plus the `HTB{...}` wrapper collapses the search to a unique answer. This is the [reliance-on-obscurity](https://cwe.mitre.org/data/definitions/656.html) failure mode: the algorithm *is* the only barrier, so reversing it removes the barrier entirely.

## Fix / defense

- **Don't gate licensing on local, invertible arithmetic.** A check the attacker can read is a check the attacker can solve. Validate a real signature instead: sign the license server-side with a private key and verify with the embedded public key — the client cannot forge one without the private key.
- Avoid embedding the entire acceptance predicate in the binary. If offline validation is genuinely required, verify a MAC/signature over the key rather than byte-by-byte math.
- Obfuscation (this binary is stripped) raises the cost slightly but does not change the outcome against an SMT solver — it is not a substitute for cryptography.
