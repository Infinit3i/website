---
title: "Armed Terminal"
date: 2027-11-20 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, arm, thumb, sigill, computed-goto, obfuscation, static-analysis, capstone, cwe-1104]
description: "An easy Reversing challenge: a 1104-byte ARM32 ELF replaces every branch with a UDF instruction whose bytes encode a jump-table index; a custom SIGILL handler dispatches execution. The flag is recovered by rebuilding the CFG statically and inverting the per-character constraints."
---

## Overview

`Armed Terminal` is an easy HackTheBox **Reversing** challenge. The binary is a statically-linked,
stripped ARM32 ELF of just 1104 bytes. Every branch has been replaced by a `UDF`
(permanently-undefined) instruction, making standard disassemblers produce a flat stream of
invalid opcodes with no visible control flow. A custom SIGILL handler installed at startup reads
the faulting instruction bytes to compute a jump-table index, then patches the saved PC in the
signal context before returning — a classic
[computed-goto obfuscation](https://cwe.mitre.org/data/definitions/1104.html) technique. The flag
is recovered by rebuilding the CFG statically and inverting all the per-character checks without
running the binary.

The flag encodes the answer in its own name: `HTB{4rmz_4ND_ThUMbZ}` — ARMs **and** THUMBs —
because the binary uses both ARM32 and Thumb16 instruction modes.

## The Technique

### SIGILL-based computed-goto

The binary installs a SIGILL handler via `sys_sigaction` (`mov r7, 0x43; svc 0`) at the very
entry point. Every branch target is encoded as a `UDF` instruction whose bytes carry a jump-table
index:

```text
UDF encoding (ARM32):   0xe7f0 00fX  →  low byte = 0xfX  (high nibble = f)
UDF encoding (Thumb16): 0xde NN      →  low byte = NN    (high nibble ≠ f)
```

When the CPU executes a `UDF`, it raises `SIGILL`. The handler at `0x10240` fires:

```asm
ldr r3, [sp, 0x5c]        ; arm_pc from ucontext (sp+0x5c on ARM Linux)
ldr r4, [r3]              ; 32-bit instruction word at the faulting address
lsr r0, r4, 4
and r3, r4, 0xf
and r0, r0, 0xf0
orr r0, r0, r3            ; default: nibble-extracted index
and r3, r4, 0xf0
cmp r3, 0xf0              ; low byte high-nibble == 0xf?
uxtbne r0, r4             ; if NOT 0xfX: r0 = raw low byte (Thumb path)
ldr r3, [r2, r0, lsl 2]   ; next_PC = jump_table[r0]  (table @ 0x10290)
bic r2, r3, 1
str r2, [sp, 0x5c]        ; patch arm_pc in saved context
; also updates CPSR Thumb bit when the table entry has LSB=1
```

The Python equivalent used for static recovery:

```python
def dispatch_index(word):
    r0 = (word >> 4) & 0xF0
    r0 |= word & 0xF
    if (word & 0xF0) != 0xF0:   # Thumb UDF or non-0xfX: raw low byte as index
        r0 = word & 0xFF
    return r0
```

### ARM32 vs Thumb mode switching

Jump-table entries with **LSB = 1** are Thumb targets. The handler clears bit 0 for the saved PC
and sets the CPSR Thumb bit (bit 5) before returning. This means the binary silently switches from
ARM32 to Thumb16 mid-execution — ARM blocks live at `0x10054`–`0x101ac`, Thumb blocks at
`0x101b0`–`0x1021e`. Linear disassembly in ARM mode produces nonsense for the Thumb region;
[Capstone](https://www.capstone-engine.org/) with `CS_MODE_THUMB` decodes it correctly.

## Solution

The binary is too small (1104 bytes, no libc, no `qemu-arm` required) to need dynamic analysis.
Everything is recoverable statically:

1. **Find the handler** — entry point installs SIGILL via `mov r7, 0x43; svc 0`.
2. **Scan for `0xe7f0????` words** in `.text` (file offset 0x54, 0x324 bytes); apply
   `dispatch_index` to each to rebuild the CFG.
3. **Detect Thumb regions** — any table entry with LSB = 1 is Thumb; pass the even address to
   `capstone.Cs(CS_ARCH_ARM, CS_MODE_THUMB)`.
4. **Read the flag checks** from each block and **invert algebraically**.

The checks break into three groups:

| Chars | Constraint | Result |
|-------|-----------|--------|
| 1–4   | `(C1\|C2<<8\|C3<<16\|C4<<24) ^ 0xbaadf00d == 0xc0c08239` | `4rmz` |
| 5–8   | `(C8\|C7<<8\|C6<<16\|C5<<24) ^ 0xf000baaa == 0xaf34f4ee` | `_4ND` |
| 9  | `(c+0x2a)&0xff == 0x89` | `_` |
| 10 | `(c-0x4e)&0xff == 0x06` | `T` |
| 11 | `~c&0xff == 0x97` | `h` |
| 12 | `c^0xcc == 0x99` | `U` |
| 13 | `(c-0x0c)&0xff == 0x41` | `M` |
| 14 | `(c+0x7b)&0xff == 0xdd` | `b` |
| 15 | `~c&0xff == 0xa5` | `Z` |
| 16 | `c == 0x7d` | `}` |

### solve.py

```python
#!/usr/bin/env python3
import struct

BINARY = "files/armedterminal"

def main():
    with open(BINARY, "rb") as f:
        data = f.read()

    def read_word(vaddr):
        return struct.unpack_from("<I", data, vaddr - 0x10000)[0]

    flag = list("HTB{")

    # Group 1: chars 5-8 combined as (C1|C2<<8|C3<<16|C4<<24)
    key1 = read_word(0x10360)       # 0xbaadf00d
    cmp1 = read_word(0x1036c)       # 0xc0c08239
    combined1 = cmp1 ^ key1
    for i in range(4):
        flag.append(chr((combined1 >> (8 * i)) & 0xFF))

    # Group 2: chars 9-12 combined reversed (C8|C7<<8|C6<<16|C5<<24)
    key2 = read_word(0x10370)       # 0xf000baaa
    cmp2 = read_word(0x10368)       # 0xaf34f4ee
    combined2 = cmp2 ^ key2
    for i in range(3, -1, -1):
        flag.append(chr((combined2 >> (8 * i)) & 0xFF))

    # Thumb individual checks — exec order: 0x101be→0x101b0→0x10202→0x101cc→0x101da→0x10210→0x101f0→0x101e8
    checks = [
        ("add", 0x2a, 0x89), ("sub", 0x4e, 0x06), ("not", 0, 0x97),
        ("xor", 0xcc, 0x99), ("sub", 0x0c, 0x41), ("add", 0x7b, 0xdd),
        ("not", 0, 0xa5),   ("eq",  0,    0x7d),
    ]
    for op, operand, target in checks:
        if op == "add":   c = (target - operand) & 0xFF
        elif op == "sub": c = (target + operand) & 0xFF
        elif op == "not": c = (~target) & 0xFF
        elif op == "xor": c = target ^ operand
        else:             c = target
        flag.append(chr(c))

    print("".join(flag))

if __name__ == "__main__":
    main()
```

Running `python3 solve.py` against the downloaded binary prints the flag directly.

## Why It Worked

The binary author placed both the jump table (`0x10290`) and the SIGILL handler (`0x10240`) in
plaintext inside the ELF's single `.text` segment. The handler's dispatch formula is fully
readable in any ARM disassembler — once you understand what `uxtbne r0, r4` does (conditionally
override the computed index with the raw low byte), the entire scheme is transparent. All 29 valid
jump-table entries can be extracted with a simple scan, and the flag constraints invert in a few
lines of arithmetic.

The [use of obfuscated, non-standard control flow](https://cwe.mitre.org/data/definitions/1104.html)
defeats automated decompilers (IDA/Ghidra show no cross-references between blocks) but is no
obstacle to static analysis once the dispatch mechanism is understood.

## Fix / Defense

From a defensive / detection perspective:

- **Static detection**: scan ARM32 binaries for dense `0xe7f0????` sequences — any binary using
  this scheme will show hundreds of UDF words with no conventional branches.
- **Dynamic detection**: `strace` reveals `SIGILL` on every "branch" — a binary that generates
  hundreds of `SIGILL` signals at normal runtime is using signal-based dispatch.
- **For code authors**: if obfuscation is genuinely required, a VM-based protector that does not
  leave a recoverable dispatch table in plaintext is significantly more resistant to static
  analysis. Exposing the jump table alongside the handler defeats the purpose.
