---
title: "Golfer - Part 1"
date: 2027-04-21 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, elf, golfed-binary, objdump, static-analysis, decoy-entrypoint]
description: "An Easy Reversing challenge: a 312-byte hand-golfed 32-bit ELF whose flag characters overlap the ELF header and whose real entry point just jumps to an exit(42) stub, so running it prints nothing. The flag is reconstructed statically from the call order of an unreachable write loop, where each instruction names the file offset of a single character."
---

## Overview

**Golfer - Part 1** is an Easy Reversing challenge built around a *golfed* binary: a 312-byte hand-assembled 32-bit ELF where header fields, code, and data all deliberately overlap to save space. There is no crackme prompt and no runtime output — running the file just exits with code 42. The flag is hidden in plain sight in the file's bytes and is recovered by reading the disassembly of an unreachable routine, where the *order* of a chain of instructions spells out the flag.

## The technique

A suspiciously tiny ELF (`wc -c` says 312 bytes, `file` even misidentifies it as `ELF 32-bit (Cell LV2)`) is a tell that the binary is hand-golfed — flag characters are stuffed into otherwise-unused ELF header bytes. `strings` confirms it, showing the flag's *alphabet* but scrambled (`a4fTUH}yR{l`, `g_30Br`).

The trick has two layers:

1. **A decoy entry point.** The ELF's `e_entry` points at a stub that immediately `jmp`s to an `exit(42)` — so dynamic analysis ("just run it") produces nothing but exit code 42.
2. **Reconstruct-by-index.** The flag is *not* stored in order. There is a character pool plus an *index list*: an unreachable routine made of repeated `mov ecx, 0x080000XX ; call write_one_byte` blocks. The binary loads at base `0x08000000`, so each `ecx` low byte is the **file offset of a single flag character**, and the **order of the calls is the order of the flag**.

This pattern — hiding data in unused header fields, a decoy entry point, and reconstruct-by-index obfuscation — also shows up in real-world packers and malware.

## Solution

Confirm the shape of the file and that it does nothing useful at runtime:

```bash
file rev_golfer/golfer            # ELF 32-bit (Cell LV2) — misidentified golfed header
wc -c rev_golfer/golfer           # 312
strings rev_golfer/golfer         # a4fTUH}yR{l / g_30Br — scrambled flag alphabet
./rev_golfer/golfer ; echo $?     # no output, exit code 42 (decoy)
```

Disassemble it as **raw machine code** (its ELF sections lie, so don't let `objdump` parse it as an ELF):

```bash
objdump -D -b binary -m i386 -M intel rev_golfer/golfer
```

The entry (`e_entry = 0x0800004c`) jumps straight to the exit stub:

```nasm
0x4c:  e9 d6 00 00 00     jmp 0x127          ; entry -> jump to the exit stub
0x127: 30 c0              xor al, al
0x129: fe c0              inc al              ; eax = 1  (sys_exit)
0x12b: b3 2a              mov bl, 0x2a        ; ebx = 42 (the "42" exit code)
0x12d: cd 80              int 0x80            ; exit(42)
```

The dead code at `0x53`-`0x126` is the puzzle — a chain of one-byte writes:

```nasm
b9 0a 00 00 08     mov ecx, 0x0800000a       ; ecx = file offset 0x0a
e8 d0 00 00 00     call 0x12f                 ; write the 1 byte at [ecx]
...
0x12f: 55 89 e5    push ebp ; mov ebp, esp
       b0 04       mov al, 4                   ; sys_write
       cd 80       int 0x80                    ; write(ebx, ecx, edx) -> 1 char
       c9 c3       leave ; ret
```

The order of `ecx` offsets, mapped to the byte stored at each offset, is the flag. Rather than read it off by hand, parse the binary's own bytes:

Create `solve.py`:

```python
#!/usr/bin/env python3
import re, sys
data = open(sys.argv[1] if len(sys.argv) > 1 else
            "rev_golfer/golfer", "rb").read()
offsets = [m[0] for m in re.findall(rb"\xb9(.)\x00\x00\x08", data, re.DOTALL)]
print("".join(chr(data[o]) for o in offsets))
```

```bash
python3 solve.py rev_golfer/golfer
# HTB{...}
```

> Use `re.DOTALL` when regex-scanning binary data — `.` will not match the `0x0a` offset byte without it, silently dropping the leading character.
{: .prompt-warning }

## Why it worked

Golfing an ELF down to a few hundred bytes means reusing header fields for data and code, so the flag characters live inside bytes that a normal loader treats as the ELF header — invisible to a casual read and misreported by `file`. The author then made the real entry point a `jmp` to an `exit()` stub so that running the binary reveals nothing, forcing static analysis. The flag itself is an [out-of-band index](https://cwe.mitre.org/data/definitions/656.html) — a list of offsets in execution order — rather than a contiguous string, so even seeing the character pool in `strings` doesn't give the answer without reconstructing the order.

## Fix / defense

This is a CTF construct, not a software vulnerability, but the takeaways for analysis are real: never trust `file`/`strings`/exit code on a tiny or hand-crafted binary; disassemble from the true `e_entry` and follow control flow instead of reading top-to-bottom; and treat overlapping ELF header/code/data as a deliberate obfuscation to be reconstructed, not a malformed file to be discarded.
