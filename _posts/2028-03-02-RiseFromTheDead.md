---
layout: post
title: "RiseFromTheDead"
date: 2028-03-02 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, core-dump, pwntools, heap, linked-list, forensics]
description: "A binary that shuffles the flag into a buffer, wipes the originals, and crashes itself — leaving a core dump. Reconstruct the heap linked list from the core to undo the shuffle and resurrect the flag."
---

## Overview

RiseFromTheDead is a Medium reversing challenge. You're handed a not-stripped PIE binary `rise` and a `core` dump. The theme — "raise them from the dead" — is a hint: the flag isn't sitting in the binary, it's frozen in the memory image of a process that deliberately killed itself. Recovering it means parsing the core dump's heap.

## What the binary does

Reading `rise` in a disassembler, `main` does something unusual — it `mmap`s the flag file (`argv[1]`) into a buffer `buf`, then:

1. **`init_shuffle_list`** walks the 175 flag bytes. For each byte it reads `/dev/urandom` until it gets a value `pos <= 0xae` that hasn't been used yet (a `pos_in_list` uniqueness check), then appends a node to a linked list: `{ next, pos (offset 8), char (offset 9) }`. Because nodes are `malloc`'d one after another, their heap addresses increase in flag order.
2. **`shuf`** walks the list and writes `buf[node.pos] = node.char` — scattering the flag characters across `buf` at their random positions — and then **zeroes `node.char`**.
3. Finally `puts(buf)` prints the scrambled result and `kill(0, SIGSEGV)` crashes the process, producing the core dump.

So the flag was permuted by `flag[i] → buf[pos_i]`, the character copies in the list were wiped, and everything was frozen into the core.

## The recovery

The relationship to invert is `flag[i] = buf[pos_i]`. Since `shuf` zeroed each node's character, the characters have to come from `buf` and the permutation (`pos_i`, in flag order) has to come from the surviving linked list. Both live in the core dump.

pwntools can parse a core file directly, including the register state at the crash — and `rbx` still holds the `mmap` pointer to `buf` at the `kill` site, so there's no need to hunt for the buffer by content.

Create `solve.py`:

```python
#!/usr/bin/env python3
from pwn import *
c = Corefile('core')
buf = c.read(c.rbx, 0x200)                       # rbx = the mmap'd flag buffer at crash

# index every glibc 0x20 chunk as a candidate node: data @ chunk+0x10 = {next, pos@8}
nd = {}
for m in c.mappings:
    try: d = c.read(m.start, m.size)
    except Exception: continue
    for o in range(0, len(d) - 0x20, 0x10):
        if (u64(d[o+8:o+16]) & ~7) == 0x20:
            nd[m.start + o + 0x10] = (u64(d[o+16:o+24]), d[o+24])

real = {a: v for a, v in nd.items() if v[0] == 0 or v[0] in nd}
ref  = {v[0] for v in real.values() if v[0]}
for head in [a for a in real if a not in ref]:   # walk each unreferenced head
    seen, a = [], head
    while a in real and a not in seen:
        seen.append(a); a = real[a][0]
    fl = bytes(buf[real[x][1]] for x in seen)
    if b'HTB{' in fl and fl.endswith(b'}'):
        print(fl.decode()); break
```

The exact `next`-chain walk (175 nodes) prints the clean flag:

```
HTB{...}
```

## Why it worked

Nothing about the shuffle is irreversible — the positions are stored in the list and the characters are still in the buffer; the crash just froze both into a core dump, which is a complete, parseable snapshot of process memory. One nuance: sorting the candidate chunks by address *approximately* reconstructs the flag (because `malloc` hands them out in order) but drags in false-positive chunks that inject stray characters. Following the actual `next` pointers from the true head gives the exact list.

## Fix / defense

This is a challenge, not a vulnerability — but the transferable lesson is real: **core dumps leak everything in a process's memory.** On production systems, disable core dumps for sensitive services (`ulimit -c 0`, `RLIMIT_CORE`), or set `madvise(MADV_DONTDUMP)` / `PR_SET_DUMPABLE` off for pages holding secrets, so a crash (or an attacker-triggered `SIGSEGV`) can't be mined for keys and plaintext.
