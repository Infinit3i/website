---
title: "Shattered Tablet"
date: 2026-10-19 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, crackme, objdump, static-analysis, cwe-602]
description: "A Very Easy Reversing crackme whose flag check is ~40 scattered, hand-unrolled single-byte comparisons instead of a loop. Each accepted byte sits in plaintext inside a cmp immediate, and its position is pinned by its stack slot — so sorting the comparisons by stack offset reassembles the flag with no execution and no brute force."
---

## Overview

`Shattered Tablet` is a Very Easy HackTheBox **Reversing** challenge. You get a single
x86-64 ELF (`tablet`) — PIE, dynamically linked, and helpfully **not stripped**. It prompts
for a line of input, and if you type the right string it tells you so. That accepted string
is the flag, and it is sitting in the binary in plaintext — just shuffled.

```bash
$ ./tablet
Hmmmm... I think the tablet says: hello
No... not that
```

## The technique

Disassembling `main()` shows the check is **not** a loop and **not** a `strcmp`. It is roughly
40 independent, hand-unrolled single-byte comparisons, emitted in **scrambled order**:

```nasm
movzx  eax,BYTE PTR [rbp-0x1e]   ; load one input byte
cmp    al,0x34                   ; must equal '4'
jne    fail
movzx  eax,BYTE PTR [rbp-0x2c]
cmp    al,0x33                   ; must equal '3'
jne    fail
...                              ; ~40 of these, in shuffled stack order
```

`fgets` reads the input into a buffer that begins at `[rbp-0x40]`, so the byte at `[rbp-X]`
is input **index `0x40 - X`**. Every comparison therefore tells us exactly which character
must equal exactly which byte — the only "obfuscation" is that the checks appear out of
order. This is a textbook [client-side enforcement of server-side security](https://cwe.mitre.org/data/definitions/602.html)
([CWE-602](https://cwe.mitre.org/data/definitions/602.html)): the secret and the check that
releases it both ship inside the distributed binary, so anyone with the file recovers it
offline.

## Solution

No need to run or brute-force the binary. Scrape every `(stack-offset, immediate)` pair from
the disassembly, convert each stack offset into its input index, and reassemble the string in
index order.

Create `solve.py`:

```python
#!/usr/bin/env python3
import re, subprocess, os
BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files", "rev_shattered_tablet", "tablet")
dis = subprocess.check_output(["objdump", "-d", "-M", "intel", BIN], text=True).splitlines()
flag = {}
for i, l in enumerate(dis):
    m = re.search(r'movzx\s+eax,BYTE PTR \[rbp-0x([0-9a-f]+)\]', l)
    if not m:
        continue
    cm = re.search(r'cmp\s+al,0x([0-9a-f]+)', dis[i + 1])   # the very next instruction
    if not cm:
        continue
    flag[0x40 - int(m.group(1), 16)] = int(cm.group(1), 16)   # index = 0x40 - X
print(''.join(chr(flag[i]) for i in sorted(flag)))            # emit in index order
```

Run it, then verify by feeding the result back into the binary:

```bash
$ python3 solve.py
HTB{...}
$ python3 solve.py | ./tablet
Hmmmm... I think the tablet says: Yes! That's right!
```

A buffer-base-agnostic one-liner (index sorts by `max(offset) - offset`, so it works even
when the buffer does not start at `0x40`):

```bash
objdump -d -M intel ./tablet | python3 -c "import sys,re;L=sys.stdin.read().splitlines();P=[(int(m.group(1),16),int(c.group(1),16)) for i,l in enumerate(L) if (m:=re.search(r'BYTE PTR \[rbp-0x([0-9a-f]+)\]',l)) and i+1<len(L) and (c:=re.search(r'cmp\s+\w+,\s*0x([0-9a-f]+)',L[i+1]))];print(''.join(chr(v) for _,v in sorted(P,key=lambda t:-t[0])))"
```

## Why it worked

Unrolling and shuffling the comparisons makes the disassembly *look* noisy, but it actually
leaks more than a loop would: every accepted byte is a literal immediate, and every byte's
position is pinned by the stack slot it is compared against. Reordering the comparisons by
stack offset perfectly undoes the shuffle — there is no key, no transform, and nothing to
brute force.

## Fix / defense

- Never let the client hold the secret it is gating. Validate server-side, or at minimum store
  only a salted hash and compare digests — still crackable, but no plaintext immediates to read off.
- If a local check is unavoidable, derive the comparison value at runtime from something the
  binary does not contain (e.g. a remote challenge-response), so static disassembly yields nothing.
- Recognise the smell in any binary: a long run of `cmp <imm>; jne fail` against a single input
  buffer is a plaintext password/flag check waiting to be reassembled.
