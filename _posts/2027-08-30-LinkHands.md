---
layout: post
title: "LinkHands"
date: 2027-08-30 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, linked-list, arbitrary-write, cwe-123, ghidra]
---

## Overview

**LinkHands** is an Easy HackTheBox Reversing challenge. You're handed a small,
stripped x86-64 ELF that greets you with *"who will you link hands with?"* and
reads a line of input. The flag is never a plain string in the binary — it's
stored as a **singly-linked list in `.data`**, one node per character. The
program prints the flag by walking that list, but one link is deliberately
**cut**, so the default walk dies halfway. Conveniently, the binary gifts you a
single [write-what-where](https://cwe.mitre.org/data/definitions/123.html)
primitive — you "link hands" by writing the cut node's true successor back into
its `next` field, repairing the chain so the full flag prints.

## The technique

`strings` on the binary comes up empty for the flag — the first tell that the
data is held in a **structure**, not a contiguous string. What `strings` *does*
show is the toolset: `fgets`, `__isoc99_sscanf`, the format `%p %p`, `strchr`,
and `putchar`. That's the whole mechanic in a nutshell: read a line, parse two
pointers, do something with them, then print characters one at a time.

Disassembling `main` (`objdump -d -M intel`) reveals the structure:

```asm
sscanf(buf, "%p %p", &a, &b)      ; a = [rsp], b = [rsp+8]
cmp eax, 2 ; jne fail             ; need BOTH pointers parsed
mov rax, [rsp]                    ; rax = a
mov rdx, [rsp+8]                  ; rdx = b
mov [rax], rdx                    ; *** *a = b : arbitrary write ***
lea rbx, [rip+0x2f75]             ; rbx = 0x404190  (list head)
.walk:
  movsx edi, BYTE PTR [rbx+8]     ; node char  @ +8
  call putchar
  mov rbx, [rbx]                  ; node->next @ +0
  test rbx, rbx ; jne .walk       ; until NULL
```

So each list node is **16 bytes**: `{ next_ptr (8B @ +0), char (1B @ +8) }`. The
program walks from the fixed head `0x404190`, prints `*(node+8)`, follows
`*node`, and stops at `NULL`. The single `mov [rax], rdx` is a full
[write-what-where condition](https://cwe.mitre.org/data/definitions/123.html):
you choose both the address and the value.

## Solution

Dump `.data` and parse it as 16-byte records to rebuild the node graph:

```bash
readelf -x .data link
```

```
0x00404050  00000000 00000000 7d000000 ...   ; node 404050: next=NULL  char='}'  (terminator)
0x00404060  00000000 00000000 5f000000 ...   ; node 404060: next=NULL  char='_'  <-- CUT LINK
0x00404070  80404000 00000000 63000000 ...   ; node 404070: next=404080 char='c'
0x00404190  a0414000 00000000 48000000 ...   ; node 404190: next=4041a0 char='H'  (HEAD)
```

Walking from the head `0x404190` follows `H T B { 4 _ b r 3 4 k _ 1 n _ t h 3`
and reaches node `0x404060`, whose char is `_` but whose `next` is **NULL** — the
walk dies after `HTB{4_br34k_1n_th3_`. The intended continuation is the
contiguous run starting at `0x404070` (`c h 4 1 n ...`), ending at the `}`
terminator node `0x404050`. There's no PIE, so every node address is static and
readable straight off disk.

Repair the chain by relinking the cut node to its true successor —
`*0x404060 = 0x404070` — by feeding those two addresses to the `%p %p` parser:

```bash
echo "0x404060 0x404070" | ./link
```

A tidy, reusable `solve.py` that re-derives the flag from the repaired chain:

```python
import subprocess, re, os

BIN    = os.path.join(os.path.dirname(__file__), "files/rev_linkhands/link")
BROKEN = 0x404060   # node whose `next` is NULL (the cut link)
FIXTO  = 0x404070   # node it must point to so the chain continues

payload = f"{BROKEN:#x} {FIXTO:#x}\n".encode()        # consumed by sscanf("%p %p")
out = subprocess.run([BIN], input=payload, capture_output=True, timeout=5).stdout
print(re.search(rb"HTB\{[^}]+\}", out).group(0).decode())
```

Running it links the hands and prints the flag:

```
HTB{...}
```

> A `subprocess.run(input=...)` call is more robust than a pwntools `recvall`
> here — the binary writes once and exits, and `recvall` blocks waiting for an
> EOF that the short-lived process delivers awkwardly.
{: .prompt-tip }

## Why it worked

The flag was deliberately **scattered across linked nodes** to defeat a naive
`strings`, and assembled only at runtime by the list-walking loop. But `.data`
is fully readable: dump it, parse fixed-size records, and the graph is laid bare
statically. The "puzzle" is just a single missing edge in that graph — and the
program itself hands you the
[arbitrary write](https://cwe.mitre.org/data/definitions/123.html) needed to
add it. No leak, no ASLR (no PIE → fixed addresses), no exploitation gymnastics.

## Fix / defense

The exploitable shape — **untrusted input parsed straight into a raw memory
write** (`sscanf("%p")` → `*ptr = val`) — is a textbook
[write-what-where condition](https://cwe.mitre.org/data/definitions/123.html)
and the root of countless real-world bugs. Never let attacker input choose an
address to write to: validate the destination against an allow-list of legal
targets (or use indices into a bounded array rather than raw pointers), and keep
genuinely read-only data in a read-only mapping so a stray write faults instead
of succeeding. The reversing takeaway is broader: when a flag isn't in
`strings`, look for **data structures** — linked lists, trees, arrays of records
— in `.data`/`.rodata`, and reconstruct the on-disk layout by hand; the bytes
are the source of truth.
